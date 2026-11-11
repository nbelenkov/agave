//! `should_discard_packet` on raw and real packets: never panics, never accepts a packet the
//! turbine mode gate or `should_discard_shred` rejects, and round-trips a repair nonce.

#![no_main]

use {
    agave_shred_fuzz::{Gates, LEADER_SEED, SHRED_VERSION, bank_for, build_fec_set},
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    solana_keypair::Keypair,
    solana_ledger::shred::{
        filter::{ShredFilterContext, TurbineMode, TurbineModeKind},
        layout,
    },
    solana_packet::PACKET_DATA_SIZE,
    solana_perf::packet::{BytesPacket, PacketFlags},
};

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    gates: Gates,
    slot_offset: u16,
    is_repair: bool,
    nonce: u32,
    size_override: u16, // 0 = real size
    turbine_kind: u8,
    raw: Vec<u8>,
}

/// Mirrors the private `TurbineModeKind::should_discard_packet`.
fn turbine_forces_discard(kind: TurbineModeKind, is_repair: bool) -> bool {
    match kind {
        TurbineModeKind::Enabled => false,
        TurbineModeKind::TurbineDisabled => !is_repair,
        TurbineModeKind::TurbineAndRepairDisabled => true,
    }
}

fuzz_target!(|input: Input| {
    let bank = bank_for(input.gates);

    verify_raw(&bank, &input.raw, input.is_repair);

    let shred_slot = bank.slot() + 1 + u64::from(input.slot_offset % 64);
    let leader = Keypair::new_from_array(LEADER_SEED);
    let Some(shred) = build_fec_set(&input.data, shred_slot, shred_slot - 1, &leader)
        .and_then(|b| b.into_iter().next())
    else {
        return;
    };

    let mut buffer = shred.payload().to_vec();
    let mut appended_nonce = false;
    if input.is_repair && buffer.len() + 4 <= PACKET_DATA_SIZE {
        buffer.extend_from_slice(&input.nonce.to_le_bytes());
        appended_nonce = true;
    }
    if input.size_override != 0 {
        buffer.resize(usize::from(input.size_override).min(PACKET_DATA_SIZE), 0);
    }
    let mut packet = BytesPacket::from_bytes(None, buffer);
    if input.is_repair {
        packet.meta_mut().flags.insert(PacketFlags::REPAIR);
    }

    let extracted = layout::get_shred_and_repair_nonce(&packet);
    if input.is_repair && appended_nonce && input.size_override == 0 {
        let shred_bytes = layout::get_shred(&packet);
        assert_eq!(
            extracted,
            shred_bytes.map(|s| (s, Some(input.nonce))),
            "get_shred_and_repair_nonce did not round-trip the appended repair nonce"
        );
    }

    let kind = TurbineModeKind::from(input.turbine_kind);
    let mut filter = ShredFilterContext::new_with_turbine_mode(
        bank.clone(),
        SHRED_VERSION,
        Some(TurbineMode::new(kind)),
    );
    let inner_discard = layout::get_shred(&packet).map(|s| {
        let mut f = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
        f.should_discard_shred(s)
    });
    let packet_discard = filter.should_discard_packet(&packet);
    if turbine_forces_discard(kind, input.is_repair) {
        assert!(
            packet_discard,
            "should_discard_packet accepted a packet the TurbineMode gate ({kind:?}) must discard"
        );
    }
    if inner_discard == Some(true) {
        assert!(
            packet_discard,
            "should_discard_packet accepted a packet whose shred should_discard_shred rejects"
        );
    }
});

fn verify_raw(bank: &std::sync::Arc<solana_runtime::bank::Bank>, raw: &[u8], is_repair: bool) {
    if raw.is_empty() {
        return;
    }
    let n = raw.len().min(PACKET_DATA_SIZE);
    let mut packet = BytesPacket::from_bytes(None, raw[..n].to_vec());
    if is_repair {
        packet.meta_mut().flags.insert(PacketFlags::REPAIR);
    }
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    let _ = filter.should_discard_packet(&packet);
}
