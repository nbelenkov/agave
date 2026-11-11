//! `should_discard_shred` on raw byte-faulted shreds, as the fetch stage sees them. It must
//! discard every shred breaking a rule of `violates_enforced_rule` (R1-R10), and discard a
//! coding shred with only its position moved exactly when SIMD-0504 is effective.

#![no_main]

use {
    agave_shred_fuzz::{
        DATA_SIZE_OFFSET, FEC_SET_INDEX_OFFSET, FLAGS_OFFSET, Gates, INDEX_OFFSET, LEADER_SEED,
        NUM_CODING_OFFSET, NUM_DATA_OFFSET, PARENT_OFFSET_OFFSET, POSITION_OFFSET, PROOF_ENTRIES,
        SHRED_VERSION, SLOT_OFFSET, VARIANT_OFFSET, VERSION_OFFSET, bank_for, build_fec_set,
        proof_size_active, read_u16_le, resign, stricter_active,
    },
    arbitrary::Arbitrary,
    libfuzzer_sys::fuzz_target,
    solana_keypair::Keypair,
    solana_ledger::shred::{
        DATA_SHREDS_PER_FEC_BLOCK, Shred, ShredFlags, ShredType, filter::ShredFilterContext, layout,
    },
    solana_runtime::bank::Bank,
    std::sync::Arc,
};

#[derive(Arbitrary, Debug)]
struct Input {
    gates: Gates,
    slot_offset: u16,
    fault: Fault,
    position_shred: u8,
    position_shift: u8,
    data: Vec<u8>,
    batch_faults: Vec<BatchFault>,
}

#[derive(Arbitrary, Debug)]
enum Fault {
    None,
    SetDataComplete { shred: u16 },
    SetLastInSlot { shred: u16 },
    FlipFlags { shred: u16, xor: u8 },
}

/// Applied to the raw bytes with no reparse (it would reject what `sanitize` rejects) and no
/// re-sign (the filter checks no signatures).
#[derive(Arbitrary, Debug)]
enum BatchFault {
    None,
    SetProofSize { shred: u16, entries: u8 },
    SetDataSize { shred: u16, size: u16 },
    SetFlags { shred: u16, flags: u8 },
    SetIndex { shred: u16, value: u32 },
    SetFecSetIndex { shred: u16, value: u32 },
    SetVersion { shred: u16, value: u16 },
    SetParentOffset { shred: u16, value: u16 },
    SetPosition { shred: u16, value: u16 },
    SlotByte { shred: u16, off: u8, xor: u8 },
    RawTamper { shred: u16, off: u16, xor: u8 },
}

fuzz_target!(|input: Input| {
    let bank = bank_for(input.gates);
    let shred_slot = bank.slot() + 1 + u64::from(input.slot_offset % 64);
    let leader = Keypair::new_from_array(LEADER_SEED);
    let Some(base) = build_fec_set(&input.data, shred_slot, shred_slot - 1, &leader) else {
        return;
    };

    check_position_rule(&bank, &base, shred_slot, &input);

    let mut payloads: Vec<Vec<u8>> = base.iter().map(|s| s.payload().to_vec()).collect();
    apply_fault(&mut payloads, &input.fault, &leader);
    let mut filter_ctx = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    for payload in &payloads {
        let discard = filter_ctx.should_discard_shred(payload);
        check_data_complete_enforcement(payload, discard);
    }

    let mut buffers: Vec<Vec<u8>> = base.iter().map(|s| s.payload().to_vec()).collect();
    for fault in input.batch_faults.iter().take(16) {
        poke_buffer(&mut buffers, fault);
    }
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    for payload in &buffers {
        let discarded = filter.should_discard_shred(payload);
        assert!(
            !violates_enforced_rule(payload, &bank) || discarded,
            "should_discard_shred accepted a shred violating an enforced rule"
        );
    }
});

fn apply_fault(payloads: &mut [Vec<u8>], fault: &Fault, leader: &Keypair) {
    let len = payloads.len();
    let (idx, bit) = match fault {
        Fault::None => return,
        Fault::SetDataComplete { shred } => (*shred, ShredFlags::DATA_COMPLETE_SHRED.bits()),
        Fault::SetLastInSlot { shred } => (*shred, ShredFlags::LAST_SHRED_IN_SLOT.bits()),
        Fault::FlipFlags { shred, xor } => (*shred, *xor),
    };
    let payload = &mut payloads[usize::from(idx) % len];
    if let Some(byte) = payload.get_mut(FLAGS_OFFSET) {
        *byte |= bit;
    }
    resign(payload, leader);
}

fn poke_buffer(buffers: &mut [Vec<u8>], fault: &BatchFault) {
    let len = buffers.len();
    let pick = |shred: u16| usize::from(shred) % len;
    let put = |buf: &mut Vec<u8>, off: usize, bytes: &[u8]| {
        if let Some(dst) = buf.get_mut(off..off + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
    };
    match fault {
        BatchFault::None => {}
        BatchFault::SetProofSize { shred, entries } => {
            let buf = &mut buffers[pick(*shred)];
            if let Some(variant) = buf.get_mut(VARIANT_OFFSET) {
                *variant = (*variant & 0xf0) | (entries & 0x0f);
            }
        }
        BatchFault::SetFlags { shred, flags } => {
            put(&mut buffers[pick(*shred)], FLAGS_OFFSET, &[*flags]);
        }
        BatchFault::SetDataSize { shred, size } => {
            put(
                &mut buffers[pick(*shred)],
                DATA_SIZE_OFFSET,
                &size.to_le_bytes(),
            );
        }
        BatchFault::SetIndex { shred, value } => {
            put(
                &mut buffers[pick(*shred)],
                INDEX_OFFSET,
                &value.to_le_bytes(),
            );
        }
        BatchFault::SetFecSetIndex { shred, value } => {
            put(
                &mut buffers[pick(*shred)],
                FEC_SET_INDEX_OFFSET,
                &value.to_le_bytes(),
            );
        }
        BatchFault::SetVersion { shred, value } => {
            put(
                &mut buffers[pick(*shred)],
                VERSION_OFFSET,
                &value.to_le_bytes(),
            );
        }
        // Same offset: parent_offset on data shreds, num_data on coding shreds.
        BatchFault::SetParentOffset { shred, value } => {
            put(
                &mut buffers[pick(*shred)],
                PARENT_OFFSET_OFFSET,
                &value.to_le_bytes(),
            );
        }
        // On a data shred this lands in the data buffer, which is harmless.
        BatchFault::SetPosition { shred, value } => {
            put(
                &mut buffers[pick(*shred)],
                POSITION_OFFSET,
                &value.to_le_bytes(),
            );
        }
        BatchFault::SlotByte { shred, off, xor } => {
            buffers[pick(*shred)][SLOT_OFFSET + usize::from(*off) % 8] ^= *xor;
        }
        BatchFault::RawTamper { shred, off, xor } => {
            let buf = &mut buffers[pick(*shred)];
            let start = VARIANT_OFFSET;
            if buf.len() > start {
                let pos = start + usize::from(*off) % (buf.len() - start);
                buf[pos] ^= *xor;
            }
        }
    }
}

/// filter.rs restated, one-directional (a violation implies a discard), with its private
/// `max_shred_slot` and pub(crate) `verify_shred_slots` replicated.
///
///   R1  fixed FEC set: fec % 32 == 0 and index in [fec, fec + 32)    always-on
///   R2  LAST_SHRED_IN_SLOT only at index % 32 == 31                   always-on
///   R3  DATA_COMPLETE only at index == fec + 31 (SIMD-0337)           always-on
///   R4  coding erasure config is 32:32                                always-on
///   R5  shred version matches                                         always-on
///   R6  index below the bank's per-slot shred limit                   always-on
///   R7  coding position == index - fec (SIMD-0504)                    gated
///   R8  proof size fits a 64-leaf tree (SIMD-0317)                    gated
///   R9  data size consistent with the proof size (SIMD-0317)          gated
///   R10 any LAST_SHRED_IN_SLOT bit implies DATA_COMPLETE (`is_valid`)  always-on
///   plus the future-slot window, coding at/below root, and the parent rule.
fn violates_enforced_rule(payload: &[u8], bank: &Arc<Bank>) -> bool {
    if read_u16_le(payload, VERSION_OFFSET) != Some(SHRED_VERSION) {
        return true; // R5
    }
    let Some(slot) = layout::get_slot(payload) else {
        return false; // not claimed
    };
    let root = bank.slot();
    let slots_per_epoch = bank.get_slots_in_epoch(bank.epoch());
    let max_slot = root.saturating_add(500.max(slots_per_epoch / 2));
    if slot > max_slot {
        return true; // future-slot window
    }
    let (Some(index), Some(fec)) = (
        layout::get_index(payload),
        layout::get_fec_set_index(payload),
    ) else {
        return false;
    };
    if proof_size_active(bank, slot) && violates_proof_rules(payload) {
        return true; // R8, R9
    }
    let block = DATA_SHREDS_PER_FEC_BLOCK as u32;
    let r1_ok = index >= fec
        && fec.checked_add(block).is_some_and(|end| index < end)
        && fec.is_multiple_of(block);
    if !r1_ok {
        return true; // R1
    }
    match layout::get_shred_type(payload) {
        Ok(ShredType::Code) => violates_code_rules(payload, bank, slot, index, fec),
        Ok(ShredType::Data) => violates_data_rules(payload, bank, slot, index, fec),
        Err(_) => false,
    }
}

fn violates_code_rules(payload: &[u8], bank: &Bank, slot: u64, index: u32, fec: u32) -> bool {
    if index >= bank.max_code_shreds_per_slot_for_slot(slot) {
        return true; // R6
    }
    if slot <= bank.slot() {
        return true; // coding shred at/below root
    }
    let block = DATA_SHREDS_PER_FEC_BLOCK as u16;
    let (Some(num_data), Some(num_coding)) = (
        read_u16_le(payload, NUM_DATA_OFFSET),
        read_u16_le(payload, NUM_CODING_OFFSET),
    ) else {
        return false;
    };
    if num_data != block || num_coding != block {
        return true; // R4
    }
    let Some(position) = read_u16_le(payload, POSITION_OFFSET) else {
        return false;
    };
    index.checked_sub(fec) != Some(u32::from(position)) && stricter_active(bank, slot) // R7
}

fn violates_data_rules(payload: &[u8], bank: &Bank, slot: u64, index: u32, fec: u32) -> bool {
    if index >= bank.max_data_shreds_per_slot_for_slot(slot) {
        return true; // R6
    }
    let Some(parent_offset) = read_u16_le(payload, PARENT_OFFSET_OFFSET) else {
        return false;
    };
    let Some(parent) = slot.checked_sub(u64::from(parent_offset)) else {
        return true; // parent offset underflow
    };
    let root = bank.slot();
    let parent_ok = (slot == 0 && parent == 0 && root == 0) || (root <= parent && parent < slot);
    if !parent_ok {
        return true; // verify_shred_slots
    }
    let Ok(flags) = layout::get_flags(payload) else {
        return false;
    };
    // LAST_SHRED_IN_SLOT includes the DATA_COMPLETE bit, hence `intersects`, as `is_valid` does.
    if flags.intersects(ShredFlags::LAST_SHRED_IN_SLOT)
        && !flags.contains(ShredFlags::DATA_COMPLETE_SHRED)
    {
        return true; // R10
    }
    let block = DATA_SHREDS_PER_FEC_BLOCK as u32;
    if flags.contains(ShredFlags::LAST_SHRED_IN_SLOT) && index % block != block - 1 {
        return true; // R2
    }
    // R3
    flags.contains(ShredFlags::DATA_COMPLETE_SHRED) && fec.checked_add(block - 1) != Some(index)
}

fn violates_proof_rules(payload: &[u8]) -> bool {
    let Ok(shred_type) = layout::get_shred_type(payload) else {
        return false;
    };
    let entries = payload.get(VARIANT_OFFSET).map_or(0, |v| v & 0x0f);
    if usize::from(entries) != PROOF_ENTRIES {
        return true; // R8
    }
    shred_type == ShredType::Data && layout::get_data(payload).is_err() // R9
}

/// The moved position stays below 32, so no other rule reads it.
fn check_position_rule(bank: &Arc<Bank>, base: &[Shred], slot: u64, input: &Input) {
    let coding: Vec<&Shred> = base.iter().filter(|s| s.is_code()).collect();
    let Some(shred) = coding.get(usize::from(input.position_shred) % coding.len().max(1)) else {
        return;
    };
    let mut payload = shred.payload().to_vec();
    let Some(position) = read_u16_le(&payload, POSITION_OFFSET) else {
        return;
    };
    let block = DATA_SHREDS_PER_FEC_BLOCK as u16;
    let moved = (position + 1 + u16::from(input.position_shift) % (block - 1)) % block;
    payload[POSITION_OFFSET..POSITION_OFFSET + 2].copy_from_slice(&moved.to_le_bytes());
    let mut filter = ShredFilterContext::new(bank.clone(), SHRED_VERSION);
    let effective = stricter_active(bank, slot);
    assert_eq!(
        filter.should_discard_shred(&payload),
        effective,
        "coding position {moved} (index implies {position}) at slot {slot}: discard should be \
         {effective}, as SIMD-0504 is {}effective there",
        if effective { "" } else { "not " },
    );
}

fn check_data_complete_enforcement(payload: &[u8], discard: bool) {
    let Ok(flags) = layout::get_flags(payload) else {
        return;
    };
    if !flags.contains(ShredFlags::DATA_COMPLETE_SHRED) {
        return;
    }
    let (Some(index), Some(fec)) = (
        layout::get_index(payload),
        layout::get_fec_set_index(payload),
    ) else {
        return;
    };
    let expected = fec
        .checked_add(DATA_SHREDS_PER_FEC_BLOCK as u32)
        .and_then(|i| i.checked_sub(1));
    if expected == Some(index) {
        return;
    }
    assert!(
        discard,
        "should_discard_shred accepted a non-canonical DATA_COMPLETE (index {index}, fec_set \
         {fec})"
    );
}
