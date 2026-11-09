//! The block creation loop driven directly for the generation harness. The loop's context and
//! functions are private to this module tree, so this is where they are built and called; the
//! replay side of the harness services the bank-forks commands they issue.

use {
    super::*,
    crate::{
        banking_channels::Channels as BankingChannels,
        block_creation_loop::rewards::msg_types::RewardRequest,
    },
    agave_banking_stage_ingress_types::BankingPacketReceiver,
    crossbeam_channel::bounded,
    solana_keypair::Keypair,
    solana_poh::{
        poh_recorder::{Record, WorkingBankMessage},
        record_channels::{RecordSender, record_channels},
    },
    solana_poh_config::PohConfig,
    solana_runtime::transaction_execution::TransactionStatusSender,
    solana_signer::Signer,
};

/// How long a leader start may wait for its parent. The loop gives a start whatever is left of
/// the slot's block timer; the harness gives it this much. The outcome does not depend on it,
/// because nothing changes the parent while the start waits: the harness thread only services
/// bank-forks commands and freezes completed leader banks, the window's first slot builds on a
/// bank replay owns, and a slot within the window starts only after the previous one completed,
/// which froze it. So the budget only bounds how long a refused start waits before giving up, as
/// the loop's does.
const START_BUDGET: Duration = Duration::from_millis(250);

/// The leader half of the harness: a `LeaderContext` over the harness's bank forks and
/// blockstore, with the channels the loop reads from held here so a test can feed them.
pub(crate) struct LeaderSide {
    ctx: LeaderContext,
    /// What PoH hands to broadcast: slot starts, entries and markers of the working bank.
    entry_receiver: Receiver<WorkingBankMessage>,
    record_sender: RecordSender,
    leader_window_info_sender: Sender<LeaderWindowInfo>,
    /// Transactions a sad handover reschedules for banking stage.
    banking_stage_receiver: BankingPacketReceiver,
    /// The rewards service's end of the loop's reward-certificate requests (see `start`).
    reward_requests: Receiver<RewardRequest>,
    /// This node's identity, for the `ClusterInfo` the real loop reads it from (`run_loop`).
    #[cfg(test)]
    identity: Arc<Keypair>,
}

impl LeaderSide {
    pub(crate) fn new(
        identity: Arc<Keypair>,
        bank_forks: Arc<RwLock<BankForks>>,
        blockstore: Arc<Blockstore>,
        leader_schedule_cache: Arc<LeaderScheduleCache>,
        bank_forks_controller: Arc<dyn BankForksController>,
        transaction_status_sender: TransactionStatusSender,
    ) -> Self {
        let root_bank = bank_forks.read().unwrap().root_bank();
        let exit = Arc::new(AtomicBool::new(false));
        let (mut poh_recorder, entry_receiver) = PohRecorder::new(
            root_bank.tick_height(),
            root_bank.last_blockhash(),
            root_bank.clone(),
            Some((4, 7)),
            root_bank.ticks_per_slot(),
            blockstore.clone(),
            &leader_schedule_cache,
            &PohConfig::default(),
            exit.clone(),
        );
        poh_recorder.enable_alpenglow();
        // Transaction indexes are tracked, as banking stage needs them for the status rows.
        let (record_sender, record_receiver) = record_channels(true);
        let (leader_window_info_sender, leader_window_info_receiver) = bounded(1024);
        // #16430 removed the banking tracer; the non-vote channel is what the loop uses to
        // reschedule transactions after a sad handover (`validator.rs:1521`).
        let banking_channels = BankingChannels::new();
        let (banking_stage_sender, banking_stage_receiver) = (
            banking_channels.non_vote_sender.clone(),
            banking_channels.non_vote_receiver.clone(),
        );
        let (reward_certs_requestor, reward_requests) = CertsRequestor::new();
        let sharable_banks = bank_forks.read().unwrap().sharable_banks();
        let ctx = LeaderContext {
            exit,
            my_pubkey: identity.pubkey(),
            leader_window_info_receiver,
            pending_parent_ready: None,
            highest_parent_ready: Arc::new(RwLock::new((0, Block::new_unique(0)))),
            highest_finalized: Arc::new(RwLock::new(None)),
            blockstore,
            record_receiver,
            poh_recorder: Arc::new(RwLock::new(poh_recorder)),
            leader_schedule_cache,
            sharable_banks,
            alpenglow_slot_clock: SharedAlpenglowSlotClock::default(),
            bank_forks,
            bank_forks_controller,
            rpc_subscriptions: None,
            slot_status_notifier: None,
            entry_notification_sender: None,
            transaction_status_sender: Some(transaction_status_sender),
            replay_highest_frozen: Arc::new(ReplayHighestFrozen::default()),
            reward_certs_requestor,
            banking_stage_sender,
            metrics: LoopMetrics::default(),
        };
        Self {
            ctx,
            entry_receiver,
            record_sender,
            leader_window_info_sender,
            banking_stage_receiver,
            reward_requests,
            #[cfg(test)]
            identity,
        }
    }

    /// Runs the real block creation loop (`start_loop`) over this leader's channels and shared
    /// state until `exit` is set, while the caller's replay side services its commands. The loop
    /// takes over the receivers, so the step-driven methods are unusable afterwards. Test only:
    /// the loop completes slots on wall-clock timers, which a fuzzer cannot schedule around.
    #[cfg(test)]
    pub(crate) fn run_loop(&mut self, exit: Arc<AtomicBool>) {
        use {
            solana_gossip::contact_info::ContactInfo, solana_net_utils::SocketAddrSpace,
            solana_time_utils::timestamp,
        };
        let cluster_info = Arc::new(ClusterInfo::new(
            ContactInfo::new_localhost(&self.identity.pubkey(), timestamp()),
            self.identity.clone(),
            SocketAddrSpace::Unspecified,
        ));
        // The loop only ever stops on `exit` or a disconnected window channel, so the
        // optimistic-parent sender lives as long as it runs.
        let (_optimistic_parent_sender, optimistic_parent_receiver) = bounded(1024);
        let (reward_certs_requestor, _reward_requests) = CertsRequestor::new();
        let ctx = &mut self.ctx;
        let config = BlockCreationLoopConfig {
            exit,
            bank_forks: ctx.bank_forks.clone(),
            sharable_banks: ctx.sharable_banks.clone(),
            alpenglow_slot_clock: ctx.alpenglow_slot_clock.clone(),
            bank_forks_controller: ctx.bank_forks_controller.clone(),
            blockstore: ctx.blockstore.clone(),
            cluster_info,
            poh_recorder: ctx.poh_recorder.clone(),
            leader_schedule_cache: ctx.leader_schedule_cache.clone(),
            rpc_subscriptions: None,
            slot_status_notifier: None,
            entry_notification_sender: None,
            transaction_status_sender: ctx.transaction_status_sender.clone(),
            leader_window_info_receiver: std::mem::replace(
                &mut ctx.leader_window_info_receiver,
                bounded(1).1,
            ),
            highest_parent_ready: ctx.highest_parent_ready.clone(),
            replay_highest_frozen: ctx.replay_highest_frozen.clone(),
            highest_finalized: ctx.highest_finalized.clone(),
            record_receiver: std::mem::replace(&mut ctx.record_receiver, record_channels(true).1),
            optimistic_parent_receiver,
            banking_stage_sender: ctx.banking_stage_sender.clone(),
        };
        start_loop(config, reward_certs_requestor);
    }

    /// Votor's end of the loop's leader-window channel, for a test that drives `run_loop`.
    #[cfg(test)]
    pub(crate) fn window_sender(&self) -> Sender<LeaderWindowInfo> {
        self.leader_window_info_sender.clone()
    }

    pub(crate) fn working_bank(&self) -> Option<Arc<Bank>> {
        self.ctx.poh_recorder.read().unwrap().bank()
    }

    /// Starts a leader slot the way the loop does up to the point where it hands the bank to
    /// banking stage (the first half of `produce_first_slot` / `produce_intra_window_slot`): it
    /// asks for reward certificates, then `start_leader_wait_for_parent_replay` refuses a window
    /// the cluster has certified past, and `maybe_start_leader` refuses a slot that already has
    /// a bank, a parent that is missing or not frozen, and a parent that is not the block the
    /// window names, before creating the bank and inserting it through the controller, which
    /// the replay side must service. `parent_block_id` is set for a window's first slot and
    /// `None` within it, as the loop passes them.
    pub(crate) fn start(
        &mut self,
        slot: Slot,
        parent_slot: Slot,
        parent_block_id: Option<BlockId>,
        fast_leader_handover: bool,
    ) -> Result<(), String> {
        let mut slot_metrics = SlotMetrics::new(slot, fast_leader_handover);
        request_reward_certs(&mut self.ctx, &mut slot_metrics, slot)
            .map_err(|err| err.to_string())?;
        // The rewards service takes the request and has nothing to offer: slot 4 is far below
        // the placeholder genesis certificate slot. The footer does not wait for a reply, so it
        // goes out without reward certificates, as it does when the service is late.
        for _request in self.reward_requests.try_iter() {}
        let root_bank = self.ctx.bank_forks.read().unwrap().root_bank();
        let timeout = block_timeout(&root_bank, slot);
        let block_timer = Instant::now()
            .checked_sub(timeout.saturating_sub(START_BUDGET))
            .expect("an instant one block timeout ago exists");
        start_leader_wait_for_parent_replay(
            &mut self.ctx,
            &mut slot_metrics,
            slot,
            parent_slot,
            parent_block_id,
            block_timer,
            /* entry_bytes_consumed */ 0,
        )
        .map(|_working_bank| ())
        .map_err(|err| err.to_string())
    }

    /// Hands banking stage's record of executed transactions to PoH. Returns the index of the
    /// first transaction within the block, which the status rows carry.
    pub(crate) fn record(&self, transactions: Vec<VersionedTransaction>) -> Result<usize, String> {
        let bank_id = self.working_bank().ok_or("no working bank")?.bank_id();
        self.record_sender
            .try_send(Record::new(Hash::new_unique(), transactions, bank_id))
            .map(|index| index.expect("transaction indexes are tracked"))
            .map_err(|err| format!("{err:?}"))
    }

    /// Votor's ParentReady for the window: the certified parent, equal to the optimistic one or
    /// not. The loop reads it from its channel while completing the slot.
    pub(crate) fn parent_ready(&self, slot: Slot, parent: Block) {
        let mut highest_parent_ready = self.ctx.highest_parent_ready.write().unwrap();
        assert!(
            slot >= highest_parent_ready.0,
            "votor's highest ParentReady only rises"
        );
        *highest_parent_ready = (slot, parent);
        drop(highest_parent_ready);
        self.leader_window_info_sender
            .send(LeaderWindowInfo {
                start_slot: slot,
                end_slot: last_of_consecutive_leader_slots(slot),
                parent_block: parent,
                block_timer: Instant::now(),
            })
            .expect("the loop holds the receiver");
    }

    /// Completes the working bank: the block timer has already expired, so the loop first checks
    /// whether the cluster certified past the window (then it aborts the bank,
    /// `abort_working_bank`), otherwise applies the ParentReady it was handed when the slot was
    /// built on an optimistic parent (the sad handover when the parent differs: UpdateParent
    /// marker, bank replaced through the controller, history purge, transactions rescheduled),
    /// then writes the footer and the alpentick and clears the bank. A slot within the window has
    /// no optimistic parent and completes without a ParentReady.
    pub(crate) fn complete(
        &mut self,
        slot: Slot,
        optimistic_parent: Option<Block>,
    ) -> Result<(), String> {
        let working_bank = self.working_bank().ok_or("no working bank")?;
        let mut block_timer = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .expect("an instant a minute ago exists");
        produce_slot(
            &mut self.ctx,
            &mut SlotMetrics::new(slot, optimistic_parent.is_some()),
            slot,
            optimistic_parent,
            // Reward certificates are a separate concern from the discard paths under test.
            None,
            &mut block_timer,
            working_bank,
        )
        .map_err(|err| err.to_string())
    }

    /// Votor certifies a parent past this node's window (in the first slot after it), so
    /// the cluster has moved on: the loop aborts a slot it is producing when it next looks, and
    /// refuses to start one. Votor raises the highest ParentReady; it sends no leader window,
    /// since the window is not this node's.
    pub(crate) fn certify_past_window(&self, window_slot: Slot, block_id: BlockId) {
        let slot = last_of_consecutive_leader_slots(window_slot) + 1;
        let mut highest_parent_ready = self.ctx.highest_parent_ready.write().unwrap();
        assert!(
            slot > highest_parent_ready.0,
            "votor's highest ParentReady only rises"
        );
        *highest_parent_ready = (slot, Block { slot, block_id });
    }

    /// Production failed: the working bank is aborted (R4).
    pub(crate) fn abort(&mut self, slot: Slot) -> Result<(), String> {
        abort_failed_working_bank(&mut self.ctx, slot).map_err(|err| err.to_string())
    }

    /// Everything PoH handed to broadcast so far, in order.
    pub(crate) fn take_entries(&self) -> Vec<WorkingBankMessage> {
        self.entry_receiver.try_iter().collect()
    }

    /// Transactions a sad handover rescheduled; the harness does not re-execute them.
    pub(crate) fn take_rescheduled(&self) -> usize {
        self.banking_stage_receiver.try_iter().count()
    }
}
