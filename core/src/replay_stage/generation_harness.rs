//! Generation harness for fast leader handover (FLH).
//!
//! Drives the real replay, blockstore, `TransactionStatusService` (TSS) and RPC code through the
//! "discard paths" (a slot `S` loses its bank generation and a
//! replacement generation with a new `BankId` is created at the same slot) and checks the
//! slot-keyed stores against a ground-truth model of which generation is canonical.
//!
//! Fixed sequences that reproduce known bugs live in the `tests` submodule. `run_program` runs
//! one program (an operation stream, random or decoded from fuzzer bytes) and is exported behind
//! `dev-context-only-utils` for the cargo-fuzz target in `core/fuzz`.
//!
//! Every harness opens a ledger, so the test suite needs more open files than a default
//! `nofile` limit of 1024 allows: run it under `ulimit -n 65536` or it fails with EMFILE.
//!
//! A panic on the fuzz path is keyed by the fleet on its last non-structural line (plus the
//! panic location and the top stack frames), so a harness assertion puts the run's details first
//! and its cause last, and never relies on `assert_eq!`'s trailing `left`/`right` lines.

use {
    super::*,
    crate::block_creation_loop::leader_harness::LeaderSide,
    agave_votor_messages::{
        certificate::{CertSignature, GenesisCert},
        consensus_message::{Block, BlockId},
    },
    crossbeam_channel::{RecvTimeoutError, bounded},
    rand::{Rng, SeedableRng, rngs::StdRng},
    solana_account::AccountSharedData,
    solana_accounts_db::accounts_db::{ACCOUNTS_DB_CONFIG_FOR_TESTING, AccountsDbConfig},
    solana_bls_signatures::{BLS_SIGNATURE_AFFINE_SIZE, Signature as BLSSignature},
    solana_commitment_config::CommitmentConfig,
    solana_entry::{
        block_component::{
            BlockComponent, BlockFooterV1, BlockHeaderV1, UpdateParentV1, VersionedBlockMarker,
        },
        entry,
        recorder_message::RecorderMessage,
    },
    solana_epoch_schedule::EpochSchedule,
    solana_hash::Hash,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_leader_schedule::{FixedSchedule, LeaderSchedule, SlotLeader},
    solana_ledger::{
        blockstore::{BlockstoreError, PossibleDuplicateShred, UpdateParentReceiver},
        blockstore_meta::BlockLocation,
        blockstore_metrics::BlockstoreInsertionMetrics,
        blockstore_processor::{
            AsyncVerificationProgress, ProcessOptions, process_blockstore_from_root,
            set_alpenglow_ticks,
        },
        shred::{
            ProcessShredsStats, Shred, Shredder,
            filter::{RetransmitSender, ShredRecoveryContext, new_dummy_retransmit_sender},
        },
    },
    solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_poh::poh_recorder::WorkingBankMessage,
    solana_program_binaries::bpf_loader_upgradeable_program_accounts,
    solana_rpc::{
        optimistically_confirmed_bank_tracker::{
            BankNotification, BankNotificationReceiver, BankNotificationSender,
            BankNotificationSenderConfig, OptimisticallyConfirmedBank,
            OptimisticallyConfirmedBankTracker,
        },
        rpc::JsonRpcRequestProcessor,
        rpc_pubsub_service::PubSubConfig,
        rpc_subscriptions::{RpcNotificationConfig, RpcSubscriptions},
        transaction_status_service::{TransactionStatusService, TransactionStatusServiceConfig},
    },
    solana_rpc_client_api::config::{
        RpcBlockConfig, RpcContextConfig, RpcEncodingConfigWrapper, RpcSignatureStatusConfig,
        RpcTransactionConfig,
    },
    solana_runtime::{
        accounts_background_service::{PrunedBanksRequestHandler, SendDroppedBankCallback},
        bank::{BankId, BankTestConfig, TransactionBalancesSet},
        bank_forks_controller::{
            BankForksCommandReceiver, BankForksControllerHandle, SetRootCommand,
        },
        block_component_processor::{BlockComponentProcessor, BlockComponentProcessorError},
        commitment::BlockCommitmentCache,
        dependency_tracker::DependencyTracker,
        genesis_utils::{
            GenesisConfigInfo, ValidatorVoteKeypairs,
            create_genesis_config_with_tower_vote_accounts,
        },
        transaction_execution::{
            TransactionStatusBatch, TransactionStatusMessage, TransactionStatusSender,
        },
    },
    solana_signature::Signature,
    solana_signer::Signer,
    solana_svm::transaction_processor::ExecutionRecordingConfig,
    solana_svm_timings::ExecuteTimings,
    solana_system_interface::instruction as system_instruction,
    solana_system_transaction as system_transaction,
    solana_transaction::{Transaction, versioned::VersionedTransaction},
    solana_transaction_error::TransactionError,
    solana_transaction_status::{
        TransactionDetails, TransactionStatus, UiTransactionEncoding,
        token_balances::TransactionTokenBalancesSet,
    },
    solana_unified_scheduler_pool::DefaultSchedulerPool,
    std::{
        cell::Cell,
        collections::{BTreeMap, BTreeSet},
        num::NonZeroUsize,
        sync::{
            Arc, Condvar, Mutex, OnceLock, RwLock,
            atomic::{AtomicBool, AtomicU64},
        },
        thread::JoinHandle,
        time::Duration,
    },
    trees::{Tree, TreeWalk, tr},
};

// ---- fixture --------------------------------------------------------------------------------

/// A fresh directory for one harness's ledger, under the system temp dir; `Harness::shutdown`
/// removes it. Not `get_tmp_ledger_path!`: that names the directory after `file!()`, which a
/// remote build makes an absolute path on the build machine, and an absolute component replaces
/// `FARF_DIR` as the parent, so the fleet tried to write to its read-only root (EROFS).
fn harness_ledger_path() -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    std::env::temp_dir().join(format!(
        "flh-harness-{}-{}-{nanos}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// What every harness starts from: the slots of a tree frozen with block ids, slot 0 the root,
/// and one staked validator whose funded node key pays for the program's transactions.
struct FixtureForks {
    bank_forks: Arc<RwLock<BankForks>>,
    progress: ProgressMap,
    blockstore: Blockstore,
    funded: Keypair,
}

/// Builds the fixture the harness used to get from `VoteSimulator::new_with(1, ..)` plus
/// `fill_bank_forks(tree, no votes, frozen)`, which #16595 deleted with the rest of Tower: same
/// genesis, stake, PoH and transfer, so programs see the state they always saw. The progress map
/// is built the way validator startup builds it (`ReplayStage::initialize_progress`).
fn fixture_forks(tree: Tree<Slot>) -> FixtureForks {
    let ledger_path = harness_ledger_path();
    let validator = ValidatorVoteKeypairs::new_rand();
    let GenesisConfigInfo {
        mut genesis_config,
        mint_keypair,
        ..
    } = create_genesis_config_with_tower_vote_accounts(1_000_000_000, &[&validator], vec![10_000]);
    genesis_config.epoch_schedule = EpochSchedule::without_warmup();
    genesis_config.poh_config.hashes_per_tick = Some(4);
    let bank_test_config = BankTestConfig {
        accounts_db_config: AccountsDbConfig {
            bank_hash_details_dir: ledger_path.clone(),
            ..ACCOUNTS_DB_CONFIG_FOR_TESTING
        },
    };
    let (bank0, bank_forks) =
        Bank::new_with_paths_for_tests(&genesis_config, Some(bank_test_config), vec![], None)
            .wrap_with_bank_forks_for_tests();
    bank0.set_block_id(Some(BlockId::new_unique()));
    bank0
        .transfer(10_000, &mint_keypair, &validator.node_keypair.pubkey())
        .unwrap();
    bank0.fill_bank_with_ticks_for_tests();
    bank0.freeze();

    let mut walk = TreeWalk::from(tree.clone());
    while let Some(visit) = walk.get() {
        let slot = *visit.node().data();
        if bank_forks.read().unwrap().get(slot).is_some() {
            walk.forward();
            continue;
        }
        let parent_slot = *walk.get_parent().unwrap().data();
        let parent_bank = bank_forks.read().unwrap().get(parent_slot).unwrap();
        let bank = Bank::new_from_parent(parent_bank, SlotLeader::default(), slot);
        let bank = bank_forks
            .write()
            .unwrap()
            .insert(bank)
            .clone_without_scheduler();
        bank.fill_bank_with_ticks_for_tests();
        bank.set_block_id(Some(BlockId::new_unique()));
        bank.freeze();
        walk.forward();
    }

    let progress = ReplayStage::initialize_progress(&bank_forks);
    let blockstore = Blockstore::open(&ledger_path).unwrap();
    blockstore.add_tree(tree, false, true, 2, Hash::default());
    FixtureForks {
        bank_forks,
        progress,
        blockstore,
        funded: validator.node_keypair,
    }
}

/// A minimal loader-v3 program, used to give the program cache an entry whose deployment slot
/// is the slot under test.
const NOOP_ELF: &[u8] =
    include_bytes!("../../../programs/bpf_loader/test_elfs/out/noop_aligned.so");

/// Marks Alpenglow as active from slot 0 with a placeholder genesis certificate.
fn enable_alpenglow_for_tests(migration_status: &MigrationStatus) {
    migration_status.record_feature_activation(0);
    let genesis_block = Block::new_unique(0);
    let genesis_certificate = Arc::new(GenesisCert {
        block: genesis_block,
        signature: CertSignature {
            signature: BLSSignature([0; BLS_SIGNATURE_AFFINE_SIZE]),
            bitmap: vec![],
        },
    });
    migration_status.set_genesis_block(genesis_block);
    migration_status.set_genesis_certificate(genesis_certificate);
    migration_status.enable_alpenglow_during_startup();
}

/// The shred version startup replay checks against. Building a `ClusterInfo` reserves a port
/// range that the test allocator never gets back, and a fuzzer runs thousands of programs in one
/// process, so the node behind it is built once and only its shred version is kept.
pub(super) fn shred_version_for_tests() -> u16 {
    // `Node::new_localhost_with_pubkey` hardcodes shred version 0 (`gossip/src/node.rs:320`), so
    // this is that value without the node. Building one bound real sockets: a per-program node
    // exhausted the test port allocator, and even one per process raced other pods for the fixed
    // gossip port. The harness needs the number, not the sockets.
    0
}

/// Where shred recovery would retransmit what it recovers. The harness inserts data shreds only,
/// so nothing is ever sent, but the context needs a sender and making one starts a worker
/// thread. One per process, rather than one per insert: the fuzz path must not start threads
/// per run.
fn retransmit_sender_for_tests() -> RetransmitSender {
    static SENDER: OnceLock<RetransmitSender> = OnceLock::new();
    SENDER.get_or_init(new_dummy_retransmit_sender).clone()
}

/// Which slots of the window at slot 4 this node leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leads {
    Nothing,
    FirstSlot,
    /// Slots 4 and 5, so the block creation loop produces 5 within its own window.
    FirstTwoSlots,
}

/// Shared with the replay-stage tests, which is why it lives here: the harness is built without
/// `cfg(test)` for the fuzz crate, and an inherent method can only be defined once.
impl ProcessActiveBanksContext {
    pub(super) fn new_for_tests(
        bank_forks: Arc<RwLock<BankForks>>,
        blockstore: Arc<Blockstore>,
    ) -> Self {
        let (cost_update_sender, _) = bounded(1024);
        let (votor_event_sender, _) = bounded(1024);
        let migration_status = bank_forks.read().unwrap().migration_status();
        Self {
            bank_forks,
            blockstore,
            transaction_status_sender: None,
            entry_notification_sender: None,
            bank_notification_sender: None,
            rpc_subscriptions: None,
            slot_status_notifier: None,
            cost_update_sender,
            block_metadata_notifier: None,
            votor_event_sender,
            replay_mode: ForkReplayMode::Serial,
            replay_verification_worker_pool: ReplayVerificationWorkerPool::new(NonZeroUsize::MIN),
            migration_status,
        }
    }
}

/// Shreds per FEC set; block components are placed at multiples of this index.
const FEC_SET_SHREDS: u32 = 32;
/// The known case for history findings at a startup root whose queued status writes a crash
/// threw away: the rows the slot should have stay missing, and rows a lost purge should have
/// removed stay served. Upstream accepts it (raised in #14432's review; #16227 drains only a
/// graceful exit).
const CRASH_LOST_ROOT_HISTORY: &str = "R1 x C4: a crash loses the startup root's queued history";

/// How long a harness wait runs before it says so. Not a deadline: an outcome must not depend on
/// wall-clock time, and a loaded fleet pod runs the same program tens of times slower than a
/// workstation. A wait that never ends is a hang, which the fuzzer's own timeout reports with a
/// stack.
const SLOW_WAIT_NOTE: Duration = Duration::from_secs(10);

/// How long a wait may run in a unit test before it fails it, so a broken test fails instead of
/// hanging. The fuzz target has no such limit; the fuzzer's own timeout covers it.
#[cfg(test)]
const TEST_WAIT_LIMIT: Duration = Duration::from_secs(120);

/// Notes once, on stderr, that a wait has run past `SLOW_WAIT_NOTE`; in a fuzz build it changes
/// nothing else.
fn note_slow_wait(started: std::time::Instant, noted: &mut bool, what: impl FnOnce() -> String) {
    #[cfg(test)]
    if started.elapsed() > TEST_WAIT_LIMIT {
        panic!("waited {TEST_WAIT_LIMIT:?} for {}", what());
    }
    if !*noted && started.elapsed() > SLOW_WAIT_NOTE {
        eprintln!("still waiting after {SLOW_WAIT_NOTE:?}: {}", what());
        *noted = true;
    }
}

/// The scratch state `OptimisticallyConfirmedBankTracker` keeps between notifications. In a
/// validator the tracker thread owns these (`optimistically_confirmed_bank_tracker.rs:114-117`);
/// the harness drives `process_notification` directly, so it holds them instead, and clears
/// them on a restart because a new process starts the tracker from scratch.
#[derive(Default)]
struct ConfirmedBankTrackerState {
    pending: HashSet<(Slot, Hash)>,
    last_notified_confirmed_slot: Slot,
    highest_confirmed_slot: Slot,
    newest_root_slot: Slot,
}

/// What the harness knows about one bank generation it created at a slot.
#[derive(Debug, Clone)]
struct Generation {
    bank_id: BankId,
    /// Signatures the generation executed, in execution order.
    signatures: Vec<Signature>,
}

/// A transaction the harness made for a slot. Its destination is credited by no other
/// transaction, so the account's presence tells which generations wrote it.
#[derive(Debug, Clone)]
struct Transfer {
    signature: Signature,
    destination: Pubkey,
    transaction: Transaction,
    /// Index of the first shred of the batch that carries it, once inserted.
    shred_index: Option<u32>,
    /// The block version whose shreds carry it. A switch replaces the slot's `Original`
    /// version wholesale, so transfers of the replaced version are no longer in the block and
    /// must not be attributed to the generation that replays what took its place.
    location: BlockLocation,
}

/// Ground truth, maintained by the harness only. The code under test never writes it.
#[derive(Default)]
struct GenerationModel {
    /// Program id deployed at the slot by the live generation, with the bank that deployed it.
    deployed_program: Option<(Pubkey, BankId)>,
    generations: BTreeMap<Slot, Vec<Generation>>,
    /// Every transfer made for a slot, in creation order; a replay pass attributes the ones in
    /// the shred range it executed to the bank it ran on.
    transfers: BTreeMap<Slot, Vec<Transfer>>,
    /// Hash of the last entry inserted per (slot, location), so later batches chain from it.
    last_entry_hash: BTreeMap<(Slot, BlockLocation), Hash>,
    /// Bank hash each built block version promises in its footer. Replay must compute the same
    /// hash, and a slot can only ever freeze to one of the versions built for it.
    footer_bank_hash: BTreeMap<(Slot, BlockLocation), Hash>,
    /// The generation that got rooted at each rooted slot.
    rooted: BTreeMap<Slot, BankId>,
}

impl GenerationModel {
    fn every_signature(&self) -> Vec<Signature> {
        self.generations
            .values()
            .flatten()
            .flat_map(|generation| generation.signatures.iter().copied())
            .collect()
    }

    /// Signatures of rooted generations that a finalized history read must return.
    fn rooted_signature_slots(&self) -> Vec<(Signature, Slot)> {
        self.rooted_signatures().into_iter().collect()
    }

    fn destination(&self, signature: Signature) -> Pubkey {
        self.transfers
            .values()
            .flatten()
            .find(|transfer| transfer.signature == signature)
            .unwrap_or_else(|| panic!("unknown transfer {signature}"))
            .destination
    }

    /// Signatures of the transfers at `slot` carried by shreds at or past `shred_index`.
    fn transfers_from(&self, slot: Slot, shred_index: u32) -> Vec<Signature> {
        // Only the live version's transfers are in the block replay reads.
        self.transfers
            .get(&slot)
            .into_iter()
            .flatten()
            .filter(|transfer| {
                transfer.location == BlockLocation::Original
                    && transfer
                        .shred_index
                        .is_some_and(|index| index >= shred_index)
            })
            .map(|transfer| transfer.signature)
            .collect()
    }

    /// Every (signature, destination) pair some generation executed, in generation order.
    fn every_transfer(&self) -> Vec<(Signature, Pubkey)> {
        self.every_signature()
            .into_iter()
            .map(|signature| (signature, self.destination(signature)))
            .collect()
    }

    /// Transfers of rooted generations as (signature, destination, slot).
    fn rooted_transfers(&self) -> Vec<(Signature, Pubkey, Slot)> {
        let rooted = self.rooted_signatures();
        self.every_transfer()
            .into_iter()
            .filter_map(|(signature, destination)| {
                rooted
                    .get(&signature)
                    .map(|slot| (signature, destination, *slot))
            })
            .collect()
    }

    /// Signatures that a finalized history read may legitimately return, with their slot.
    fn rooted_signatures(&self) -> BTreeMap<Signature, Slot> {
        self.rooted
            .iter()
            .flat_map(|(slot, bank_id)| {
                self.generations
                    .get(slot)
                    .into_iter()
                    .flatten()
                    .filter(move |generation| generation.bank_id == *bank_id)
                    .flat_map(move |generation| {
                        generation
                            .signatures
                            .iter()
                            .map(move |signature| (*signature, *slot))
                    })
            })
            .collect()
    }
}

/// Sits between the senders under test and the real `TransactionStatusService`. While closed it
/// forwards nothing, which models TSS lagging behind replay by an arbitrary amount; the order of
/// messages is never changed.
struct TssGate {
    open: Arc<(Mutex<bool>, Condvar)>,
    exit: Arc<AtomicBool>,
    /// While set, messages are discarded instead of forwarded. A process that crashes with a TSS
    /// backlog never writes it, so those rows are simply lost. A graceful exit no longer loses
    /// them: since #16227 the validator joins TSS after its producers stop, and the join drains
    /// the queue (`TransactionStatusService::join`). See `TssGate::discarded` for what a
    /// discarded batch still carries.
    discard: Arc<AtomicBool>,
    /// Slots the discarded messages were for, until `take_lost_slots` reads them.
    lost_slots: Arc<Mutex<BTreeSet<Slot>>>,
    thread: Option<JoinHandle<()>>,
}

impl TssGate {
    const POLL: Duration = Duration::from_millis(20);

    fn spawn(
        proxy: Receiver<TransactionStatusMessage>,
        tss_input: Sender<TransactionStatusMessage>,
    ) -> Self {
        let open = Arc::new((Mutex::new(true), Condvar::new()));
        let exit = Arc::new(AtomicBool::new(false));
        let discard = Arc::new(AtomicBool::new(false));
        let lost_slots = Arc::new(Mutex::new(BTreeSet::new()));
        let thread = std::thread::spawn({
            let open = open.clone();
            let exit = exit.clone();
            let discard = discard.clone();
            let lost_slots = lost_slots.clone();
            move || {
                while !exit.load(Ordering::Relaxed) {
                    let message = match proxy.recv_timeout(Self::POLL) {
                        Ok(message) => message,
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return,
                    };
                    let (lock, condvar) = &*open;
                    let mut is_open = lock.lock().unwrap();
                    while !*is_open && !exit.load(Ordering::Relaxed) {
                        is_open = condvar.wait_timeout(is_open, Self::POLL).unwrap().0;
                    }
                    drop(is_open);
                    let message = if discard.load(Ordering::Relaxed) {
                        if let Some(slot) = Self::message_slot(&message) {
                            lost_slots.lock().unwrap().insert(slot);
                        }
                        match Self::discarded(message) {
                            Some(message) => message,
                            None => continue,
                        }
                    } else {
                        message
                    };
                    if tss_input.send(message).is_err() {
                        return;
                    }
                }
            }
        });
        Self {
            open,
            exit,
            discard,
            lost_slots,
            thread: Some(thread),
        }
    }

    /// The slot a message writes history for, if it writes any.
    fn message_slot(message: &TransactionStatusMessage) -> Option<Slot> {
        match message {
            TransactionStatusMessage::Batch((batch, _)) => Some(batch.slot),
            TransactionStatusMessage::Freeze(bank) => Some(bank.slot()),
            TransactionStatusMessage::Rooted { slot }
            | TransactionStatusMessage::PurgeTransactionHistory { slot, .. } => Some(*slot),
        }
    }

    /// The slots discarded messages were for since the last call.
    fn take_lost_slots(&self) -> BTreeSet<Slot> {
        std::mem::take(&mut *self.lost_slots.lock().unwrap())
    }

    /// What reaches TSS of a message the crash discards. Its rows are lost, but a batch's work id
    /// still has to complete: TSS advances the shared dependency tracker only over a contiguous
    /// run of work ids (#16419), and one TSS thread and tracker serve every process here, so a
    /// dropped id would leave a gap no later drain gets past. A new validator starts a fresh
    /// tracker with nothing outstanding; an empty batch carrying the id gets this one to the same
    /// place and writes nothing.
    fn discarded(message: TransactionStatusMessage) -> Option<TransactionStatusMessage> {
        match message {
            TransactionStatusMessage::Batch((batch, Some(work_id))) => {
                Some(TransactionStatusMessage::Batch((
                    TransactionStatusBatch {
                        slot: batch.slot,
                        bank_id: batch.bank_id,
                        transactions: vec![],
                        commit_results: vec![],
                        balances: TransactionBalancesSet::new(vec![], vec![]),
                        token_balances: TransactionTokenBalancesSet::new(vec![], vec![]),
                        costs: vec![],
                        transaction_indexes: vec![],
                    },
                    Some(work_id),
                )))
            }
            _ => None,
        }
    }

    fn set_discard(&self, discard: bool) {
        self.discard.store(discard, Ordering::Relaxed);
    }

    fn is_open(&self) -> bool {
        *self.open.0.lock().unwrap()
    }

    fn set_open(&self, open: bool) {
        let (lock, condvar) = &*self.open;
        *lock.lock().unwrap() = open;
        condvar.notify_all();
    }

    fn stop(mut self) {
        self.exit.store(true, Ordering::Relaxed);
        self.set_open(true);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// A finalized RPC answer the oracle rejected: `query` served `signature` at `slot`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RpcViolation {
    query: &'static str,
    signature: Signature,
    slot: Slot,
}

/// Broadcast stand-in state. The real broadcast run is private to the turbine crate, so the
/// harness shreds PoH's messages the way it does: one header per slot on the first slot start,
/// the shred-header parent kept across a handover, shred indices continuing.
#[derive(Default)]
struct BroadcastState {
    slot: Option<Slot>,
    parent_slot: Slot,
    header_sent: bool,
    next_index: u32,
}

struct Harness {
    blockstore: Arc<Blockstore>,
    bank_forks: Arc<RwLock<BankForks>>,
    progress: ProgressMap,
    leader_schedule_cache: Arc<LeaderScheduleCache>,
    /// Identity passed to the replay helpers. In replay mode it starts as one no slot is
    /// scheduled to, so replay creates banks for every slot, until `set_identity` takes over
    /// `takeover_identity`. In leader mode it leads slot 4, which the block creation loop
    /// produces instead of replay.
    my_pubkey: Pubkey,
    /// Who leads slot 4 in replay mode: another validator's identity, which this node can take
    /// over (`set_identity`) the way an operator's failover does.
    takeover_identity: Pubkey,
    migration_status: Arc<MigrationStatus>,
    update_parent_receiver: UpdateParentReceiver,
    active_banks_context: ProcessActiveBanksContext,
    bank_forks_context: ProcessBankForksContext,
    /// Banks root pruning retires. A validator's `DropBankService` drops them as they arrive,
    /// which is what queues their write-cache purge (#16508); `run_drop_bank_service` does that.
    drop_bank_receiver: Receiver<Vec<BankWithScheduler>>,
    /// The real ABS queue: every dropped bank lands here instead of purging inline.
    pruned_banks: PrunedBanksRequestHandler,
    _votor_commitment_receiver: Receiver<CommitmentAggregationData>,
    async_verification_freelist: Vec<AsyncVerificationProgress>,
    block_commitment_cache: Arc<RwLock<BlockCommitmentCache>>,
    latest_switch_request: LatestSwitchRequest,
    pending_switch: Option<SwitchBankEvent>,
    tss: Option<TransactionStatusService>,
    tss_exit: Arc<AtomicBool>,
    tss_sender: TransactionStatusSender,
    tss_gate: Option<TssGate>,
    dependency_tracker: Arc<DependencyTracker>,
    max_complete_transaction_status_slot: Arc<AtomicU64>,
    /// Highest slot whose generation TSS has seen both frozen and rooted; the finalized gate.
    max_complete_and_rooted_transaction_status_slot: Arc<AtomicU64>,
    optimistically_confirmed_bank: Arc<RwLock<OptimisticallyConfirmedBank>>,
    /// Where `OptimisticallyConfirmedBankTracker` sends its notifications. Nothing reads them;
    /// the tracker is here for what it does to the confirmed bank, not for its notifications.
    rpc_subscriptions: Arc<RpcSubscriptions>,
    bank_notification_receiver: BankNotificationReceiver,
    /// Stands in for `votor::root_utils::set_root`, which is `pub(crate)` to votor.
    votor_bank_notification_sender: BankNotificationSender,
    confirmed_tracker: Mutex<ConfirmedBankTrackerState>,
    /// The real RPC request processor over the harness's stores, for client-level reads.
    rpc: JsonRpcRequestProcessor,
    funded: Keypair,
    /// Counter behind `next_pubkey` / `next_block_id`. Identifiers a program mints are derived
    /// from it rather than from the process RNG, so a crash reproduces with the same addresses
    /// and block ids as the run that found it.
    next_id: Cell<u64>,
    model: GenerationModel,
    /// The block creation loop for slot 4, when the program runs in leader mode.
    leader: Option<LeaderSide>,
    /// Commands the loop issues to the replay side (insert and clear bank).
    bank_forks_commands: Option<BankForksCommandReceiver>,
    broadcast: BroadcastState,
}

impl Harness {
    /// Builds a harness whose bank forks and blockstore already hold the frozen `tree`
    /// (slot 0 is the root). All slots in the tree are frozen with block ids.
    fn new(tree: Tree<Slot>) -> Self {
        Self::build(tree, Leads::Nothing)
    }

    /// As `new`, with this node as the leader of slot 4 and a block creation loop for it.
    fn new_leader(tree: Tree<Slot>) -> Self {
        Self::build(tree, Leads::FirstSlot)
    }

    /// As `new_leader`, with this node leading slot 5 as well, so the loop produces it within
    /// the window on top of slot 4.
    fn new_window_leader(tree: Tree<Slot>) -> Self {
        Self::build(tree, Leads::FirstTwoSlots)
    }

    fn build(tree: Tree<Slot>, leads: Leads) -> Self {
        let is_leader = leads != Leads::Nothing;
        let FixtureForks {
            bank_forks,
            progress,
            blockstore,
            funded,
        } = fixture_forks(tree);
        let blockstore = Arc::new(blockstore);
        let root_bank = bank_forks.read().unwrap().root_bank();
        // Post-migration banks run PoH in low-power mode (one hash per tick); the fixture's
        // banks predate that, so every bank built on them inherits it from here.
        for bank in bank_forks.read().unwrap().banks().values() {
            bank.set_hashes_per_tick(None);
        }
        // Slot 4's leader collects its fees, so a crash reproduces with the same bank hashes only
        // if it is the same key every run: in leader mode this node's identity comes from a fixed
        // seed, and in replay mode the identity it can take over is a constant. A keypair, not just
        // a pubkey, because the real block creation loop reads its identity from a `ClusterInfo`,
        // which holds the keypair.
        let leader_identity = Arc::new(Keypair::new_from_array([0x4c; 32]));
        let my_pubkey = if is_leader {
            leader_identity.pubkey()
        } else {
            Pubkey::new_unique()
        };
        let takeover_identity = Pubkey::new_from_array([0xf1; 32]);
        let mut leader_schedule_cache = LeaderScheduleCache::new_from_bank(&root_bank);
        // Slot 4 has a leader of its own and every other slot keeps the fixture's, so replay
        // still creates banks for the fixture slots and the child slot. In leader mode slot 4 is
        // ours, and slot 5 too when this node leads more of the window; otherwise slot 4 belongs
        // to an identity this node can later take over.
        let other = leader_schedule_cache
            .slot_leader_at(0, Some(&root_bank))
            .expect("fixture has a leader");
        let slot_four_leader = if is_leader {
            SlotLeader {
                id: my_pubkey,
                vote_address: Pubkey::new_unique(),
            }
        } else {
            SlotLeader {
                id: takeover_identity,
                vote_address: Pubkey::new_from_array([0xf2; 32]),
            }
        };
        let schedule: Vec<SlotLeader> = (0..32)
            .map(|slot| match (slot, leads) {
                (4, _) | (5, Leads::FirstTwoSlots) => slot_four_leader,
                _ => other,
            })
            .collect();
        leader_schedule_cache.set_fixed_leader_schedule(Some(FixedSchedule {
            leader_schedule: Arc::new(LeaderSchedule::new_from_schedule(
                schedule,
                NonZeroUsize::MIN,
            )),
        }));
        let leader_schedule_cache = Arc::new(leader_schedule_cache);
        let (update_parent_sender, update_parent_receiver) = bounded(1024);
        blockstore.add_update_parent_signal(update_parent_sender);

        let (tss_proxy_sender, tss_proxy_receiver) = crossbeam_channel::unbounded();
        let (tss_input_sender, tss_input_receiver) = crossbeam_channel::unbounded();
        let dependency_tracker = Arc::new(DependencyTracker::default());
        // Both watermarks start at the ledger root, as a validator builds them
        // (`initialize_rpc_transaction_history_services`, `validator.rs:2807-2809`).
        let max_complete_transaction_status_slot = Arc::new(AtomicU64::new(blockstore.max_root()));
        let max_complete_and_rooted_transaction_status_slot =
            Arc::new(AtomicU64::new(blockstore.max_root()));
        let tss_exit = Arc::new(AtomicBool::new(false));
        let tss = TransactionStatusService::new(
            tss_input_receiver,
            max_complete_transaction_status_slot.clone(),
            max_complete_and_rooted_transaction_status_slot.clone(),
            blockstore.clone(),
            TransactionStatusServiceConfig {
                enable_rpc_transaction_history: true,
                dependency_tracker: Some(dependency_tracker.clone()),
                // A validator points this at the RPC notifier; the harness runs none (see
                // `rpc_subscriptions` below), so nothing would consume it.
                transaction_history_notification_sender: None,
                ..TransactionStatusServiceConfig::default_for_tests()
            },
            tss_exit.clone(),
            None,
        );
        let tss_gate = TssGate::spawn(tss_proxy_receiver, tss_input_sender);
        let tss_sender = TransactionStatusSender {
            sender: tss_proxy_sender,
            dependency_tracker: Some(dependency_tracker.clone()),
        };
        // The unified scheduler sends status batches through the sender configured on the
        // pool, not the one on the replay context, so the pool must get the same sender.
        bank_forks.write().unwrap().install_scheduler_pool(
            DefaultSchedulerPool::new_for_verification(None, None, Some(tss_sender.clone()), None),
        );

        // A validator queues a dropped bank's purge to the accounts background service rather
        // than purging it inline in `Bank::drop`. The harness does the same so the gap between
        // the drop and the purge is a state the program can schedule through `QueuedPurge`.
        let (pruned_banks_sender, pruned_banks_receiver) = crossbeam_channel::unbounded();
        {
            let root_bank = bank_forks.read().unwrap().root_bank();
            root_bank
                .rc
                .accounts
                .accounts_db
                .enable_bank_drop_callback();
            // Children inherit the callback from their parent, but the fixture's banks already
            // exist, so each one needs it.
            for bank in bank_forks.read().unwrap().banks().values() {
                bank.set_callback(Some(Box::new(SendDroppedBankCallback::new(
                    pruned_banks_sender.clone(),
                ))));
            }
        }
        let pruned_banks = PrunedBanksRequestHandler {
            pruned_banks_receiver,
        };

        // Startup replay and the bank forks controller read the bank forks' own status, so
        // that is the one every component of the harness shares.
        let migration_status = bank_forks.read().unwrap().migration_status();
        enable_alpenglow_for_tests(&migration_status);
        let mut active_banks_context =
            ProcessActiveBanksContext::new_for_tests(bank_forks.clone(), blockstore.clone());
        active_banks_context.transaction_status_sender = Some(tss_sender.clone());
        active_banks_context.migration_status = migration_status.clone();

        let (drop_bank_sender, drop_bank_receiver) = bounded(1024);
        let (votor_commitment_sender, votor_commitment_receiver) = bounded(1024);
        // Rooting emits the bank notifications RPC's confirmed-bank tracker consumes
        // (`votor/src/root_utils.rs:72-86` and `:164-193`). Wiring the real sender means the
        // harness drives both ends of C9 with production code instead of deciding for itself
        // what a root does to the confirmed bank. `should_send_parents` follows a validator
        // without geyser (`validator.rs:1332`), which is what this fixture is.
        let (bank_notification_sender, bank_notification_receiver) = bounded(1024);
        let votor_bank_notification_sender = bank_notification_sender.clone();
        let bank_forks_context = ProcessBankForksContext {
            bank_forks: bank_forks.clone(),
            blockstore: blockstore.clone(),
            snapshot_controller: None,
            bank_notification_sender: Some(BankNotificationSenderConfig {
                sender: bank_notification_sender,
                should_send_parents: false,
                dependency_tracker: Some(dependency_tracker.clone()),
            }),
            // Rooting tells TSS which bank generation was rooted
            // (`votor/src/root_utils.rs:157-159`), and RPC serves a slot's history as finalized
            // only once TSS has seen that same generation frozen and rooted (#15418). Replay
            // builds this context with the validator's sender (`replay_stage.rs`, `run`).
            transaction_status_sender: Some(tss_sender.clone()),
            rpc_subscriptions: None,
            drop_bank_sender,
            leader_schedule_cache: leader_schedule_cache.clone(),
            votor_commitment_sender,
        };

        let (leader, bank_forks_commands) = if is_leader {
            let (handle, receiver) = BankForksControllerHandle::new();
            let leader = LeaderSide::new(
                leader_identity,
                bank_forks.clone(),
                blockstore.clone(),
                leader_schedule_cache.clone(),
                Arc::new(handle),
                tss_sender.clone(),
            );
            (Some(leader), Some(receiver))
        } else {
            (None, None)
        };

        let block_commitment_cache = Arc::new(RwLock::new(BlockCommitmentCache::default()));
        let optimistically_confirmed_bank = Arc::new(RwLock::new(OptimisticallyConfirmedBank {
            bank: bank_forks.read().unwrap().root_bank(),
        }));
        let rpc = JsonRpcRequestProcessor::new_for_tests(
            bank_forks.clone(),
            block_commitment_cache.clone(),
            blockstore.clone(),
            optimistically_confirmed_bank.clone(),
            max_complete_transaction_status_slot.clone(),
            max_complete_and_rooted_transaction_status_slot.clone(),
        );
        // The confirmed-bank tracker needs somewhere to send its notifications. Nothing here
        // subscribes, and `notification_threads: None` means no notifier thread is spawned, so
        // this costs a channel: the fuzz path builds a harness per program and may not start
        // threads or open files per run.
        let rpc_subscriptions = Arc::new(RpcSubscriptions::new_with_config(
            tss_exit.clone(),
            max_complete_transaction_status_slot.clone(),
            max_complete_and_rooted_transaction_status_slot.clone(),
            blockstore.clone(),
            bank_forks.clone(),
            block_commitment_cache.clone(),
            optimistically_confirmed_bank.clone(),
            &PubSubConfig {
                notification_threads: None,
                ..PubSubConfig::default_for_tests()
            },
            RpcNotificationConfig::default(),
        ));

        Self {
            blockstore,
            bank_forks,
            progress,
            leader_schedule_cache,
            my_pubkey,
            takeover_identity,
            migration_status,
            update_parent_receiver,
            active_banks_context,
            bank_forks_context,
            drop_bank_receiver,
            pruned_banks,
            _votor_commitment_receiver: votor_commitment_receiver,
            async_verification_freelist: Vec::new(),
            block_commitment_cache,
            latest_switch_request: LatestSwitchRequest::default(),
            pending_switch: None,
            tss: Some(tss),
            tss_exit,
            tss_sender,
            tss_gate: Some(tss_gate),
            dependency_tracker,
            max_complete_transaction_status_slot,
            max_complete_and_rooted_transaction_status_slot,
            optimistically_confirmed_bank,
            rpc_subscriptions,
            bank_notification_receiver,
            votor_bank_notification_sender,
            confirmed_tracker: Mutex::new(ConfirmedBankTrackerState::default()),
            rpc,
            funded,
            next_id: Cell::new(0),
            model: GenerationModel::default(),
            leader,
            bank_forks_commands,
            broadcast: BroadcastState::default(),
        }
    }

    fn bank(&self, slot: Slot) -> Option<Arc<Bank>> {
        self.bank_forks.read().unwrap().get(slot)
    }

    /// A fresh address, derived from this harness's own counter.
    fn next_pubkey(&self) -> Pubkey {
        let seed = self.next_id.get();
        self.next_id.set(seed.saturating_add(1));
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8] = 0xA1;
        Pubkey::from(bytes)
    }

    /// A fresh block id, derived from this harness's own counter.
    fn next_block_id(&self) -> BlockId {
        BlockId::from(Hash::new_from_array(self.next_pubkey().to_bytes()))
    }

    fn block_id(&self, slot: Slot) -> BlockId {
        self.bank_forks
            .read()
            .unwrap()
            .block_id(slot)
            .unwrap_or_else(|| panic!("slot {slot} has no frozen bank with a block id"))
    }

    // ---- shred insertion (what turbine would deliver) -------------------------------------

    fn component_shreds(
        slot: Slot,
        shred_parent_slot: Slot,
        component: &BlockComponent,
        fec_set_index: u32,
        is_last_in_slot: bool,
    ) -> Vec<Shred> {
        Shredder::new(slot, shred_parent_slot, 0, 0)
            .unwrap()
            .make_merkle_shreds_from_component(
                &Keypair::new(),
                component,
                is_last_in_slot,
                Hash::new_unique(),
                fec_set_index,
                fec_set_index,
                &mut ProcessShredsStats::default(),
            )
    }

    fn insert_component(
        &self,
        slot: Slot,
        shred_parent_slot: Slot,
        component: &BlockComponent,
        fec_set_index: u32,
        is_last_in_slot: bool,
    ) {
        let shreds = Self::component_shreds(
            slot,
            shred_parent_slot,
            component,
            fec_set_index,
            is_last_in_slot,
        );
        self.blockstore.insert_shreds(shreds, true).unwrap();
    }

    /// Inserts a component into an alternate block location, the way block-id repair does.
    fn insert_component_at_location(
        &self,
        slot: Slot,
        shred_parent_slot: Slot,
        component: &BlockComponent,
        fec_set_index: u32,
        is_last_in_slot: bool,
        location: BlockLocation,
    ) {
        let shreds = Self::component_shreds(
            slot,
            shred_parent_slot,
            component,
            fec_set_index,
            is_last_in_slot,
        );
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        let mut recovery_context =
            ShredRecoveryContext::new(retransmit_sender_for_tests(), root_bank, 0);
        let mut pinnable_slice = self.blockstore.new_pinnable_slice();
        let mut write_batch = self.blockstore.get_write_batch();
        // Block-id repair, the only producer of alternate locations, delivers data shreds only.
        let data_shreds: Vec<Shred> = shreds.into_iter().filter(Shred::is_data).collect();
        self.blockstore
            .insert_shreds_at_location_handle_duplicate(
                data_shreds.into_iter().map(|shred| {
                    (
                        shred, /*is_repaired:*/ true, location,
                        /*precomputed_merkle_root:*/ None,
                    )
                }),
                true,
                &mut recovery_context,
                &mut pinnable_slice,
                &mut write_batch,
                &|_duplicate: PossibleDuplicateShred| {},
                &mut BlockstoreInsertionMetrics::default(),
            )
            .unwrap();
    }

    fn header_component(&self, parent_slot: Slot) -> BlockComponent {
        BlockComponent::new_block_marker(VersionedBlockMarker::from_block_header(BlockHeaderV1 {
            parent_slot,
            parent_block_id: self.block_id(parent_slot),
        }))
    }

    /// Entries chain across batches: the first batch starts from the parent's last blockhash,
    /// later ones from the previous batch's last entry hash.
    fn transfer_batch_component_at(
        &mut self,
        slot: Slot,
        parent_slot: Slot,
        location: BlockLocation,
    ) -> BlockComponent {
        let parent_bank = self.bank(parent_slot).unwrap();
        let destination = self.next_pubkey();
        let transaction = system_transaction::transfer(
            &self.funded,
            &destination,
            1_000,
            parent_bank.last_blockhash(),
        );
        let signature = transaction.signatures[0];
        let previous_hash = *self
            .model
            .last_entry_hash
            .get(&(slot, location))
            .unwrap_or(&parent_bank.last_blockhash());
        let entry = entry::next_entry(&previous_hash, 1, vec![transaction.clone()]);
        self.model
            .last_entry_hash
            .insert((slot, location), entry.hash);
        self.model
            .transfers
            .entry(slot)
            .or_default()
            .push(Transfer {
                signature,
                destination,
                transaction,
                shred_index: None,
                location,
            });
        BlockComponent::new_entry_batch(vec![entry]).unwrap()
    }

    fn transfer_batch_component(&mut self, slot: Slot, parent_slot: Slot) -> BlockComponent {
        self.transfer_batch_component_at(slot, parent_slot, BlockLocation::Original)
    }

    /// Block header at FEC set 0, naming `parent_slot` and its real block id.
    fn insert_block_header(&self, slot: Slot, parent_slot: Slot) {
        let header = self.header_component(parent_slot);
        self.insert_component(slot, parent_slot, &header, 0, false);
    }

    /// One entry batch holding one transfer, chained from `parent_slot`'s last blockhash so it
    /// executes when the slot replays on top of `parent_slot`.
    fn insert_transfer_batch(
        &mut self,
        slot: Slot,
        parent_slot: Slot,
        fec_set_index: u32,
    ) -> Signature {
        let component = self.transfer_batch_component(slot, parent_slot);
        self.insert_component(slot, parent_slot, &component, fec_set_index, false);
        let transfer = self
            .model
            .transfers
            .get_mut(&slot)
            .unwrap()
            .last_mut()
            .unwrap();
        transfer.shred_index = Some(fec_set_index);
        transfer.signature
    }

    /// A transfer batch whose first data shred is withheld: the FEC set stays incomplete, so
    /// replay stops before it while a later marker is still recognised (its previous shred is
    /// the set's data-complete last shred). Returns the withheld shred; blockstore serves
    /// nothing past a gap, so a recreated bank cannot read its suffix until the gap is repaired,
    /// even though the prefix is never executed.
    fn insert_incomplete_transfer_batch(
        &mut self,
        slot: Slot,
        parent_slot: Slot,
        fec_set_index: u32,
    ) -> Shred {
        let component = self.transfer_batch_component(slot, parent_slot);
        let transfer = self
            .model
            .transfers
            .get_mut(&slot)
            .unwrap()
            .last_mut()
            .unwrap();
        transfer.shred_index = Some(fec_set_index);
        let (withheld, shreds): (Vec<Shred>, Vec<Shred>) =
            Self::component_shreds(slot, parent_slot, &component, fec_set_index, false)
                .into_iter()
                .partition(|shred| shred.is_data() && shred.index() == fec_set_index);
        self.blockstore.insert_shreds(shreds, true).unwrap();
        withheld.into_iter().next().unwrap()
    }

    /// A complete alternate version of `slot` (header plus one transfer batch that ends the
    /// slot) under `Alternate { placeholder }`, registered so a switch request for
    /// `placeholder` resolves to it. Returns the version's transaction signature.
    fn insert_alternate_version(
        &mut self,
        slot: Slot,
        parent_slot: Slot,
        placeholder: BlockId,
    ) -> Signature {
        let location = BlockLocation::Alternate {
            block_id: placeholder.to_hash(),
        };
        let header = self.header_component(parent_slot);
        self.insert_component_at_location(slot, parent_slot, &header, 0, false, location);
        let batch = self.transfer_batch_component_at(slot, parent_slot, location);
        self.insert_component_at_location(
            slot,
            parent_slot,
            &batch,
            FEC_SET_SHREDS,
            /*is_last_in_slot:*/ true,
            location,
        );
        self.blockstore
            .set_double_merkle_root(slot, location, placeholder.to_hash())
            .unwrap();
        let transfer = self
            .model
            .transfers
            .get_mut(&slot)
            .unwrap()
            .last_mut()
            .unwrap();
        transfer.shred_index = Some(FEC_SET_SHREDS);
        transfer.signature
    }

    /// After an UpdateParent the entry chain restarts from the new parent's last blockhash, as
    /// the recreated bank's progress does.
    fn reset_entry_chain(&mut self, slot: Slot, new_parent_slot: Slot) {
        let last_blockhash = self.bank(new_parent_slot).unwrap().last_blockhash();
        self.model
            .last_entry_hash
            .insert((slot, BlockLocation::Original), last_blockhash);
    }

    /// Builds the components that complete `slot` on top of `parent_slot`: `suffix_batches`
    /// transfer batches, a footer carrying the bank hash the replacement will compute, and the
    /// alpentick. The hash comes from a shadow bank that mirrors replay's own steps (same
    /// parent, leader and tick setup, the same transactions, the footer's clock update, the
    /// tick registration, then freeze).
    ///
    /// The shadow shares the accounts db with the live banks and writes at `slot`, so it may
    /// only exist while no live bank occupies that slot; afterwards its slot-keyed traces are
    /// removed with the same triple the discard paths use. Insert the returned components with
    /// `insert_completion` once the slot is ready for them.
    fn build_completion(
        &mut self,
        slot: Slot,
        parent_slot: Slot,
        suffix_batches: u32,
        location: BlockLocation,
    ) -> Vec<BlockComponent> {
        assert!(
            self.bank(slot).is_none(),
            "a shadow bank at slot {slot} would merge into the live bank's slot cache"
        );
        let parent_bank = self.bank(parent_slot).unwrap();
        let mut components = Vec::new();
        let mut transfers = Vec::new();
        for _ in 0..suffix_batches {
            components.push(self.transfer_batch_component_at(slot, parent_slot, location));
            transfers.push(self.model.transfers[&slot].last().unwrap().clone());
        }
        let last_entry_hash = *self
            .model
            .last_entry_hash
            .get(&(slot, location))
            .unwrap_or(&parent_bank.last_blockhash());
        let alpentick = entry::next_entry(&last_entry_hash, 1, vec![]);

        let leader = self
            .leader_schedule_cache
            .slot_leader_at(slot, Some(&parent_bank))
            .unwrap();
        let shadow = Bank::new_from_parent(parent_bank.clone(), leader, slot);
        set_alpenglow_ticks(&shadow, &self.migration_status);
        for transfer in &transfers {
            shadow
                .process_transaction(&transfer.transaction)
                .expect("suffix transfer must execute on the shadow bank");
        }
        let parent_time_nanos = parent_bank
            .get_nanosecond_clock()
            .unwrap_or_else(|| shadow.clock().unix_timestamp.saturating_mul(1_000_000_000));
        let elapsed = shadow.slot_range_duration_nanos(parent_slot.saturating_add(1), slot);
        let (block_producer_time_nanos, _) =
            BlockComponentProcessor::nanosecond_time_bounds(parent_time_nanos, elapsed);
        BlockComponentProcessor::update_bank_with_footer_fields(
            &shadow,
            block_producer_time_nanos,
            None,
            None,
            None,
        )
        .unwrap();
        shadow.register_tick_for_test(&alpentick.hash);
        shadow.freeze();
        let bank_hash = shadow.hash();
        self.model
            .footer_bank_hash
            .insert((slot, location), bank_hash);

        // Remove every slot-keyed trace of the shadow before a live bank can take the slot. Its
        // write cache goes when it drops (#16508), through the accounts background service
        // (an inline purge is refused once the drop callback is enabled). The callback it
        // inherited would queue that purge behind whatever the program left on the harness's
        // ABS queue, so the shadow gets a queue of its own and the real handler runs it now.
        // The shadow is the harness's own bank, never in bank forks, so no production path
        // changes.
        let (shadow_drop_sender, shadow_drop_receiver) = crossbeam_channel::unbounded();
        shadow.set_callback(Some(Box::new(SendDroppedBankCallback::new(
            shadow_drop_sender,
        ))));
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        root_bank.clear_slot_signatures(slot);
        root_bank.prune_program_cache_by_deployment_slot(slot);
        drop(shadow);
        let shadow_purges = PrunedBanksRequestHandler {
            pruned_banks_receiver: shadow_drop_receiver,
        };
        let purged = shadow_purges.handle_request(&root_bank);
        assert!(
            purged == 1,
            "shadow purges run: {purged}\nthe shadow bank's write cache was not purged"
        );

        components.push(BlockComponent::new_block_marker(
            VersionedBlockMarker::from_block_footer(BlockFooterV1 {
                bank_hash,
                block_producer_time_nanos: u64::try_from(block_producer_time_nanos).unwrap(),
                block_user_agent: b"flh-harness".to_vec(),
                block_final_cert: None,
                skip_reward_cert: None,
                notar_reward_cert: None,
            }),
        ));
        components.push(BlockComponent::new_entry_batch(vec![alpentick]).unwrap());
        components
    }

    /// Inserts components from `build_completion` at consecutive FEC sets; the last one ends
    /// the slot. The transfer batches come first, in the order their transfers were made
    /// pending; the footer and the alpentick carry no transfers.
    fn insert_completion(
        &mut self,
        slot: Slot,
        shred_parent_slot: Slot,
        components: &[BlockComponent],
        mut fec_set_index: u32,
        location: BlockLocation,
    ) {
        let last = components.len() - 1;
        let transfer_batches = components.len() - 2;
        let unplaced = self
            .model
            .transfers
            .get_mut(&slot)
            .into_iter()
            .flatten()
            .filter(|transfer| transfer.shred_index.is_none());
        for (batch, transfer) in unplaced.take(transfer_batches).enumerate() {
            transfer.shred_index =
                Some(fec_set_index + u32::try_from(batch).unwrap() * FEC_SET_SHREDS);
        }
        for (index, component) in components.iter().enumerate() {
            let is_last_in_slot = index == last;
            match location {
                BlockLocation::Original => self.insert_component(
                    slot,
                    shred_parent_slot,
                    component,
                    fec_set_index,
                    is_last_in_slot,
                ),
                BlockLocation::Alternate { .. } => self.insert_component_at_location(
                    slot,
                    shred_parent_slot,
                    component,
                    fec_set_index,
                    is_last_in_slot,
                    location,
                ),
            }
            fec_set_index += FEC_SET_SHREDS;
        }
    }

    /// UpdateParent marker at `fec_set_index`, re-parenting `slot` onto `new_parent_slot`.
    fn insert_update_parent(
        &self,
        slot: Slot,
        shred_parent_slot: Slot,
        new_parent_slot: Slot,
        fec_set_index: u32,
    ) {
        let marker = VersionedBlockMarker::from_update_parent(UpdateParentV1 {
            new_parent_slot,
            new_parent_block_id: self.block_id(new_parent_slot),
        });
        self.insert_component(
            slot,
            shred_parent_slot,
            &BlockComponent::new_block_marker(marker),
            fec_set_index,
            false,
        );
    }

    // ---- replay-stage steps, in the order the replay loop runs them -----------------------

    fn handle_update_parent_interrupts(&mut self) {
        handle_update_parent_interrupts(
            &self.my_pubkey,
            &self.blockstore,
            &self.bank_forks,
            &mut self.progress,
            &mut self.async_verification_freelist,
            &self.update_parent_receiver,
            None,
            Some(&self.tss_sender),
        )
        .unwrap();
    }

    fn generate_new_bank_forks(&mut self) {
        let context = NewBankForksContext {
            blockstore: &self.blockstore,
            bank_forks: &self.bank_forks,
            leader_schedule_cache: &self.leader_schedule_cache,
            rpc_subscriptions: None,
            slot_status_notifier: &None,
            my_pubkey: &self.my_pubkey,
            transaction_status_sender: Some(&self.tss_sender),
        };
        ReplayStage::generate_new_bank_forks(
            context,
            &mut self.progress,
            &mut ReplayLoopTiming::default(),
        )
        .expect("the harness keeps TSS alive, so the purge always queues");
    }

    /// Replays whatever completed shred ranges `slot` has, from its progress offset, through
    /// the real replay path (so TSS receives real status batches).
    /// Replay creates the progress entry lazily when it first replays a bank (the UpdateParent
    /// re-creation path pre-seeds it instead); the harness mirrors that wherever a bank is about
    /// to be replayed or frozen, since `generate_new_bank_forks` expects every frozen bank to
    /// have one.
    fn ensure_progress(&mut self, bank: &Bank) {
        Self::seed_progress(
            &mut self.progress,
            &mut self.async_verification_freelist,
            bank,
        );
    }

    /// The entry replay creates (`replay_stage.rs:1175-1191`), except that a missing parent
    /// entry is a harness bug here rather than a slot to abandon.
    fn seed_progress(
        progress: &mut ProgressMap,
        async_verification_freelist: &mut Vec<AsyncVerificationProgress>,
        bank: &Bank,
    ) {
        let slot = bank.slot();
        if progress.get(&slot).is_some() {
            return;
        }
        let parent_slot = bank.parent_slot();
        let parent_stats = progress
            .get(&parent_slot)
            .unwrap_or_else(|| panic!("no progress entry for parent slot {parent_slot}"));
        let num_blocks_on_fork = parent_stats.num_blocks_on_fork + 1;
        let num_dropped_blocks_on_fork =
            parent_stats.num_dropped_blocks_on_fork + (slot - parent_slot - 1);
        progress.entry(slot).or_insert_with(|| {
            ForkProgress::new_from_bank(
                bank,
                num_blocks_on_fork,
                num_dropped_blocks_on_fork,
                async_verification_freelist.pop(),
            )
        });
    }

    fn replay(&mut self, slot: Slot) -> result::Result<usize, BlockstoreProcessorError> {
        let bank = self
            .bank_forks
            .read()
            .unwrap()
            .get_with_scheduler(slot)
            .unwrap_or_else(|| panic!("no bank for slot {slot}"));
        self.ensure_progress(&bank);
        let fork_progress = self.progress.get(&slot).unwrap();
        let (finalization_cert_sender, _finalization_cert_receiver) = bounded(1024);
        let first_shred = fork_progress.replay_progress.read().unwrap().num_shreds;
        let result = ReplayStage::replay_blockstore_into_bank(
            shred_version_for_tests(),
            &self.active_banks_context,
            &bank,
            &fork_progress.replay_stats,
            &fork_progress.replay_progress,
            &finalization_cert_sender,
        );
        // Attribute the transfers in the shred range this pass executed: up to the new progress
        // on success, up to the marker when it abandoned the bank there (everything before the
        // marker still ran). Transfers below the bank's first shred were not executed by it.
        let executed_until = match &result {
            Ok(_) => Some(
                self.progress
                    .get(&slot)
                    .unwrap()
                    .replay_progress
                    .read()
                    .unwrap()
                    .num_shreds,
            ),
            Err(BlockstoreProcessorError::BlockComponentProcessor(
                BlockComponentProcessorError::AbandonedBank(_),
            )) => Some(u64::from(
                self.blockstore
                    .meta(slot)
                    .unwrap()
                    .unwrap()
                    .replay_fec_set_index,
            )),
            Err(_) => None,
        };
        if let Some(executed_until) = executed_until {
            let executed: Vec<Signature> = self
                .model
                .transfers
                .get(&slot)
                .into_iter()
                .flatten()
                .filter(|transfer| {
                    // Replay reads the slot's live block, so a transfer stored under another
                    // version (an alternate waiting for a switch) is not in what it executed.
                    transfer.location == BlockLocation::Original
                        && transfer.shred_index.is_some_and(|index| {
                            (first_shred..executed_until).contains(&u64::from(index))
                        })
                })
                .map(|transfer| transfer.signature)
                .collect();
            if let Ok(transaction_count) = &result {
                assert!(
                    executed.len() == *transaction_count,
                    "model {}, replay {transaction_count} (slot {slot}, shreds \
                     {first_shred}..{executed_until})\nmodel attributed a different number of \
                     transfers than replay executed",
                    executed.len()
                );
            }
            self.wait_for_history_rows(slot, &executed);
            self.model
                .generations
                .entry(slot)
                .or_default()
                .push(Generation {
                    bank_id: bank.bank_id(),
                    signatures: executed,
                });
        }
        result
    }

    /// Execution runs on the scheduler's threads and the status batch is sent when the task
    /// commits, so a drain right after a replay pass could run ahead of it. Waiting for the rows
    /// of the transactions this pass executed syncs with that without retiring the scheduler,
    /// which the real loop only does when the bank freezes.
    fn wait_for_history_rows(&self, slot: Slot, signatures: &[Signature]) {
        if signatures.is_empty() || !self.tss_gate.as_ref().is_some_and(TssGate::is_open) {
            return;
        }
        let started = std::time::Instant::now();
        let mut noted = false;
        loop {
            let missing = signatures
                .iter()
                .filter(|signature| {
                    self.blockstore
                        .read_transaction_status((**signature, slot))
                        .unwrap()
                        .is_none()
                })
                .count();
            if missing == 0 {
                return;
            }
            note_slow_wait(started, &mut noted, || {
                format!("rows of {missing} transactions executed at slot {slot}")
            });
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Records a generation that was created but never replayed (its signatures are empty).
    fn record_empty_generation(&mut self, slot: Slot) {
        let bank = self.bank(slot).unwrap();
        assert!(
            !self
                .model
                .generations
                .get(&slot)
                .is_some_and(|generations| generations
                    .iter()
                    .any(|generation| generation.bank_id == bank.bank_id())),
            "generation {:?} at slot {slot} was already recorded",
            bank.bank_id()
        );
        self.model
            .generations
            .entry(slot)
            .or_default()
            .push(Generation {
                bank_id: bank.bank_id(),
                signatures: Vec::new(),
            });
    }

    /// Generations that startup replay created at slots the harness has transfers for: a full
    /// slot is replayed from its marker offset, so those are the transfers it executed.
    fn record_startup_generations(&mut self) {
        let banks: Vec<Arc<Bank>> = {
            let forks = self.bank_forks.read().unwrap();
            forks
                .banks()
                .values()
                .map(|bank| bank.clone_without_scheduler())
                .collect()
        };
        for bank in banks {
            let slot = bank.slot();
            if !self.model.transfers.contains_key(&slot) {
                continue;
            }
            let recorded = self
                .model
                .generations
                .get(&slot)
                .is_some_and(|generations| {
                    generations
                        .iter()
                        .any(|generation| generation.bank_id == bank.bank_id())
                });
            if recorded {
                continue;
            }
            let start = self
                .blockstore
                .meta(slot)
                .unwrap()
                .unwrap()
                .replay_fec_set_index;
            let signatures = self.model.transfers_from(slot, start);
            self.model
                .generations
                .entry(slot)
                .or_default()
                .push(Generation {
                    bank_id: bank.bank_id(),
                    signatures,
                });
        }
    }

    /// A validator restart. Every bank above the root is gone (a snapshot of the root is what
    /// comes back), the ledger is what it was, and startup replay rebuilds the forks from the
    /// blockstore through the real `process_blockstore_from_root`, with TSS attached so the
    /// startup-time purge of pre-UpdateParent history runs.
    /// A switch replaces the slot's block wholesale: the version that was `Original` is gone
    /// from the blockstore, and the alternate takes its place. The model follows, so attribution
    /// never credits a generation with transactions that are no longer in the block.
    fn switch_transfer_locations(
        &mut self,
        slot: Slot,
        switched_in: BlockLocation,
        switched_out: BlockId,
    ) {
        let retired = BlockLocation::Alternate {
            block_id: switched_out.to_hash(),
        };
        for transfer in self.model.transfers.entry(slot).or_default() {
            // Retired rather than dropped: earlier generations still name these signatures,
            // and the oracles look their destinations up.
            transfer.location = if transfer.location == switched_in {
                BlockLocation::Original
            } else if transfer.location == BlockLocation::Original {
                retired
            } else {
                transfer.location
            };
        }
    }

    /// One accounts-background-service pass over the dropped-bank queue. A validator runs this
    /// every 100 ms; the delay between a bank's drop and this purge is the window the late-purge
    /// and startup-discard bugs (fixed by #16102 and #16180) both depended on.
    fn run_queued_purges(&self) -> usize {
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        self.pruned_banks.handle_request(&root_bank)
    }

    /// What `DropBankService` (`core/src/drop_bank_service.rs`) does with the banks a root
    /// prunes: drops them, which queues each one's write-cache purge for the ABS. A validator
    /// runs it on its own thread as the banks arrive; the harness runs it right after each
    /// root. Before #16508 holding these banks was harmless because pruning purged inline.
    fn run_drop_bank_service(drop_bank_receiver: &Receiver<Vec<BankWithScheduler>>) {
        while let Ok(banks) = drop_bank_receiver.try_recv() {
            drop(banks);
        }
    }

    /// Every bank generation that still has write-cache entries, with its slot. Each bank stores
    /// its sysvars when it is created, so every generation has entries until it is purged. The
    /// cache is keyed by `BankId`, and the harness's banks draw ids from one counter starting at
    /// 0, so drawing the next id bounds the scan exactly (the id it uses up is never needed).
    fn cached_generations(&self) -> Vec<(BankId, Slot)> {
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        let next_bank_id = u64::from(root_bank.rc.next_bank_id());
        let accounts_cache = &root_bank.rc.accounts.accounts_db.accounts_cache;
        (0..next_bank_id)
            .map(BankId::new)
            .filter_map(|bank_id| {
                accounts_cache
                    .bank_cache(bank_id)
                    .map(|cache| (bank_id, cache.slot()))
            })
            .collect()
    }

    /// Deploys a loader-v3 program into the live bank at `slot`, with `slot` as its deployment
    /// slot, by storing the program and programdata accounts the way a finished deploy leaves
    /// them. A program is visible only from the slot after its deployment, so the invocation
    /// that puts it in the global program cache belongs in a child slot.
    fn deploy_program_at(&mut self, slot: Slot) -> Pubkey {
        let bank = self.bank(slot).expect("deploy needs a live bank");
        let program_id = self.next_pubkey();
        let accounts = bpf_loader_upgradeable_program_accounts(
            &program_id,
            NOOP_ELF,
            &Pubkey::new_unique(),
            &bank.rent_collector().rent,
        );
        for (address, mut account) in accounts {
            // The helper stamps deployment slot 0; the cache keys entries by the deployment slot
            // in the programdata, and this generation deployed at `slot`.
            if address != program_id {
                let mut data = wincode::serialize(&UpgradeableLoaderState::ProgramData {
                    slot,
                    upgrade_authority_address: Some(Pubkey::new_unique()),
                })
                .unwrap();
                data.extend_from_slice(NOOP_ELF);
                account.data = data;
            }
            bank.store_account(&address, &AccountSharedData::from(account));
        }
        self.model.deployed_program = Some((program_id, bank.bank_id()));
        program_id
    }

    /// An entry batch whose transaction invokes `program_id`, for a child slot of the slot the
    /// program was deployed at.
    fn invoke_component_at(
        &mut self,
        slot: Slot,
        parent_slot: Slot,
        program_id: Pubkey,
    ) -> BlockComponent {
        let parent_bank = self.bank(parent_slot).unwrap();
        // The invocation rides along with a transfer so the slot's transactions stay the
        // transfers the model tracks and attributes by shred range.
        let destination = self.next_pubkey();
        let transaction = Transaction::new_signed_with_payer(
            &[
                system_instruction::transfer(&self.funded.pubkey(), &destination, 1_000),
                Instruction::new_with_bytes(program_id, &[], Vec::new()),
            ],
            Some(&self.funded.pubkey()),
            &[&self.funded],
            parent_bank.last_blockhash(),
        );
        let signature = transaction.signatures[0];
        let previous_hash = *self
            .model
            .last_entry_hash
            .get(&(slot, BlockLocation::Original))
            .unwrap_or(&parent_bank.last_blockhash());
        let entry = entry::next_entry(&previous_hash, 1, vec![transaction.clone()]);
        self.model
            .last_entry_hash
            .insert((slot, BlockLocation::Original), entry.hash);
        self.model
            .transfers
            .entry(slot)
            .or_default()
            .push(Transfer {
                signature,
                destination,
                transaction,
                shred_index: Some(FEC_SET_SHREDS),
                location: BlockLocation::Original,
            });
        BlockComponent::new_entry_batch(vec![entry]).unwrap()
    }

    /// C3: program-cache entries deployed at `slot` that belong to a generation other than the
    /// one that now owns the slot. A discard must prune them
    /// (`prune_program_cache_by_deployment_slot`), or the replacement inherits the discarded
    /// generation's program.
    fn program_cache_leaks(&self, slot: Slot) -> Vec<Pubkey> {
        let Some((program_id, deployed_by)) = self.model.deployed_program else {
            return Vec::new();
        };
        let live = self.bank(slot).map(|bank| bank.bank_id());
        if live == Some(deployed_by) {
            return Vec::new();
        }
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        let cache = root_bank
            .get_transaction_processor()
            .global_program_cache
            .read()
            .unwrap();
        cache
            .get_slot_versions_for_tests(&program_id)
            .iter()
            .any(|entry| entry.deployment_slot == slot)
            .then_some(program_id)
            .into_iter()
            .collect()
    }

    /// Roots `slot` in the ledger and the leader schedule without advancing the bank forks
    /// root. Steady state does both (`check_and_handle_new_root` sets the blockstore roots
    /// before `set_bank_forks_root`), so this is the state a restart finds whenever the
    /// snapshot it loads is older than the ledger's latest root.
    fn ledger_root(&mut self, slot: Slot) {
        let bank = self.bank(slot).expect("ledger root needs the slot's bank");
        let mut rooted: Vec<Slot> = bank.parents().iter().map(|parent| parent.slot()).collect();
        rooted.push(slot);
        rooted.retain(|rooted_slot| *rooted_slot >= self.bank_forks.read().unwrap().root());
        self.blockstore.set_roots(rooted.iter()).unwrap();
        self.leader_schedule_cache.set_root(&bank);
    }

    /// Stores a complete alternate version of `slot` on `parent_slot`: header, one transfer
    /// batch, the footer carrying the hash replay will compute, and the alpentick. Block-id
    /// repair delivers versions like this, and a switch to one revives the slot with a block
    /// replay can freeze. Returns the version's block id.
    fn insert_complete_alternate_version(&mut self, slot: Slot, parent_slot: Slot) -> BlockId {
        assert!(
            self.bank(slot).is_none(),
            "the shadow bank in build_completion would merge into a live bank at slot {slot}"
        );
        let block_id = self.next_block_id();
        let location = BlockLocation::Alternate {
            block_id: block_id.to_hash(),
        };
        let header = self.header_component(parent_slot);
        self.insert_component_at_location(slot, parent_slot, &header, 0, false, location);
        let completion = self.build_completion(slot, parent_slot, 1, location);
        self.insert_completion(slot, parent_slot, &completion, FEC_SET_SHREDS, location);
        self.blockstore
            .set_double_merkle_root(slot, location, block_id.to_hash())
            .unwrap();
        block_id
    }

    /// A validator restart. `drained` says how the old process went: `true` is a graceful exit
    /// that let TSS finish its queue, `false` an exit or crash with a backlog, which is lost.
    fn restart(&mut self, drained: bool) {
        if drained {
            // A graceful exit lets TSS finish, which means it is forwarding again.
            self.open_tss_gate();
            self.drain_tss();
        } else {
            self.discard_tss_backlog();
        }
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        // A block id is a property of the block's shreds, so the banks startup rebuilds carry
        // the ids their predecessors had (the fixture's tick-only slots get none from replay).
        let block_ids: Vec<(Slot, BlockId)> = {
            let forks = self.bank_forks.read().unwrap();
            forks
                .banks()
                .values()
                .filter_map(|bank| bank.block_id().map(|block_id| (bank.slot(), block_id)))
                .collect()
        };
        let removed: Vec<BankWithScheduler> = {
            let mut bank_forks = self.bank_forks.write().unwrap();
            let slots: Vec<Slot> = bank_forks
                .banks()
                .keys()
                .copied()
                .filter(|slot| *slot != root_bank.slot())
                .collect();
            slots
                .into_iter()
                .filter_map(|slot| bank_forks.remove(slot))
                .collect()
        };
        for bank in &removed {
            let _ = bank.wait_for_completed_scheduler();
        }
        // A fresh accounts db and status cache would hold none of the removed banks' state, and
        // a fresh process has no accounts-background-service backlog either. Dropping queues
        // each removed bank's write-cache purge (#16508 moved that purge into the drop), so one
        // pass over the queue empties the cache of everything the old process discarded,
        // including banks it dropped earlier whose purge had not run yet.
        let removed_slots: Vec<Slot> = removed.iter().map(|bank| bank.slot()).collect();
        for slot in &removed_slots {
            root_bank.clear_slot_signatures(*slot);
            root_bank.prune_program_cache_by_deployment_slot(*slot);
        }
        drop(removed);
        Self::run_drop_bank_service(&self.drop_bank_receiver);
        self.run_queued_purges();
        // A new process also has a new scheduler pool, so it holds none of the banks the old
        // pool's idle schedulers keep (a scheduler keeps the last bank it ran until its next
        // session, so a discarded bank's purge waits for that since #16508). Bank forks cannot
        // take a new pool, so those banks outlive the restart here; what the new process would
        // not have is their write cache. Roots still waiting to flush are part of the state it
        // loads, and the purge skips them itself.
        let accounts_db = &root_bank.rc.accounts.accounts_db;
        for (bank_id, _slot) in self.cached_generations() {
            if bank_id != root_bank.bank_id() {
                accounts_db.purge_slot(bank_id, /*is_serialized_with_abs:*/ true);
            }
        }
        self.progress = ProgressMap::default();
        self.async_verification_freelist.clear();
        self.pending_switch = None;
        while self.update_parent_receiver.try_recv().is_ok() {}

        // A new process builds both history watermarks from the ledger root
        // (`validator.rs:2807-2809`, `AtomicU64::new(blockstore.max_root())`), not from whatever
        // the last process reached. The old values can sit above the ledger root, because every
        // frozen bank lifts the first with `fetch_max` across forks and nothing lowers either,
        // so carrying them over would let reads admit slots a restarted validator withholds.
        // Startup replay lifts the first again for the slots it actually walks. TSS keeps its
        // frozen/rooted bookkeeping across this restart (one thread serves every process here).
        // It is keyed by `BankId`, and the harness's banks keep drawing ids from the same
        // counter across the restart, so nothing the old process recorded can match a bank the
        // new one builds; a validator gets the same result from starting a fresh TSS.
        let max_root = self.blockstore.max_root();
        self.max_complete_transaction_status_slot
            .store(max_root, Ordering::SeqCst);
        self.max_complete_and_rooted_transaction_status_slot
            .store(max_root, Ordering::SeqCst);
        let options = ProcessOptions {
            run_verification: false,
            accounts_db_config: ACCOUNTS_DB_CONFIG_FOR_TESTING,
            ..ProcessOptions::default()
        };
        process_blockstore_from_root(
            &self.blockstore,
            &self.bank_forks,
            shred_version_for_tests(),
            &self.leader_schedule_cache,
            &options,
            Some(&self.tss_sender),
            None,
            None,
        )
        .expect("startup replay must succeed on the harness ledger");
        for (slot, block_id) in block_ids {
            if let Some(bank) = self.bank(slot)
                && bank.is_frozen()
                && bank.block_id().is_none()
            {
                bank.set_block_id(Some(block_id));
            }
        }
        // A validator builds its commitment cache from the forks it loaded
        // (`validator.rs:1158-1163`), so nothing a previous run left in it survives a restart.
        {
            let forks = self.bank_forks.read().unwrap();
            let (working, root) = (forks.working_bank().slot(), forks.root());
            drop(forks);
            self.block_commitment_cache
                .write()
                .unwrap()
                .initialize_slots(working, root);
        }
        // The optimistically confirmed bank is seeded from the loaded root in the same place
        // (`validator.rs:1166-1167`, `OptimisticallyConfirmedBank::locked_from_bank_forks_root`).
        // Carrying the old process's bank over would leave it below the root the restart just
        // loaded, which no validator can be. The tracker's scratch state goes with it: a new
        // process starts it empty.
        {
            let root_bank = self.bank_forks.read().unwrap().root_bank();
            self.optimistically_confirmed_bank.write().unwrap().bank = root_bank;
            *self.confirmed_tracker.lock().unwrap() = ConfirmedBankTrackerState::default();
            // The notification channel dies with the process it belonged to, so anything the
            // old one queued and never processed is gone, not waiting for the new tracker.
            while self.bank_notification_receiver.try_recv().is_ok() {}
        }
        self.seed_progress_for_all_banks();
        self.record_startup_generations();
        let root = self.bank_forks.read().unwrap().root();
        for (slot, bank_id) in self.model.rooted.clone() {
            if slot > root {
                self.model.rooted.remove(&slot);
            } else if slot == root
                && let Some(bank) = self.bank(slot)
                && bank.bank_id() != bank_id
            {
                self.model.rooted.insert(slot, bank.bank_id());
            }
        }
    }

    /// After a restart, progress exists for no bank; replay would create it for each as it is
    /// replayed, and the root's entry comes from initialisation.
    fn seed_progress_for_all_banks(&mut self) {
        let mut banks: Vec<Arc<Bank>> = {
            let forks = self.bank_forks.read().unwrap();
            forks
                .banks()
                .values()
                .map(|bank| bank.clone_without_scheduler())
                .collect()
        };
        banks.sort_by_key(|bank| bank.slot());
        let root = self.bank_forks.read().unwrap().root();
        for bank in banks {
            if bank.slot() == root {
                // As `ReplayStage::initialize_progress` seeds it.
                self.progress
                    .entry(root)
                    .or_insert_with(|| ForkProgress::new_from_bank(&bank, 0, 0, None));
            } else {
                self.ensure_progress(&bank);
            }
        }
    }

    /// Feeds a replay result through the real post-replay handling (dead marking, abandoned
    /// bank, freeze). This is how an UpdateParent met mid-replay becomes R2.
    fn process_replay_result(
        &mut self,
        slot: Slot,
        replay_result: result::Result<usize, BlockstoreProcessorError>,
    ) {
        self.process_replay_slot(slot, Some(replay_result));
    }

    /// The replay loop's handling of its own leader bank: never replayed from the blockstore,
    /// frozen once PoH reached the last tick, block id from the shreds if broadcast has them.
    fn complete_leader_bank(&mut self, slot: Slot) {
        let bank = self.bank(slot).unwrap();
        self.ensure_progress(&bank);
        drop(bank);
        self.process_replay_slot(slot, None);
    }

    fn process_replay_slot(
        &mut self,
        slot: Slot,
        replay_result: Option<result::Result<usize, BlockstoreProcessorError>>,
    ) {
        let results = [ReplaySlotFromBlockstore {
            is_slot_dead: false,
            bank_slot: slot,
            replay_result,
        }];
        ReplayStage::process_replay_results(
            &self.active_banks_context,
            &mut self.progress,
            &mut self.async_verification_freelist,
            &results,
            &self.my_pubkey,
        )
        .unwrap();
    }

    /// Votor's first-round vote for a frozen bank: the commitment cache's processed slot. Under
    /// Alpenglow notarisation does not move the confirmed bank; only the votor root does (see
    /// `drain_tss`).
    fn notarize(&self, slot: Slot) {
        assert!(self.bank(slot).unwrap().is_frozen());
        self.block_commitment_cache.write().unwrap().set_slot(slot);
    }

    /// Votor asks replay to switch `slot` to the block `block_id` (R3).
    fn request_switch(&mut self, slot: Slot, block_id: BlockId) {
        self.latest_switch_request
            .try_advance(SwitchBankEvent::Switch {
                block: Block { slot, block_id },
            });
    }

    fn process_switch_bank_events(&mut self) {
        ReplayStage::process_switch_bank_events(
            &self.my_pubkey,
            &self.latest_switch_request,
            &mut self.pending_switch,
            &self.blockstore,
            &self.bank_forks,
            &mut self.progress,
            &mut self.async_verification_freelist,
            Some(&self.tss_sender),
        )
        .unwrap();
    }

    /// Freezes an unreplayed bank directly. Used where the test is about what happens after a
    /// slot roots, not about how its block was completed.
    fn freeze_for_test(&mut self, slot: Slot) {
        let bank = self.bank(slot).unwrap();
        self.ensure_progress(&bank);
        bank.freeze();
        bank.set_block_id(Some(BlockId::new_unique()));
    }

    /// `freeze_for_test` plus what replay sends once it has frozen a block: the freeze message
    /// that tells TSS this generation is complete (`replay_stage.rs:1572-1578`). Since #15418,
    /// RPC serves a slot's history as finalized only after TSS has seen that same generation
    /// frozen and rooted, so a freeze TSS never hears about withholds the slot's history for
    /// good, which no validator does.
    /// Takes over the identity that leads slot 4, as an operator's `set-identity` failover does.
    /// Replay rereads the identity every loop iteration, so from here a block for slot 4 is this
    /// node's own: replay creates its bank only once the block is full in the blockstore, and
    /// freezes it without checking the footer (`replay_stage.rs:2046-2052` and `:1523-1528`).
    /// Sigverify drops shreds of slots this node leads, repair included
    /// (`turbine/src/sigverify_shreds.rs:463-470`), so nothing more of the block arrives; the
    /// program enforces that, since the harness inserts shreds itself.
    fn set_identity(&mut self) {
        self.my_pubkey = self.takeover_identity;
    }

    /// Leader mode: this node gives up the identity that leads the slot (an operator's
    /// `set-identity` onto another key). Replay and the block creation loop both see the new
    /// one, the loop the way it does at a window start (`block_creation_loop.rs`, `run_loop`).
    fn move_leader_identity(&mut self) {
        let successor = Pubkey::new_from_array([0x5e; 32]);
        self.my_pubkey = successor;
        self.drive_leader(move |leader| leader.set_identity(successor));
    }

    /// Slots whose queued status writes the last crash restart threw away.
    fn take_crash_lost_slots(&self) -> BTreeSet<Slot> {
        self.tss_gate
            .as_ref()
            .map(TssGate::take_lost_slots)
            .unwrap_or_default()
    }

    fn freeze_like_replay(&mut self, slot: Slot) {
        self.freeze_for_test(slot);
        let bank = self.bank(slot).unwrap();
        self.tss_sender
            .send_transaction_status_freeze_message(&bank);
    }

    /// Roots `slot` through the real votor set-root path (replay side).
    fn set_root(&mut self, slot: Slot) {
        let block_id = self.block_id(slot);
        // Votor sends this as it enqueues the SetRootCommand (`votor/src/root_utils.rs:58` then
        // `:72-86`), and replay handles that command later, so the confirmation reaches the
        // tracker BEFORE the `NewRootBank` the command produces. Sending it after would let
        // `NewRootBank` move the confirmed bank first and leave the confirmation with nothing to
        // do. `votor::root_utils::set_root` is `pub(crate)`, so the harness stands in for it.
        let bank_hash = self.bank(slot).expect("the rooted slot has a bank").hash();
        let work = self.dependency_tracker.get_current_declared_work();
        let _ = self.votor_bank_notification_sender.try_send((
            BankNotification::OptimisticallyConfirmed(slot, bank_hash),
            Some(work),
        ));
        ReplayStage::process_set_root_command(
            SetRootCommand {
                new_root: Block { slot, block_id },
            },
            &self.bank_forks_context,
            &self.my_pubkey,
            &mut self.progress,
        );
        Self::run_drop_bank_service(&self.drop_bank_receiver);
        let root = self.bank_forks.read().unwrap().root();
        assert!(
            root == slot,
            "requested root {slot}, bank forks root {root}\nthe set-root command did not root the \
             slot"
        );
        let bank_id = self.bank(slot).unwrap().bank_id();
        self.model.rooted.insert(slot, bank_id);
        // The commitment aggregation service publishes the new root to RPC's commitment cache.
        let mut commitment_cache = self.block_commitment_cache.write().unwrap();
        commitment_cache.set_root(slot);
        commitment_cache.set_highest_super_majority_root(slot);
    }

    // ---- leader side ----------------------------------------------------------------------

    /// Runs `f` on the block creation loop's own thread while this thread, as ReplayStage, services
    /// the bank-forks commands it issues through the real handler.
    fn drive_leader<R: Send>(&mut self, f: impl FnOnce(&mut LeaderSide) -> R + Send) -> R {
        let leader = self.leader.as_mut().expect("leader mode");
        let receiver = self.bank_forks_commands.as_ref().expect("leader mode");
        let context = &self.bank_forks_context;
        let active_banks_context = &self.active_banks_context;
        let bank_forks = self.bank_forks.clone();
        let progress = &mut self.progress;
        let freelist = &mut self.async_verification_freelist;
        let my_pubkey = self.my_pubkey;
        let drop_bank_receiver = &self.drop_bank_receiver;
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || f(leader));
            loop {
                if let Some(command) = receiver.take_set_root_command() {
                    ReplayStage::process_set_root_command(command, context, &my_pubkey, progress);
                    Self::run_drop_bank_service(drop_bank_receiver);
                }
                // ReplayStage freezes a leader bank once PoH reached its last tick; the recorder
                // waits for that before it sends the footer, so this must run concurrently.
                let completed: Vec<Arc<Bank>> = bank_forks
                    .read()
                    .unwrap()
                    .banks()
                    .values()
                    .filter(|bank| {
                        !bank.should_replay_from_blockstore()
                            && bank.is_complete()
                            && !bank.is_frozen()
                    })
                    .map(|bank| bank.clone_without_scheduler())
                    .collect();
                for bank in completed {
                    Self::seed_progress(progress, freelist, &bank);
                    let results = [ReplaySlotFromBlockstore {
                        is_slot_dead: false,
                        bank_slot: bank.slot(),
                        replay_result: None,
                    }];
                    ReplayStage::process_replay_results(
                        active_banks_context,
                        progress,
                        freelist,
                        &results,
                        &my_pubkey,
                    )
                    .unwrap();
                }
                match receiver.receiver().recv_timeout(Duration::from_millis(5)) {
                    Ok(command) => ReplayStage::process_bank_forks_command(
                        command, context, progress, freelist,
                    ),
                    Err(RecvTimeoutError::Timeout) => {
                        if worker.is_finished() {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            worker.join().expect("leader step panicked")
        })
    }

    /// Banking stage for one transfer: execute it in the working bank, record it with PoH from
    /// the pre-commit callback (the bank's execution token is held there, so a bank being
    /// retired under the loop, by a root prune say, gets no record), commit it and send its
    /// status batch to TSS. Returns false when the bank was retired and nothing happened.
    fn leader_record(&mut self) -> result::Result<bool, String> {
        let leader = self.leader.as_ref().expect("leader mode");
        let bank = leader.working_bank().ok_or("no working bank")?;
        let slot = bank.slot();
        let destination = self.next_pubkey();
        let transaction =
            system_transaction::transfer(&self.funded, &destination, 1_000, bank.last_blockhash());
        let signature = transaction.signatures[0];
        let batch = bank.prepare_batch_for_tests(vec![transaction.clone()]);
        let mut transaction_index = None;
        let committed = bank.load_execute_and_commit_transactions_with_pre_commit_callback(
            &batch,
            ExecutionRecordingConfig::new_single_setting(true),
            &mut ExecuteTimings::default(),
            None,
            |processing_results| {
                // A bank being retired under the loop fails the execution token, and the bank
                // then runs this callback over `CommitCancelled` results. Banking stage never
                // reaches PoH in that case: it takes the token first and returns early when it
                // is gone (`banking_stage/consumer.rs:331-335`), and it holds the freeze lock
                // across record and commit, so a recorded transaction is always committed.
                // Recording here instead would leave a transaction in the record receiver with
                // no status row, and the leader purge that names it would kill TSS.
                if let Err(err) = &processing_results[0] {
                    return Err(err.clone());
                }
                let index = leader
                    .record(vec![VersionedTransaction::from(transaction.clone())])
                    .map_err(|_| TransactionError::CommitCancelled)?;
                transaction_index = Some(index);
                Ok(())
            },
        );
        let (commit_results, _balances) = match committed {
            Ok(committed) => committed,
            Err(TransactionError::CommitCancelled) => return Ok(false),
            Err(err) => return Err(format!("{err:?}")),
        };
        match &commit_results[0] {
            Ok(_) => {}
            Err(TransactionError::CommitCancelled) => return Ok(false),
            Err(err) => return Err(format!("leader transfer must execute: {err:?}")),
        }
        let transaction_index = transaction_index.expect("recorded before the commit");
        self.tss_sender.send_transaction_status_batch(
            slot,
            bank.bank_id(),
            batch
                .sanitized_transactions()
                .iter()
                .map(|transaction| (**transaction).clone())
                .collect(),
            commit_results,
            TransactionBalancesSet::new(vec![vec![]], vec![vec![]]),
            TransactionTokenBalancesSet::new(vec![vec![]], vec![vec![]]),
            vec![None],
            vec![transaction_index],
        );
        drop(batch);
        let bank_id = bank.bank_id();
        self.model
            .transfers
            .entry(slot)
            .or_default()
            .push(Transfer {
                signature,
                destination,
                transaction,
                shred_index: None,
                location: BlockLocation::Original,
            });
        let _ = signature;
        let generations = self.model.generations.entry(slot).or_default();
        match generations
            .iter_mut()
            .find(|generation| generation.bank_id == bank_id)
        {
            Some(generation) => generation.signatures.push(signature),
            None => generations.push(Generation {
                bank_id,
                signatures: vec![signature],
            }),
        }
        Ok(true)
    }

    /// Broadcast: shreds everything PoH handed over so far and inserts it into the blockstore,
    /// setting the leader bank's block id once the last shred is in, as the broadcast stage does.
    fn broadcast(&mut self) {
        let messages: Vec<WorkingBankMessage> =
            self.leader.as_ref().expect("leader mode").take_entries();
        for (bank, (message, tick_height)) in messages {
            let slot = bank.slot();
            if self.broadcast.slot != Some(slot) {
                self.broadcast = BroadcastState {
                    slot: Some(slot),
                    parent_slot: bank.parent_slot(),
                    header_sent: false,
                    next_index: 0,
                };
            }
            let is_tick_entry = matches!(message, RecorderMessage::Entry(_));
            let component = match message {
                RecorderMessage::SlotStart => {
                    // A second slot start for the same slot (after a handover) gets no header.
                    if self.broadcast.header_sent {
                        continue;
                    }
                    self.broadcast.header_sent = true;
                    BlockComponent::new_block_marker(VersionedBlockMarker::from_block_header(
                        BlockHeaderV1 {
                            parent_slot: bank.parent_slot(),
                            parent_block_id: bank
                                .parent_block_id()
                                .expect("leader parent has a block id"),
                        },
                    ))
                }
                RecorderMessage::Entry(entry) => {
                    for transaction in &entry.transactions {
                        let signature = transaction.signatures[0];
                        if let Some(transfer) = self
                            .model
                            .transfers
                            .get_mut(&slot)
                            .into_iter()
                            .flatten()
                            .find(|transfer| transfer.signature == signature)
                        {
                            transfer.shred_index = Some(self.broadcast.next_index);
                        }
                    }
                    BlockComponent::new_entry_batch(vec![entry]).unwrap()
                }
                RecorderMessage::Marker(marker) => BlockComponent::new_block_marker(marker),
            };
            let is_last = is_tick_entry && tick_height == bank.max_tick_height();
            self.insert_component(
                slot,
                self.broadcast.parent_slot,
                &component,
                self.broadcast.next_index,
                is_last,
            );
            self.broadcast.next_index += FEC_SET_SHREDS;
            if is_last {
                // Production's broadcast computes the block id from the merkle roots of the
                // shreds it just made and sets it whatever the blockstore then does with them
                // (`standard_broadcast_run.rs`, `set_block_id_and_send`), so a leader slot always
                // has one by the time the next slot's header names it as parent. The harness
                // reads it back from the blockstore, which keeps none of a slot whose fork a root
                // pruned (its parent is below the root). Nothing can compare that block's id with
                // stored shreds, so the harness names one.
                let block_id = match self
                    .blockstore
                    .get_block_id(slot, &self.migration_status)
                    .unwrap()
                {
                    Some(block_id) => BlockId::from(block_id),
                    None => self.next_block_id(),
                };
                bank.set_block_id(Some(block_id));
            }
        }
    }

    // ---- TSS control --------------------------------------------------------------------------

    /// Blocks until TSS has processed every message sent so far. Uses an empty status batch
    /// carrying a dependency-tracker work id as a sentinel: TSS is a single FIFO consumer and
    /// marks the id only after writing, so everything queued before it is done.
    fn drain_tss(&self) {
        // Draining is catching up, so the gate forwards again: waiting behind a shut gate would
        // never return. A program models TSS lagging with `Op::TssLag` and ends that lag here.
        self.open_tss_gate();
        let root_bank = self.bank_forks.read().unwrap().root_bank();
        self.tss_sender.send_transaction_status_batch(
            root_bank.slot(),
            root_bank.bank_id(),
            vec![],
            vec![],
            TransactionBalancesSet::new(vec![], vec![]),
            TransactionTokenBalancesSet::new(vec![], vec![]),
            vec![],
            vec![],
        );
        let work = self.dependency_tracker.get_current_declared_work();
        let tracker = self.dependency_tracker.clone();
        let (done_sender, done_receiver) = bounded(1);
        std::thread::spawn(move || {
            tracker.wait_for_dependency(work);
            let _ = done_sender.send(());
        });
        let started = std::time::Instant::now();
        let mut noted = false;
        loop {
            match done_receiver.recv_timeout(TssGate::POLL) {
                Ok(()) => break,
                Err(RecvTimeoutError::Timeout) => note_slow_wait(started, &mut noted, || {
                    format!(
                        "TSS to drain (exit flag = {})",
                        self.tss_exit.load(Ordering::Relaxed)
                    )
                }),
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("the TSS drain waiter thread died")
                }
            }
        }
        // Rooting queued bank notifications; hand them to the real tracker rather than deciding
        // here what a root does to the confirmed bank. Its guards are the thing under test, and
        // a paraphrase of them is how the confirmed bank came to sit below the root across a
        // restart. The tracker runs on its own thread in a validator, gated on the same
        // dependency work that was just waited for, so draining it here is the same ordering.
        let mut guard = self.confirmed_tracker.lock().unwrap();
        let tracker = &mut *guard;
        while let Ok(notification) = self.bank_notification_receiver.try_recv() {
            OptimisticallyConfirmedBankTracker::process_notification(
                notification,
                &self.bank_forks,
                &self.optimistically_confirmed_bank,
                &self.rpc_subscriptions,
                &mut tracker.pending,
                &mut tracker.last_notified_confirmed_slot,
                &mut tracker.highest_confirmed_slot,
                &mut tracker.newest_root_slot,
                &None,
                None,
                &Some(self.dependency_tracker.clone()),
            );
        }
    }

    /// Stops forwarding to TSS: everything replay sends from now on stays queued, as if TSS were
    /// arbitrarily far behind. Anything that waits on TSS must open the gate first, or it waits
    /// forever; the ops that do are `DrainTss` and `Switch`.
    fn close_tss_gate(&self) {
        if let Some(gate) = &self.tss_gate {
            gate.set_open(false);
        }
    }

    fn tss_gate_is_open(&self) -> bool {
        self.tss_gate.as_ref().is_none_or(TssGate::is_open)
    }

    fn open_tss_gate(&self) {
        if let Some(gate) = &self.tss_gate {
            gate.set_open(true);
        }
    }

    /// Throws away whatever TSS has not yet written, which is what a process exit does: the
    /// service breaks on its exit flag without draining, so queued rows never reach the
    /// blockstore. Leaves the gate open and forwarding again, for the process that comes next.
    fn discard_tss_backlog(&self) {
        let Some(gate) = &self.tss_gate else {
            return;
        };
        gate.set_discard(true);
        gate.set_open(true);
        // The sender's queue plus the one message the gate holds in flight; poll both empty.
        let started = std::time::Instant::now();
        let mut noted = false;
        while !self.tss_sender.sender.is_empty() {
            note_slow_wait(started, &mut noted, || {
                "the TSS backlog to drain through the gate".to_owned()
            });
            std::thread::sleep(TssGate::POLL);
        }
        std::thread::sleep(TssGate::POLL * 3);
        gate.set_discard(false);
    }

    // ---- RPC: what a client sees ---------------------------------------------------------------

    fn rpc_signature_status(
        &self,
        signature: Signature,
        commitment: CommitmentConfig,
    ) -> Option<TransactionStatus> {
        let config = RpcSignatureStatusConfig {
            search_transaction_history: true,
            commitment: Some(commitment),
            min_context_slot: None,
        };
        futures::executor::block_on(
            self.rpc
                .get_signature_statuses(vec![signature], Some(config)),
        )
        .unwrap()
        .value
        .pop()
        .flatten()
    }

    fn rpc_transaction_slot(
        &self,
        signature: Signature,
        commitment: CommitmentConfig,
    ) -> Option<Slot> {
        let config = RpcTransactionConfig {
            commitment: Some(commitment),
            ..RpcTransactionConfig::default()
        };
        futures::executor::block_on(self.rpc.get_transaction(
            signature,
            Some(RpcEncodingConfigWrapper::Current(Some(config))),
        ))
        .unwrap()
        .map(|transaction| transaction.slot)
    }

    fn rpc_signatures_for_address(
        &self,
        address: Pubkey,
        commitment: CommitmentConfig,
    ) -> Vec<(Signature, Slot)> {
        let config = RpcContextConfig {
            commitment: Some(commitment),
            min_context_slot: None,
        };
        futures::executor::block_on(
            self.rpc
                .get_signatures_for_address(address, None, None, 1000, config),
        )
        .unwrap()
        .into_iter()
        .map(|item| (item.signature.parse().unwrap(), item.slot))
        .collect()
    }

    /// `getBlock` with full transaction details: each signature with whether its status meta
    /// was present. `Err` carries the RPC error text (not rooted, not yet available, ...).
    fn rpc_block(
        &self,
        slot: Slot,
        commitment: CommitmentConfig,
    ) -> result::Result<Option<Vec<(Signature, bool)>>, String> {
        let config = RpcBlockConfig {
            encoding: Some(UiTransactionEncoding::Base64),
            transaction_details: Some(TransactionDetails::Full),
            rewards: Some(false),
            commitment: Some(commitment),
            max_supported_transaction_version: Some(0),
        };
        let block = futures::executor::block_on(
            self.rpc
                .get_block(slot, Some(RpcEncodingConfigWrapper::Current(Some(config)))),
        )
        .map_err(|err| err.to_string())?;
        Ok(block.map(|block| {
            block
                .transactions
                .unwrap_or_default()
                .into_iter()
                .map(|transaction| {
                    let decoded = transaction
                        .transaction
                        .decode()
                        .expect("base64 transaction decodes");
                    (decoded.signatures[0], transaction.meta.is_some())
                })
                .collect()
        }))
    }

    /// I1 through RPC: for every signature the harness ever replayed, each finalized history
    /// query answers with the rooted generation's slot or with nothing, and a finalized block
    /// never lacks status meta.
    fn rpc_finalized_soundness_violations(&self) -> Vec<RpcViolation> {
        let allowed = self.model.rooted_signatures();
        let finalized = CommitmentConfig::finalized();
        let mut violations = Vec::new();
        for (signature, destination) in self.model.every_transfer() {
            let served = [
                (
                    "getSignatureStatuses",
                    self.rpc_signature_status(signature, finalized)
                        .map(|status| status.slot),
                ),
                (
                    "getTransaction",
                    self.rpc_transaction_slot(signature, finalized),
                ),
            ];
            for (query, slot) in served {
                if let Some(slot) = slot
                    && allowed.get(&signature) != Some(&slot)
                {
                    violations.push(RpcViolation {
                        query,
                        signature,
                        slot,
                    });
                }
            }
            for (served_signature, slot) in self.rpc_signatures_for_address(destination, finalized)
            {
                if allowed.get(&served_signature) != Some(&slot) {
                    violations.push(RpcViolation {
                        query: "getSignaturesForAddress",
                        signature: served_signature,
                        slot,
                    });
                }
            }
        }
        for slot in self.model.generations.keys().copied() {
            let Ok(Some(transactions)) = self.rpc_block(slot, finalized) else {
                continue;
            };
            for (signature, has_meta) in transactions {
                if allowed.get(&signature) != Some(&slot) {
                    violations.push(RpcViolation {
                        query: "getBlock",
                        signature,
                        slot,
                    });
                } else if !has_meta {
                    violations.push(RpcViolation {
                        query: "getBlock without status meta",
                        signature,
                        slot,
                    });
                }
            }
        }
        violations
    }

    /// What a confirmed read may legitimately return: the rooted generations plus the generations
    /// on the confirmed bank's own ancestry (by bank id, so a replaced generation at an ancestor
    /// slot is excluded).
    fn confirmed_signatures(&self) -> BTreeMap<Signature, Slot> {
        let confirmed_bank = self
            .optimistically_confirmed_bank
            .read()
            .unwrap()
            .bank
            .clone();
        let mut bank_ids: HashSet<BankId> = confirmed_bank
            .parents()
            .iter()
            .map(|bank| bank.bank_id())
            .collect();
        bank_ids.insert(confirmed_bank.bank_id());
        let mut allowed = self.model.rooted_signatures();
        for (slot, generations) in &self.model.generations {
            for generation in generations {
                if bank_ids.contains(&generation.bank_id) {
                    for signature in &generation.signatures {
                        allowed.insert(*signature, *slot);
                    }
                }
            }
        }
        allowed
    }

    /// I1 at confirmed commitment: each query answers with a generation on the confirmed bank's
    /// ancestry (or a rooted one) at its slot, or with nothing.
    fn rpc_confirmed_soundness_violations(&self) -> Vec<RpcViolation> {
        let allowed = self.confirmed_signatures();
        let confirmed = CommitmentConfig::confirmed();
        let mut violations = Vec::new();
        for (signature, destination) in self.model.every_transfer() {
            let served = [
                (
                    "getSignatureStatuses(confirmed)",
                    self.rpc_signature_status(signature, confirmed)
                        .map(|status| status.slot),
                ),
                (
                    "getTransaction(confirmed)",
                    self.rpc_transaction_slot(signature, confirmed),
                ),
            ];
            for (query, slot) in served {
                if let Some(slot) = slot
                    && allowed.get(&signature) != Some(&slot)
                {
                    violations.push(RpcViolation {
                        query,
                        signature,
                        slot,
                    });
                }
            }
            for (served_signature, slot) in self.rpc_signatures_for_address(destination, confirmed)
            {
                if allowed.get(&served_signature) != Some(&slot) {
                    violations.push(RpcViolation {
                        query: "getSignaturesForAddress(confirmed)",
                        signature: served_signature,
                        slot,
                    });
                }
            }
        }
        for slot in self.model.generations.keys().copied() {
            let Ok(Some(transactions)) = self.rpc_block(slot, confirmed) else {
                continue;
            };
            for (signature, has_meta) in transactions {
                if allowed.get(&signature) != Some(&slot) {
                    violations.push(RpcViolation {
                        query: "getBlock(confirmed)",
                        signature,
                        slot,
                    });
                } else if !has_meta {
                    violations.push(RpcViolation {
                        query: "getBlock(confirmed) without status meta",
                        signature,
                        slot,
                    });
                }
            }
        }
        violations
    }

    /// A frozen bank must have computed the bank hash its block promised in the footer.
    ///
    /// Replay enforces this itself, but **only for slots someone else led**
    /// (`replay_stage.rs:1523-1528` gates `freeze_and_verify_bank_hash` on
    /// `!leader_is_me`), so a slot this node led and later replayed freezes with no check at all.
    /// A switch causes that (replay executes leader banks after a SwitchBank since #14580), and
    /// so does a repair after set-identity. The harness holds the footer hashes it built, so it
    /// can assert the invariant on every slot and catch a divergence production would accept in
    /// silence.
    ///
    /// Compared against every version built for the slot rather than the one believed live: a
    /// correct replay lands on one of them, and this way the oracle does not depend on the
    /// harness's own belief about which version won.
    fn footer_hash_violations(&self, slot: Slot) -> Option<(Hash, Vec<Hash>)> {
        let expected: Vec<Hash> = self
            .model
            .footer_bank_hash
            .iter()
            .filter(|((built_slot, _), _)| *built_slot == slot)
            .map(|(_, hash)| *hash)
            .collect();
        if expected.is_empty() {
            return None;
        }
        let bank = self.bank(slot).filter(|bank| bank.is_frozen())?;
        let computed = bank.hash();
        (!expected.contains(&computed)).then_some((computed, expected))
    }

    /// Signatures of discarded generations at `slot` whose history rows still exist.
    fn history_rows_of_discarded_generations(&self, slot: Slot) -> Vec<Signature> {
        self.discarded_only_signatures(slot)
            .into_iter()
            .filter(|signature| {
                self.blockstore
                    .read_transaction_status((*signature, slot))
                    .unwrap()
                    .is_some()
            })
            .collect()
    }

    /// I3 through RPC: once TSS drained, every rooted transaction is served by each finalized
    /// signature query at its slot. `getBlock` is left to the tests: `freeze_for_test` sends
    /// no Freeze message, so the blockstore-writes watermark never reaches such slots.
    fn rpc_finalized_completeness_violations(&self) -> Vec<RpcViolation> {
        let finalized = CommitmentConfig::finalized();
        let mut violations = Vec::new();
        for (signature, destination, slot) in self.model.rooted_transfers() {
            let missing = [
                (
                    "getSignatureStatuses",
                    self.rpc_signature_status(signature, finalized)
                        .map(|status| status.slot)
                        != Some(slot),
                ),
                (
                    "getTransaction",
                    self.rpc_transaction_slot(signature, finalized) != Some(slot),
                ),
                (
                    "getSignaturesForAddress",
                    !self
                        .rpc_signatures_for_address(destination, finalized)
                        .contains(&(signature, slot)),
                ),
            ];
            for (query, is_missing) in missing {
                if is_missing {
                    violations.push(RpcViolation {
                        query,
                        signature,
                        slot,
                    });
                }
            }
        }
        violations
    }

    // ---- oracles ------------------------------------------------------------------------------

    fn rooted_history_slot(&self, signature: Signature) -> Option<Slot> {
        self.blockstore
            .get_rooted_transaction_status(signature)
            .unwrap()
            .map(|(slot, _meta)| slot)
    }

    /// I1: a finalized history read returns a signature only from the rooted generation of
    /// its slot. Returns the violations instead of asserting so a test can document a known
    /// bug explicitly.
    fn finalized_soundness_violations(&self) -> Vec<(Signature, Slot)> {
        let allowed = self.model.rooted_signatures();
        self.model
            .every_signature()
            .into_iter()
            .filter_map(|signature| {
                let served = self.rooted_history_slot(signature)?;
                (allowed.get(&signature) != Some(&served)).then_some((signature, served))
            })
            .collect()
    }

    /// I3: every transaction of a rooted generation has its history row, once TSS drained.
    fn finalized_completeness_violations(&self) -> Vec<(Signature, Slot)> {
        self.model
            .rooted_signature_slots()
            .into_iter()
            .filter(|(signature, slot)| self.rooted_history_slot(*signature) != Some(*slot))
            .collect()
    }

    /// Generations at `slot` other than the one currently in bank forks.
    fn discarded_generations(&self, slot: Slot) -> Vec<&Generation> {
        let current = self.bank(slot).map(|bank| bank.bank_id());
        self.model
            .generations
            .get(&slot)
            .into_iter()
            .flatten()
            .filter(|generation| Some(generation.bank_id) != current)
            .collect()
    }

    /// Signatures that only discarded generations at `slot` executed: a transaction the current
    /// generation also executed (the suffix after a restart, say) is legitimately visible.
    fn discarded_only_signatures(&self, slot: Slot) -> Vec<Signature> {
        let current: HashSet<Signature> = self
            .bank(slot)
            .map(|bank| bank.bank_id())
            .and_then(|bank_id| {
                self.model.generations.get(&slot).and_then(|generations| {
                    generations
                        .iter()
                        .find(|generation| generation.bank_id == bank_id)
                })
            })
            .map(|generation| generation.signatures.iter().copied().collect())
            .unwrap_or_default();
        self.discarded_generations(slot)
            .iter()
            .flat_map(|generation| generation.signatures.iter().copied())
            .filter(|signature| !current.contains(signature))
            .collect()
    }

    /// I6 / C2: signatures of discarded generations at `slot` that the replacement bank's
    /// status cache still reports.
    fn status_cache_leaks(&self, slot: Slot) -> Vec<Signature> {
        let Some(bank) = self.bank(slot) else {
            return Vec::new();
        };
        self.discarded_only_signatures(slot)
            .into_iter()
            .filter(|signature| bank.get_signature_status(signature).is_some())
            .collect()
    }

    /// I6 / C1: accounts only a discarded generation at `slot` ever wrote that the
    /// replacement bank can still load.
    fn accounts_cache_leaks(&self, slot: Slot) -> Vec<Pubkey> {
        let Some(bank) = self.bank(slot) else {
            return Vec::new();
        };
        self.discarded_only_signatures(slot)
            .into_iter()
            .map(|signature| self.model.destination(signature))
            .filter(|destination| bank.get_account(destination).is_some())
            .collect()
    }

    /// C1 as a client sees it: an account only a discarded generation at slot 4 or 5 wrote has no
    /// balance at processed or confirmed commitment, read from whichever bank the commitment
    /// picks (the slot's replacement or a descendant of it). Since #16508 a discarded
    /// generation's write cache lives until its bank drops, which an idle pooled scheduler can
    /// put off by about 190 s; this is what RPC serves in that window.
    fn rpc_account_leaks(&self) -> (Vec<(&'static str, Pubkey, Slot)>, usize) {
        let mut leaks = Vec::new();
        let mut checked = 0;
        for slot in [ProgramRun::SLOT, ProgramRun::CHILD_SLOT] {
            let destinations: Vec<Pubkey> = self
                .discarded_only_signatures(slot)
                .into_iter()
                .map(|signature| self.model.destination(signature))
                .collect();
            for (name, commitment) in [
                ("processed", CommitmentConfig::processed()),
                ("confirmed", CommitmentConfig::confirmed()),
            ] {
                let config = RpcContextConfig {
                    commitment: Some(commitment),
                    min_context_slot: None,
                };
                for destination in &destinations {
                    checked += 1;
                    let balance = self.rpc.get_balance(destination, config).unwrap().value;
                    if balance > 0 {
                        leaks.push((name, *destination, slot));
                    }
                }
            }
        }
        (leaks, checked)
    }

    /// I6 / C8: the commitment cache's processed slot names a bank that exists but is not
    /// frozen, which is what `simulateTransaction` asserts on.
    fn commitment_cache_violation(&self) -> Option<Slot> {
        let slot = self.block_commitment_cache.read().unwrap().slot();
        self.bank(slot)
            .filter(|bank| !bank.is_frozen())
            .map(|bank| bank.slot())
    }

    /// Stops TSS without waiting out its one-second receive timeout: set the exit flag, then
    /// wake the loop with an empty batch so it re-checks the flag at once.
    fn shutdown(mut self) {
        self.open_tss_gate();
        self.drain_tss();
        // TSS no longer stops on the exit flag (#16227): `join` asks it to drain and stop, and it
        // notices between one-second receive timeouts, or at once when its input disconnects.
        // The gate holds its only input sender, so stopping the gate first makes the join
        // immediate; the other order costs up to a second per program on the fuzz path.
        if let Some(gate) = self.tss_gate.take() {
            gate.stop();
        }
        if let Some(tss) = self.tss.take() {
            tss.join().unwrap();
        }
        // Every harness opens its own ledger directory; a long fuzzing run must not keep them.
        let ledger_path = self.blockstore.ledger_path().clone();
        drop(self);
        if let Err(err) = std::fs::remove_dir_all(&ledger_path) {
            warn!("could not remove harness ledger {ledger_path:?}: {err}");
        }
    }
}

// ---- programs: operation streams over the discard paths ---------------------------------------

/// One step of a program. The interpreter runs an op only when the harness state allows it and
/// counts the rest as skipped, so every byte string is a valid program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// A transfer batch for the slot on its optimistic parent, before any marker.
    PrefixBatch,
    /// A transfer batch with its first shred withheld, so replay stops at the gap; once.
    GapBatch,
    /// The UpdateParent marker at the next FEC set, re-parenting onto the rooted sibling; once.
    Marker,
    /// Replay drains the UpdateParent signals (the restart path).
    HandleInterrupts,
    /// The UpdateParent signals are lost, as a full channel drops them.
    DropSignal,
    /// One replay pass over the slot's bank.
    Replay,
    /// Replay creates banks for the new slots in the blockstore.
    Recreate,
    /// Repair delivers the withheld shred.
    RepairGap,
    /// The leader's completion of the slot after the marker: suffix, footer, alpentick.
    Completion,
    /// Freeze the slot's bank directly, as banks without a block are frozen in tests.
    Freeze,
    /// A child slot on the frozen bank, replayed.
    Child,
    /// Votor notarises the frozen slot.
    Notarize,
    /// A certified alternate version switches the slot out (R3).
    Switch,
    /// The competing sibling roots (R5).
    PruneRoot,
    /// The slot roots.
    Root,
    /// TSS catches up.
    DrainTss,
    /// TSS falls behind: what replay sends from here stays queued. A purge queued while it is
    /// behind has not happened yet, which is what makes a crash able to lose one.
    TssLag,
    /// The accounts background service flushes the write cache.
    FlushAccounts,
    /// The accounts background service purges the banks dropped since its last pass.
    QueuedPurge,
    /// The validator restarts gracefully: TSS drains its queue on the way out (#16227), banks
    /// above the root are lost, and startup replay rebuilds them.
    Restart,
    /// The validator crashes with transaction-status writes still queued, then restarts. Those
    /// rows are never written (a graceful exit drains them, see `Restart`), and startup only
    /// purges the history of slots it walks as children, so a slot that is already the root
    /// keeps whatever the old process left.
    CrashRestart,
    /// The slot roots in the ledger only, leaving bank forks behind: the state a validator is in
    /// when its snapshot is older than the ledger's roots, so startup replay advances the root
    /// itself and prunes the forks that leaves behind (R14).
    LedgerRoot,
    /// A complete alternate version of the slot (header, suffix, footer, alpentick) is stored
    /// for block-id repair, so a later switch revives the slot with a valid block.
    AlternateComplete,
    /// The generation at the slot deploys a loader-v3 program (C3).
    DeployProgram,
    /// The child slot invokes the deployed program, putting it in the global program cache.
    InvokeProgram,
    /// Leader mode: the block creation loop starts the slot on the optimistic parent.
    LeaderStart,
    /// Leader mode: banking stage executes and records one transfer.
    LeaderRecord,
    /// Leader mode: votor certifies the optimistic parent (happy handover).
    LeaderParentReady,
    /// Leader mode: votor certifies the other sibling (sad handover: UpdateParent, new bank).
    LeaderHandover,
    /// Leader mode: the loop applies the ParentReady and completes the block.
    LeaderComplete,
    /// Leader mode: the loop aborts the working bank (R4).
    LeaderAbort,
    /// Leader mode: broadcast shreds what PoH produced so far into the blockstore.
    Broadcast,
    /// Replay mode: this node takes over the identity that leads the slot (an operator's
    /// failover). From here the slot's shreds no longer arrive, and a full block of it replays
    /// as this node's own, so its footer goes unchecked.
    SetIdentity,
    /// Leader mode, when this node leads slot 5 too: the loop starts slot 5 on its own slot 4,
    /// within the window (`produce_intra_window_slot`).
    LeaderNextSlot,
    /// Leader mode: votor certifies a parent past this node's window, so the loop aborts the slot
    /// it is producing (`abort_working_bank`) and refuses to start another.
    WindowCertifiedPast,
    /// A byte the encoding has not given an op yet (see `Op::REPLAY_TABLE`). It never runs.
    Unassigned,
    /// Replay mode: the slot roots while TSS is behind, so the rooted slot's history checks wait
    /// for the next drain. A crash before that loses the writes still queued, the purge an
    /// UpdateParent restart queued among them: the restart purge's crash leg, which upstream
    /// accepts (raised in #14432's review; #16227 drains only a graceful exit).
    RootLagging,
    /// Leader mode: the loop is handed a window whose ParentReady names a version of the parent
    /// that replay never froze. `maybe_start_leader` finds the parent's block id differs
    /// (`ParentBlockIdMismatch`), the loop waits for a bank switch that never comes, and the
    /// start gives up within its budget (`ReplayIsBehind`) having created nothing.
    LeaderStartOtherParentVersion,
    /// Leader mode: an operator moves this node to another identity between slots
    /// (`set-identity`). The loop picks that up at its next window start, updating its cached
    /// identity and next leader slot (#16637). From then on this node does not lead the slot,
    /// so the loop refuses to start one (`LeaderIdentityMismatch`).
    LeaderSetIdentity,
}

impl Op {
    /// Replay mode's encoding: byte `b` decodes to `REPLAY_TABLE[b % REPLAY_SLOTS]`, and to
    /// `Unassigned` past the table's end. **Append only.** Moving or inserting an entry changes
    /// what every stored input means, which needs a `corpus_format` bump in `targets.toml`; a new
    /// op takes the next free slot, which only changes the inputs that used that byte.
    const REPLAY_TABLE: [Op; 27] = [
        Op::PrefixBatch,
        Op::GapBatch,
        Op::Marker,
        Op::HandleInterrupts,
        Op::DropSignal,
        Op::Replay,
        Op::Recreate,
        Op::RepairGap,
        Op::Completion,
        Op::Freeze,
        Op::Child,
        Op::Notarize,
        Op::Switch,
        Op::PruneRoot,
        Op::Root,
        Op::DrainTss,
        Op::TssLag,
        Op::FlushAccounts,
        Op::QueuedPurge,
        Op::Restart,
        Op::CrashRestart,
        Op::LedgerRoot,
        Op::AlternateComplete,
        Op::DeployProgram,
        Op::InvokeProgram,
        Op::SetIdentity,
        Op::RootLagging,
    ];
    const REPLAY_SLOTS: usize = 32;

    /// Leader mode's encoding, on the same terms as `REPLAY_TABLE`.
    const LEADER_TABLE: [Op; 36] = [
        Op::PrefixBatch,
        Op::GapBatch,
        Op::Marker,
        Op::HandleInterrupts,
        Op::DropSignal,
        Op::Replay,
        Op::Recreate,
        Op::RepairGap,
        Op::Completion,
        Op::Freeze,
        Op::Child,
        Op::Notarize,
        Op::Switch,
        Op::PruneRoot,
        Op::Root,
        Op::DrainTss,
        Op::TssLag,
        Op::FlushAccounts,
        Op::QueuedPurge,
        Op::Restart,
        Op::CrashRestart,
        Op::LedgerRoot,
        Op::AlternateComplete,
        Op::DeployProgram,
        Op::InvokeProgram,
        Op::LeaderStart,
        Op::LeaderRecord,
        Op::LeaderParentReady,
        Op::LeaderHandover,
        Op::LeaderComplete,
        Op::LeaderAbort,
        Op::Broadcast,
        Op::LeaderNextSlot,
        Op::WindowCertifiedPast,
        Op::LeaderStartOtherParentVersion,
        Op::LeaderSetIdentity,
    ];
    const LEADER_SLOTS: usize = 44;

    /// The ops a program in this mode can run, in encoding order, and the slot count the
    /// encoding reduces a byte to. Each mode leaves out the ops the other alone can run, so few
    /// bytes go to ops that would be rejected on sight.
    fn encoding(leader: bool) -> (&'static [Op], usize) {
        if leader {
            (&Self::LEADER_TABLE, Self::LEADER_SLOTS)
        } else {
            (&Self::REPLAY_TABLE, Self::REPLAY_SLOTS)
        }
    }

    fn from_byte(byte: u8, leader: bool) -> Self {
        let (table, slots) = Self::encoding(leader);
        table
            .get(usize::from(byte) % slots)
            .copied()
            .unwrap_or(Op::Unassigned)
    }

    /// The byte `from_byte` maps back to this op, so a program round-trips through `to_bytes`.
    fn to_byte(self, leader: bool) -> u8 {
        let (table, slots) = Self::encoding(leader);
        let index = table.iter().position(|op| *op == self).unwrap_or(slots - 1);
        u8::try_from(index).expect("the encoding is far smaller than a byte")
    }
}

/// A walk through the discard paths at a window-first slot: which sibling the prefix builds on,
/// then the ops in order.
#[derive(Debug, Clone)]
pub struct Program {
    /// Label for messages: the RNG seed, or the fuzzer input's leading bytes.
    label: u64,
    /// Optimistic parent is slot 2 (the higher sibling) or slot 1.
    optimistic_is_higher: bool,
    /// This node leads slot 4: the block creation loop produces it instead of the network.
    leader: bool,
    /// In leader mode, this node leads slot 5 too, so the loop produces it within the window
    /// rather than another leader building on slot 4.
    leads_next_slot: bool,
    ops: Vec<Op>,
}

impl Program {
    /// Longest program the decoder reads; the fuzzer's `max_len` is one more for the header.
    pub const MAX_OPS: usize = 32;

    /// A seeded program shaped like a handover: a skeleton of the discard paths with each step
    /// kept by a coin toss, then noise ops at random positions and a few adjacent swaps. Uniform
    /// op bytes are mostly illegal and rarely reach the known open cases; the fuzzer gets its
    /// orderings from coverage instead (`from_bytes`).
    pub fn random(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let leader = rng.random_bool(0.3);
        let mut ops = Vec::new();
        let mut keep = |rng: &mut StdRng, probability: f64, op: Op| {
            if rng.random_bool(probability) {
                ops.push(op);
            }
        };
        if leader {
            let leads_next_slot = rng.random_bool(0.5);
            // A window naming a parent version replay never froze: the loop refuses it.
            keep(&mut rng, 0.1, Op::LeaderStartOtherParentVersion);
            keep(&mut rng, 1.0, Op::LeaderStart);
            keep(&mut rng, 0.8, Op::LeaderRecord);
            keep(&mut rng, 0.4, Op::LeaderRecord);
            keep(&mut rng, 0.3, Op::Broadcast);
            if rng.random_bool(0.15) {
                // The cluster moves past the window before the slot completes.
                keep(&mut rng, 1.0, Op::WindowCertifiedPast);
            } else if rng.random_bool(0.6) {
                keep(&mut rng, 1.0, Op::LeaderHandover);
            } else {
                keep(&mut rng, 1.0, Op::LeaderParentReady);
            }
            if rng.random_bool(0.85) {
                keep(&mut rng, 1.0, Op::LeaderComplete);
            } else {
                keep(&mut rng, 1.0, Op::LeaderAbort);
            }
            // An operator moves this node off the identity between slots; the loop then refuses
            // to start slot 5.
            keep(&mut rng, 0.12, Op::LeaderSetIdentity);
            if leads_next_slot {
                keep(&mut rng, 0.8, Op::LeaderNextSlot);
                keep(&mut rng, 0.6, Op::LeaderRecord);
                keep(&mut rng, 0.2, Op::WindowCertifiedPast);
                if rng.random_bool(0.15) {
                    keep(&mut rng, 1.0, Op::LeaderAbort);
                } else {
                    keep(&mut rng, 0.9, Op::LeaderComplete);
                }
            }
            keep(&mut rng, 0.8, Op::Broadcast);
            keep(&mut rng, 0.7, Op::HandleInterrupts);
            keep(&mut rng, 0.9, Op::Replay);
            keep(&mut rng, 0.5, Op::Broadcast);
            keep(&mut rng, 0.5, Op::Recreate);
            keep(&mut rng, 0.5, Op::Replay);
            if !leads_next_slot {
                keep(&mut rng, 0.3, Op::Child);
            }
            keep(&mut rng, 0.4, Op::Notarize);
            keep(&mut rng, 0.3, Op::PruneRoot);
            keep(&mut rng, 0.8, Op::Root);
            if rng.random_bool(0.3) {
                let at = rng.random_range(0..=ops.len());
                ops.insert(at, Op::Restart);
            }
            for noise in [
                Op::DrainTss,
                Op::FlushAccounts,
                Op::HandleInterrupts,
                Op::QueuedPurge,
            ] {
                for _ in 0..rng.random_range(0..=3) {
                    let at = rng.random_range(0..=ops.len());
                    ops.insert(at, noise);
                }
            }
            for _ in 0..rng.random_range(0..=2) {
                if ops.len() >= 2 {
                    let at = rng.random_range(0..ops.len() - 1);
                    ops.swap(at, at + 1);
                }
            }
            ops.truncate(Self::MAX_OPS);
            return Self {
                label: seed,
                optimistic_is_higher: rng.random_bool(0.6),
                leader,
                leads_next_slot,
                ops,
            };
        }
        for _ in 0..rng.random_range(1..=2) {
            keep(&mut rng, 1.0, Op::PrefixBatch);
        }
        keep(&mut rng, 0.4, Op::GapBatch);
        keep(&mut rng, 0.7, Op::Replay);
        keep(&mut rng, 0.4, Op::PruneRoot);
        keep(&mut rng, 0.9, Op::Marker);
        if rng.random_bool(0.3) {
            keep(&mut rng, 1.0, Op::DropSignal);
        } else {
            keep(&mut rng, 0.8, Op::HandleInterrupts);
        }
        keep(&mut rng, 0.6, Op::Replay);
        keep(&mut rng, 0.5, Op::HandleInterrupts);
        keep(&mut rng, 0.8, Op::RepairGap);
        keep(&mut rng, 0.6, Op::Completion);
        // A failover onto the slot's leader once its block is in: the block replays as this
        // node's own, with no footer check.
        keep(&mut rng, 0.25, Op::SetIdentity);
        keep(&mut rng, 0.9, Op::Recreate);
        keep(&mut rng, 0.8, Op::Replay);
        keep(&mut rng, 0.7, Op::Freeze);
        if rng.random_bool(0.25) {
            keep(&mut rng, 1.0, Op::DeployProgram);
            keep(&mut rng, 0.7, Op::Freeze);
            keep(&mut rng, 0.8, Op::InvokeProgram);
        }
        keep(&mut rng, 0.5, Op::Child);
        keep(&mut rng, 0.5, Op::Notarize);
        if rng.random_bool(0.4) {
            // A complete version is what block-id repair delivers; the switch below prefers it.
            keep(&mut rng, 0.5, Op::AlternateComplete);
            keep(&mut rng, 1.0, Op::Switch);
            keep(&mut rng, 0.9, Op::Recreate);
            keep(&mut rng, 0.5, Op::Replay);
            keep(&mut rng, 0.8, Op::Freeze);
            keep(&mut rng, 0.5, Op::Notarize);
        }
        // The restart purge's crash leg: TSS falls behind before the UpdateParent purge is queued
        // (the lag goes in below, once `keep` is done with `ops`), the slot roots with it still
        // queued, and the process usually crashes before TSS catches up (see `Op::RootLagging`).
        let crash_leg = rng.random_bool(0.15);
        if crash_leg {
            keep(&mut rng, 1.0, Op::RootLagging);
            keep(&mut rng, 0.7, Op::CrashRestart);
            keep(&mut rng, 1.0, Op::DrainTss);
        } else {
            keep(&mut rng, 0.8, Op::Root);
        }
        // A ledger-only root leaves the bank forks root behind, so the restart below makes
        // startup replay advance the root itself (R14).
        keep(&mut rng, 0.3, Op::LedgerRoot);
        if crash_leg {
            let lag_at = ops
                .iter()
                .position(|op| *op == Op::HandleInterrupts)
                .unwrap_or(ops.len());
            ops.insert(lag_at, Op::TssLag);
        }
        if rng.random_bool(0.3) {
            // A restart, sometimes one that loses the status writes the old process had queued.
            let restart = if rng.random_bool(0.3) {
                Op::CrashRestart
            } else {
                Op::Restart
            };
            let at = rng.random_range(0..=ops.len());
            ops.insert(at, restart);
        }
        for noise in [
            Op::DrainTss,
            Op::FlushAccounts,
            Op::HandleInterrupts,
            Op::QueuedPurge,
            Op::TssLag,
        ] {
            for _ in 0..rng.random_range(0..=3) {
                let at = rng.random_range(0..=ops.len());
                ops.insert(at, noise);
            }
        }
        for _ in 0..rng.random_range(0..=2) {
            if ops.len() >= 2 {
                let at = rng.random_range(0..ops.len() - 1);
                ops.swap(at, at + 1);
            }
        }
        ops.truncate(Self::MAX_OPS);
        Self {
            label: seed,
            optimistic_is_higher: rng.random_bool(0.6),
            leader,
            leads_next_slot: false,
            ops,
        }
    }

    /// Decodes a program from fuzzer bytes: bit 0 of byte 0 picks the optimistic sibling, bit 1
    /// leader mode, bit 2 (in leader mode) that this node leads slot 5 too; every later byte is
    /// one op (see `Op::REPLAY_TABLE` and `Op::LEADER_TABLE`). An empty input is an empty program.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut label = [0; 8];
        for (index, byte) in label.iter_mut().zip(bytes) {
            *index = *byte;
        }
        let leader = bytes.first().is_some_and(|byte| byte & 2 != 0);
        Self {
            label: u64::from_le_bytes(label),
            optimistic_is_higher: bytes.first().is_some_and(|byte| byte & 1 != 0),
            leader,
            leads_next_slot: leader && bytes.first().is_some_and(|byte| byte & 4 != 0),
            ops: bytes
                .iter()
                .skip(1)
                .take(Self::MAX_OPS)
                .map(|byte| Op::from_byte(*byte, leader))
                .collect(),
        }
    }

    /// Whether the program can run anything at all. The slot only ever gets a bank from one of
    /// these, so a program without one is a harness setup and teardown with no work in between.
    fn can_do_work(&self) -> bool {
        self.ops.iter().any(|op| {
            matches!(
                op,
                Op::PrefixBatch | Op::GapBatch | Op::Recreate | Op::LeaderStart
            )
        })
    }

    /// The fuzzer input this program decodes from, so seeded programs can be written out as a
    /// corpus. `from_bytes(&program.to_bytes()) == program` for the parts the decoder reads.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.ops.len() + 1);
        let mut header = 0u8;
        if self.optimistic_is_higher {
            header |= 1;
        }
        if self.leader {
            header |= 2;
        }
        if self.leads_next_slot {
            header |= 4;
        }
        bytes.push(header);
        bytes.extend(
            self.ops
                .iter()
                .take(Self::MAX_OPS)
                .map(|op| op.to_byte(self.leader)),
        );
        bytes
    }

    fn optimistic_parent(&self) -> Slot {
        if self.optimistic_is_higher { 2 } else { 1 }
    }

    fn rooted_parent(&self) -> Slot {
        if self.optimistic_is_higher { 1 } else { 2 }
    }
}

/// Something the oracle flagged. `known` names the known open case it matches, if any.
#[derive(Debug)]
pub struct Finding {
    pub cell: &'static str,
    pub detail: String,
    pub known: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerState {
    NotInserted,
    Accepted,
    Rejected,
}

/// Interpreter state: what the program has done to the slot so far, which decides which ops are
/// legal next and which findings are known.
struct ProgramRun<'a> {
    program: &'a Program,
    harness: Harness,
    step: u32,
    skipped: u32,
    step_timer: std::time::Instant,
    findings: Vec<Finding>,
    /// First shred index of the next component inserted into the slot's original location.
    next_shred_index: u32,
    prefix_batches: u32,
    withheld: Option<Shred>,
    marker: MarkerState,
    completion_inserted: bool,
    child_built: bool,
    switched: bool,
    pruned: bool,
    rooted: bool,
    restarted: bool,
    /// The restart lost queued transaction-status writes.
    crashed: bool,
    /// The slot was rooted in the ledger without advancing the bank forks root.
    ledger_rooted: bool,
    /// The deployed program was invoked from the child slot.
    invoked: bool,
    /// Block id of a complete alternate version stored for repair, if one was built.
    alternate_complete: Option<BlockId>,
    leader_started: bool,
    /// The parent the leader slot started on, for the loop's ParentReady handling.
    leader_optimistic: Option<Block>,
    parent_ready_sent: bool,
    /// The loop started slot 5 within the window (`Op::LeaderNextSlot`).
    next_slot_started: bool,
    /// Votor certified a parent past the window (`Op::WindowCertifiedPast`).
    window_certified_past: bool,
    /// Leader generations the loop aborted (R4): their rows stay, the slot cannot root.
    aborted_generations: Vec<BankId>,
    /// Generations at the slot that a root prune removed (the pruned-prefix bug left their rows).
    pruned_generations: Vec<BankId>,
    /// Generations that were notarised, and those a switch discarded (R3 x C8 is their meet).
    notarized_generations: Vec<BankId>,
    switched_generations: Vec<BankId>,
    /// The generation replay froze through a real block completion, if any.
    frozen_by_replay: Option<BankId>,
    /// This node took over the identity that leads the slot (`Op::SetIdentity`).
    identity_taken_over: bool,
    /// The slot rooted while TSS lagged (`Op::RootLagging`); its history checks run once TSS
    /// has caught up.
    root_history_pending: bool,
    /// A crash restart threw away queued status writes for the slot, and the slot is the root
    /// startup began from, so startup never replays it to write them again.
    crash_lost_root_history: bool,
    /// This node moved off the identity that leads the slot (`Op::LeaderSetIdentity`).
    identity_moved: bool,
    /// Steps at which the footer-hash oracle compared a bank replay froze, and how many of
    /// those were of a slot this node led, where replay itself does not compare.
    footer_checks: usize,
    own_leader_footer_checks: usize,
    /// Accounts the RPC account oracle read (`Harness::rpc_account_leaks`), so a guard can tell
    /// whether programs reach it at all.
    rpc_account_checks: usize,
    #[cfg(test)]
    applied: Vec<Op>,
}

impl ProgramRun<'_> {
    const SLOT: Slot = 4;
    /// Child of `SLOT`, built on whichever generation is frozen there when the program asks.
    const CHILD_SLOT: Slot = 5;

    fn run(mut self) -> ProgramReport {
        let slot = Self::SLOT;
        if self.program.leader {
            self.after_step("create");
        } else {
            // The slot always starts with its header on the optimistic parent and a bank for it.
            self.harness
                .insert_block_header(slot, self.program.optimistic_parent());
            self.harness.generate_new_bank_forks();
            self.after_step("create");
        }
        for op in self.program.ops.clone() {
            if self.apply(op) {
                #[cfg(test)]
                self.applied.push(op);
                self.after_step(&format!("{op:?}"));
            } else {
                self.skipped += 1;
            }
        }
        self.finish()
    }

    fn bank(&self) -> Option<Arc<Bank>> {
        self.harness.bank(Self::SLOT)
    }

    fn frozen_bank(&self) -> Option<Arc<Bank>> {
        self.bank().filter(|bank| bank.is_frozen())
    }

    /// Runs `op` if the state allows it. Returns false when it was skipped.
    fn apply(&mut self, op: Op) -> bool {
        // A ledger-only root models a snapshot older than the ledger's roots: the blockstore is
        // rooted above bank forks. That is a startup-only state, because steady-state rooting
        // writes the blockstore roots and the bank forks root together on the replay thread. Only
        // a restart reconciles it, so until then the replay loop and the block creation loop are
        // not running; the background services are, and they keep their ops.
        if self.ledger_rooted
            && !self.restarted
            && !matches!(
                op,
                Op::Restart | Op::DrainTss | Op::FlushAccounts | Op::QueuedPurge
            )
        {
            return false;
        }
        let slot = Self::SLOT;
        let optimistic = self.program.optimistic_parent();
        let rooted_parent = self.program.rooted_parent();
        // Once this node holds the identity that leads the slot, sigverify drops the slot's
        // shreds, from turbine and repair alike (`turbine/src/sigverify_shreds.rs:463-470`), so
        // nothing more of its block, original or alternate, reaches the blockstore.
        let slot_shreds_arrive = !self.identity_taken_over;
        // Shreds go into the slot's original location only before a marker ends the prefix and
        // while no switch has replaced it; the prefix needs its parent bank for the blockhash.
        let prefix_open = !self.program.leader
            && slot_shreds_arrive
            && self.marker == MarkerState::NotInserted
            && !self.switched
            && self.harness.bank(optimistic).is_some();
        let leader_mode = self.program.leader;
        let working_bank = self
            .harness
            .leader
            .as_ref()
            .and_then(|leader| leader.working_bank());
        match op {
            Op::PrefixBatch => {
                if !prefix_open || self.withheld.is_some() || self.prefix_batches >= 3 {
                    return false;
                }
                self.harness
                    .insert_transfer_batch(slot, optimistic, self.next_shred_index);
                self.next_shred_index += FEC_SET_SHREDS;
                self.prefix_batches += 1;
            }
            Op::GapBatch => {
                if !prefix_open || self.withheld.is_some() {
                    return false;
                }
                self.withheld = Some(self.harness.insert_incomplete_transfer_batch(
                    slot,
                    optimistic,
                    self.next_shred_index,
                ));
                self.next_shred_index += FEC_SET_SHREDS;
            }
            Op::Marker => {
                if leader_mode
                    || !slot_shreds_arrive
                    || self.marker != MarkerState::NotInserted
                    || self.switched
                    || self.frozen_bank().is_some()
                {
                    return false;
                }
                self.harness.insert_update_parent(
                    slot,
                    optimistic,
                    rooted_parent,
                    self.next_shred_index,
                );
                let accepted = self
                    .harness
                    .blockstore
                    .meta(slot)
                    .unwrap()
                    .unwrap()
                    .has_update_parent();
                // The blockstore rejects a marker whose new parent is a higher slot than the
                // shred header's parent (`validate_shred_parent`) and marks the slot dead.
                if accepted {
                    assert!(
                        self.program.optimistic_is_higher,
                        "marker accepted in the rejected layout ({})",
                        self.label()
                    );
                    self.marker = MarkerState::Accepted;
                } else {
                    assert!(
                        self.harness.blockstore.is_dead(slot),
                        "rejected marker must mark the slot dead ({})",
                        self.label()
                    );
                    assert!(
                        !self.program.optimistic_is_higher,
                        "marker rejected in the accepted layout ({})",
                        self.label()
                    );
                    self.marker = MarkerState::Rejected;
                }
                self.next_shred_index += FEC_SET_SHREDS;
            }
            Op::HandleInterrupts => self.harness.handle_update_parent_interrupts(),
            Op::DropSignal => {
                if self.harness.update_parent_receiver.is_empty() {
                    return false;
                }
                while self.harness.update_parent_receiver.try_recv().is_ok() {}
            }
            Op::Replay => {
                let Some(bank) = self.bank().filter(|bank| !bank.is_frozen()) else {
                    return false;
                };
                // The alternate version the switch brought in has no footer in this fixture, so
                // replaying it would only kill the slot; it is frozen directly instead.
                if self.switched && self.harness.progress.get(&slot).is_none() {
                    return false;
                }
                // Our own leader bank is never replayed from the blockstore; the loop handles it
                // once PoH reached the last tick.
                if !bank.should_replay_from_blockstore() {
                    if !bank.is_complete() {
                        return false;
                    }
                    drop(bank);
                    self.harness.complete_leader_bank(slot);
                    if let Some(bank) = self.frozen_bank() {
                        self.frozen_by_replay = Some(bank.bank_id());
                    }
                    return true;
                }
                let result = self.harness.replay(slot);
                // Every pass goes through the real post-replay handling, as every pass of the
                // replay loop does: it freezes a block the pass completed (checking the footer
                // unless this node led the slot), and handles the marker met mid-replay (R2), a
                // dead slot (a rejected marker) and an invalid block. Before 2026-11-08 only
                // the errors went through it, so no program ever froze a block by replaying it.
                match &result {
                    Ok(_)
                    | Err(BlockstoreProcessorError::BlockComponentProcessor(
                        BlockComponentProcessorError::AbandonedBank(_),
                    ))
                    | Err(BlockstoreProcessorError::FailedToLoadEntries(
                        BlockstoreError::DeadSlot,
                    ))
                    | Err(BlockstoreProcessorError::InvalidBlock(_)) => {}
                    Err(err) => panic!("unexpected replay error ({}): {err:?}", self.label()),
                }
                self.harness.process_replay_result(slot, result);
                if let Some(bank) = self.bank().filter(|bank| bank.is_frozen()) {
                    // A real completion froze the bank; the block id votor would attach with
                    // the certificate is assigned here.
                    if bank.block_id().is_none() {
                        bank.set_block_id(Some(BlockId::new_unique()));
                    }
                    self.frozen_by_replay = Some(bank.bank_id());
                }
                drop(bank);
            }
            Op::Recreate => {
                let before = self.bank().map(|bank| bank.bank_id());
                self.harness.generate_new_bank_forks();
                let after = self.bank();
                if self.marker == MarkerState::Rejected {
                    let after_id = after.as_ref().map(|bank| bank.bank_id());
                    assert!(
                        after_id == before,
                        "before {before:?}, after {after_id:?} ({})\na dead slot was recreated",
                        self.label()
                    );
                } else if before.is_none()
                    && let Some(bank) = &after
                    && self.marker == MarkerState::Accepted
                {
                    assert!(
                        bank.parent_slot() == rooted_parent,
                        "parent {}, marker parent {rooted_parent} ({})\na bank created after the \
                         marker does not build on the marker's parent",
                        bank.parent_slot(),
                        self.label()
                    );
                }
            }
            Op::RepairGap => {
                if !slot_shreds_arrive {
                    return false;
                }
                let Some(withheld) = self.withheld.take() else {
                    return false;
                };
                self.harness
                    .blockstore
                    .insert_shreds(vec![withheld], true)
                    .unwrap();
            }
            Op::Completion => {
                // The footer's hash comes from a shadow bank at the slot, so the completion can
                // only be built while no live bank occupies it.
                if leader_mode
                    || !slot_shreds_arrive
                    || self.marker != MarkerState::Accepted
                    || self.completion_inserted
                    || self.switched
                    || self.bank().is_some()
                {
                    return false;
                }
                self.harness.reset_entry_chain(slot, rooted_parent);
                let completion =
                    self.harness
                        .build_completion(slot, rooted_parent, 1, BlockLocation::Original);
                self.harness.insert_completion(
                    slot,
                    optimistic,
                    &completion,
                    self.next_shred_index,
                    BlockLocation::Original,
                );
                self.next_shred_index += FEC_SET_SHREDS * u32::try_from(completion.len()).unwrap();
                self.completion_inserted = true;
            }
            Op::Freeze => {
                let Some(bank) = self.bank().filter(|bank| !bank.is_frozen()) else {
                    return false;
                };
                // A bank whose block is dead, or that still has the marker ahead of it, never
                // freezes in a validator; a leader bank freezes through the loop's completion.
                // Nor does a bank whose block is incomplete: replay freezes a bank when it
                // finishes the block, so a frozen bank always means a complete one. Without this
                // a program could freeze a partial slot, notarize it, and then re-parent it with
                // a marker - a sequence no validator can reach, because a complete slot cannot
                // take a marker afterwards.
                if self.harness.blockstore.is_dead(slot)
                    || !self.harness.blockstore.is_full(slot)
                    || !bank.should_replay_from_blockstore()
                    || (self.marker == MarkerState::Accepted && bank.parent_slot() != rooted_parent)
                {
                    return false;
                }
                let recorded =
                    self.harness
                        .model
                        .generations
                        .get(&slot)
                        .is_some_and(|generations| {
                            generations
                                .iter()
                                .any(|generation| generation.bank_id == bank.bank_id())
                        });
                drop(bank);
                if !recorded {
                    self.harness.record_empty_generation(slot);
                }
                // A shortcut, kept on purpose next to the faithful route. A validator freezes a
                // complete block only by replaying it, which `Op::Replay` now does (with the
                // footer check for a slot someone else led, `replay_stage.rs:1523-1528`). This
                // freezes directly, skipping the footer and fabricating a block id, because
                // replay legitimately refuses many of the banks programs reach here (over 120
                // seeds on 2026-10-27: 30 `DeadSlot`, 15 `AbandonedBank` from a marker still
                // ahead), and routing this op through replay instead removed the program route
                // to R3 x C8 entirely. `known_bug_classifiers_cover_every_path_that_reaches_them`
                // fails if that coverage is lost again.
                self.harness.freeze_like_replay(slot);
            }
            Op::SetIdentity => {
                if leader_mode || self.identity_taken_over {
                    return false;
                }
                self.harness.set_identity();
                self.identity_taken_over = true;
            }
            Op::Child => {
                // When this node leads slot 5 the loop produces it, and sigverify drops shreds of
                // it from the network, so no other leader's child block arrives.
                if self.child_built
                    || self.program.leads_next_slot
                    || self.frozen_bank().is_none()
                    || self
                        .harness
                        .bank_forks
                        .read()
                        .unwrap()
                        .block_id(slot)
                        .is_none()
                {
                    return false;
                }
                self.harness.insert_block_header(Self::CHILD_SLOT, slot);
                self.harness
                    .insert_transfer_batch(Self::CHILD_SLOT, slot, FEC_SET_SHREDS);
                self.harness.generate_new_bank_forks();
                let result = self.harness.replay(Self::CHILD_SLOT);
                assert!(
                    result.as_ref().ok() == Some(&1),
                    "{result:?} ({})\nthe child slot did not execute its transfer",
                    self.label()
                );
                self.child_built = true;
            }
            Op::Notarize => {
                let Some(bank) = self.frozen_bank() else {
                    return false;
                };
                self.harness.notarize(slot);
                self.notarized_generations.push(bank.bank_id());
                self.check_confirmed_reads("Notarize");
            }
            Op::Switch => {
                let Some(bank) = self
                    .frozen_bank()
                    .filter(|_| !leader_mode && !self.switched && !self.rooted)
                else {
                    return false;
                };
                if self
                    .harness
                    .bank_forks
                    .read()
                    .unwrap()
                    .block_id(slot)
                    .is_none()
                {
                    return false;
                }
                // Without a stored complete version, the switch needs block-id repair to deliver
                // one now, which sigverify refuses for a slot this node leads.
                if !slot_shreds_arrive && self.alternate_complete.is_none() {
                    return false;
                }
                // The SwitchBank purge waits for TSS, so it cannot run behind a closed gate.
                self.harness.open_tss_gate();
                let parent = bank.parent_slot();
                // Repair delivers an alternate version with a parent, and the harness has to name
                // that parent's block id to build the header. Once the root has passed the parent
                // its bank is gone, and the real switch path abandons such a request anyway
                // (`replay_stage.rs:838-844`), so there is nothing to model.
                if self
                    .harness
                    .bank_forks
                    .read()
                    .unwrap()
                    .block_id(parent)
                    .is_none()
                {
                    return false;
                }
                let block_id = self.harness.block_id(slot);
                self.harness
                    .blockstore
                    .set_double_merkle_root(slot, BlockLocation::Original, block_id.to_hash())
                    .unwrap();
                let alternate = match self.alternate_complete.take() {
                    // A complete version is already stored; switching to it revives the slot
                    // with a block replay can finish and freeze.
                    Some(block_id) => block_id,
                    None => {
                        let block_id = BlockId::new_unique();
                        self.harness
                            .insert_alternate_version(slot, parent, block_id);
                        block_id
                    }
                };
                self.harness.request_switch(slot, alternate);
                let child_before = self.harness.bank(Self::CHILD_SLOT).is_some();
                self.harness.process_switch_bank_events();
                // `process_switch_bank_events` abandons a switch whose ancestor chain reaches
                // the root (`replay_stage.rs:838-844`) and defers one that is still waiting on
                // repair. Neither clears the slot, and both are states a validator reaches, so
                // the op models them: the alternate version stays stored for repair to serve and
                // the live generation keeps the slot. Only a switch that actually happened
                // updates the bookkeeping below.
                if self.harness.pending_switch.is_some() || self.bank().is_some() {
                    return true;
                }
                self.harness.switch_transfer_locations(
                    slot,
                    BlockLocation::Alternate {
                        block_id: alternate.to_hash(),
                    },
                    block_id,
                );
                self.switched_generations.push(bank.bank_id());
                self.switched = true;
                drop(bank);
                if child_before {
                    // The switch clears the generation's descendants with it: their banks,
                    // progress and history rows (the SwitchBank purge waits for TSS).
                    assert!(
                        self.harness.bank(Self::CHILD_SLOT).is_none(),
                        "switch must clear the descendant bank ({})",
                        self.label()
                    );
                    assert!(
                        self.harness.progress.get(&Self::CHILD_SLOT).is_none(),
                        "switch must clear the descendant progress ({})",
                        self.label()
                    );
                    for signature in self
                        .harness
                        .history_rows_of_discarded_generations(Self::CHILD_SLOT)
                    {
                        self.findings.push(Finding {
                            cell: "R3 x C4 descendant rows",
                            detail: format!(
                                "{signature} at slot {} survived the switch",
                                Self::CHILD_SLOT
                            ),
                            known: None,
                        });
                    }
                }
            }
            Op::PruneRoot => {
                if self.pruned || self.rooted {
                    return false;
                }
                let before: Vec<BankId> = [Self::SLOT, Self::CHILD_SLOT]
                    .into_iter()
                    .filter_map(|at| self.harness.bank(at).map(|bank| bank.bank_id()))
                    .collect();
                self.harness.set_root(rooted_parent);
                for bank_id in before {
                    let survives = [Self::SLOT, Self::CHILD_SLOT]
                        .into_iter()
                        .filter_map(|at| self.harness.bank(at))
                        .any(|bank| bank.bank_id() == bank_id);
                    if !survives {
                        self.pruned_generations.push(bank_id);
                    }
                }
                self.pruned = true;
            }
            Op::Root => {
                if self.rooted
                    || self.frozen_bank().is_none()
                    || self
                        .harness
                        .bank_forks
                        .read()
                        .unwrap()
                        .block_id(slot)
                        .is_none()
                {
                    return false;
                }
                self.harness.set_root(slot);
                self.rooted = true;
                self.harness.drain_tss();
                self.check_rooted_history();
                self.check_confirmed_reads("Root");
            }
            Op::TssLag => {
                if !self.harness.tss_gate_is_open() {
                    return false;
                }
                self.harness.close_tss_gate();
            }
            Op::DrainTss => {
                self.harness.drain_tss();
                self.check_pending_root_history("DrainTss");
                if leader_mode {
                    // Once TSS caught up, rows of a generation the sad handover replaced are gone
                    // (the leader purge names the transactions it recorded, R9 x C4).
                    for signature in self.harness.history_rows_of_discarded_generations(slot) {
                        self.findings.push(Finding {
                            cell: "R9 x C4 leader purge",
                            detail: format!("{signature} at slot {slot} survived the handover"),
                            known: self.known_for(signature),
                        });
                    }
                }
            }
            Op::QueuedPurge => {
                if self.harness.run_queued_purges() == 0 {
                    return false;
                }
            }
            Op::FlushAccounts => {
                let root_bank = self.harness.bank_forks.read().unwrap().root_bank();
                root_bank.force_flush_accounts_cache();
            }
            Op::DeployProgram => {
                // Needs a live, unfrozen bank: a deploy is part of the block at this slot.
                if self.harness.model.deployed_program.is_some()
                    || self.harness.bank(slot).is_none_or(|bank| bank.is_frozen())
                {
                    return false;
                }
                self.harness.deploy_program_at(slot);
            }
            Op::InvokeProgram => {
                // A program is visible from the slot after its deployment, so the invocation
                // goes in the child slot, before that slot's bank is created.
                let Some((program_id, _)) = self.harness.model.deployed_program else {
                    return false;
                };
                if self.child_built
                    || self.invoked
                    || self.program.leads_next_slot
                    || self.frozen_bank().is_none()
                    || self
                        .harness
                        .bank_forks
                        .read()
                        .unwrap()
                        .block_id(slot)
                        .is_none()
                {
                    return false;
                }
                self.harness.insert_block_header(Self::CHILD_SLOT, slot);
                let component =
                    self.harness
                        .invoke_component_at(Self::CHILD_SLOT, slot, program_id);
                self.harness.insert_component(
                    Self::CHILD_SLOT,
                    slot,
                    &component,
                    FEC_SET_SHREDS,
                    false,
                );
                self.harness.generate_new_bank_forks();
                // The invocation itself may fail (the program is new and the harness does not
                // model its accounts); what matters is that replay loaded it into the cache.
                let _ = self.harness.replay(Self::CHILD_SLOT);
                self.child_built = true;
                self.invoked = true;
            }
            Op::LedgerRoot => {
                // Nothing live runs between this and the restart that reconciles it; the gate
                // at the top of `apply` enforces that.
                // Only a frozen block with an id can be rooted, and the ledger root must stay
                // above the bank forks root for the restart to have anything to advance over.
                let root = self.harness.bank_forks.read().unwrap().root();
                if self.ledger_rooted
                    || self.rooted
                    || self.restarted
                    || slot <= root
                    || self.frozen_bank().is_none()
                    || self
                        .harness
                        .bank_forks
                        .read()
                        .unwrap()
                        .block_id(slot)
                        .is_none()
                {
                    return false;
                }
                self.harness.ledger_root(slot);
                self.ledger_rooted = true;
            }
            Op::AlternateComplete => {
                // The shadow bank `build_completion` runs writes at the slot, so the slot must
                // be free of a live bank, and only one alternate version is modelled.
                if leader_mode
                    || !slot_shreds_arrive
                    || self.alternate_complete.is_some()
                    || self.harness.bank(slot).is_some()
                    || self.harness.bank(rooted_parent).is_none()
                {
                    return false;
                }
                let block_id = self
                    .harness
                    .insert_complete_alternate_version(slot, rooted_parent);
                self.alternate_complete = Some(block_id);
            }
            Op::Restart => {
                // The fixture's slots 1 and 2 are Tower-shaped tick blocks that only exist as
                // in-memory banks; startup replay from slot 0 would reject them. A restart is
                // modelled once the root is at or above them.
                if self.restarted || !(self.pruned || self.rooted) {
                    return false;
                }
                self.harness.restart(/*drained:*/ true);
                self.restarted = true;
                self.frozen_by_replay = None;
                self.check_startup_purge();
                self.check_pending_root_history("Restart");
            }
            Op::CrashRestart => {
                // Same preconditions as `Restart`; what differs is that the old process leaves
                // its queued status rows unwritten.
                //
                // Not in leader mode. A real crash takes the block creation loop with it, but
                // the harness keeps its leader state across the restart, so the leader purge
                // would later name transactions whose status writes this just threw away. TSS
                // treats a purge that finds no metadata as fatal
                // (`transaction_status_service.rs:459-468`), which is a true report of a state a
                // validator cannot be in: in one process TSS is FIFO, so the writes always land
                // before the purge that names them.
                if leader_mode || self.restarted || !(self.pruned || self.rooted) {
                    return false;
                }
                self.harness.restart(/*drained:*/ false);
                self.restarted = true;
                self.crashed = true;
                self.frozen_by_replay = None;
                // Startup begins at the root and never replays it, so whatever status writes the
                // crash threw away for a rooted slot stay unwritten (and a purge among them stays
                // undone). Upstream accepts that crash leg (#14432's review, #16227).
                let root = self.harness.bank_forks.read().unwrap().root();
                self.crash_lost_root_history =
                    self.harness.take_crash_lost_slots().contains(&Self::SLOT)
                        && Self::SLOT <= root;
                self.check_startup_purge();
                if self.root_history_pending {
                    self.harness.drain_tss();
                }
                self.check_pending_root_history("CrashRestart");
            }
            Op::LeaderStart => {
                if !leader_mode || self.leader_started || working_bank.is_some() {
                    return false;
                }
                // A parent replay does not have frozen makes the loop wait out the slot's timer
                // and give up; the harness skips the op instead of waiting, with the same
                // outcome. Every other refusal (a bank already at the slot, a window the cluster
                // has certified past) is the loop's own, below.
                if self
                    .harness
                    .bank(optimistic)
                    .is_none_or(|bank| !bank.is_frozen())
                {
                    return false;
                }
                let parent_block = Block {
                    slot: optimistic,
                    block_id: self.harness.block_id(optimistic),
                };
                let started = self.harness.drive_leader(move |leader| {
                    leader.start(slot, parent_block.slot, Some(parent_block.block_id), true)
                });
                match started {
                    Ok(()) => {
                        self.leader_started = true;
                        self.leader_optimistic = Some(parent_block);
                    }
                    Err(err) if verbose() => {
                        eprintln!("{}: the loop refused to start: {err}", self.label())
                    }
                    Err(_) => {}
                }
            }
            Op::LeaderRecord => {
                if !leader_mode || working_bank.is_none() {
                    return false;
                }
                let label = self.label();
                let recorded = self
                    .harness
                    .leader_record()
                    .unwrap_or_else(|err| panic!("leader record failed ({label}): {err}"));
                if !recorded && verbose() {
                    eprintln!("{label}: the working bank was retired, nothing recorded");
                }
            }
            Op::LeaderParentReady | Op::LeaderHandover => {
                // ParentReady for the window is for its first slot, and votor's highest
                // ParentReady only rises, so none comes once it certified past the window.
                if !leader_mode
                    || self.parent_ready_sent
                    || self.window_certified_past
                    || working_bank.is_none_or(|bank| bank.slot() != slot)
                {
                    return false;
                }
                // An honest leader builds on the newest block, so a certified parent that differs
                // is an older one; the blockstore rejects a marker to a higher slot.
                if op == Op::LeaderHandover && rooted_parent > optimistic {
                    return false;
                }
                let parent_slot = if op == Op::LeaderHandover {
                    rooted_parent
                } else {
                    optimistic
                };
                if self
                    .harness
                    .bank_forks
                    .read()
                    .unwrap()
                    .block_id(parent_slot)
                    .is_none()
                {
                    return false;
                }
                let parent = Block {
                    slot: parent_slot,
                    block_id: self.harness.block_id(parent_slot),
                };
                self.harness
                    .leader
                    .as_ref()
                    .expect("leader mode")
                    .parent_ready(slot, parent);
                self.parent_ready_sent = true;
            }
            Op::LeaderComplete => {
                let Some(bank) = working_bank else {
                    return false;
                };
                if !leader_mode {
                    return false;
                }
                let working_slot = bank.slot();
                // The window's first slot was built on an optimistic parent, so the loop will not
                // complete it before votor's ParentReady arrives, unless the cluster certified
                // past the window first. A slot within the window waits for nothing.
                let optimistic_parent = (working_slot == slot)
                    .then_some(self.leader_optimistic)
                    .flatten();
                if optimistic_parent.is_some()
                    && !self.parent_ready_sent
                    && !self.window_certified_past
                {
                    return false;
                }
                let before = bank.bank_id();
                drop(bank);
                let completed = self
                    .harness
                    .drive_leader(move |leader| leader.complete(working_slot, optimistic_parent));
                // An error means the loop aborted the bank (R4): production failed, or the cluster
                // moved past the window and `abort_working_bank` cleared it instead of completing.
                if let Err(err) = completed {
                    if verbose() {
                        eprintln!("{}: leader completion failed: {err}", self.label());
                    }
                    self.aborted_generations.push(before);
                }
                // The loop reschedules the handed-over transactions for banking stage; the
                // harness does not re-execute them, so they stay with the discarded generation.
                self.harness
                    .leader
                    .as_ref()
                    .expect("leader mode")
                    .take_rescheduled();
                self.parent_ready_sent = false;
            }
            Op::LeaderAbort => {
                let Some(bank) = working_bank else {
                    return false;
                };
                if !leader_mode {
                    return false;
                }
                // The loop aborts the slot it is producing, which within the window may be slot 5.
                // Naming slot 4 there cleared slot 4's completed bank through the controller, a
                // state the loop cannot produce, and left slot 5's bank behind.
                let (working_slot, before) = (bank.slot(), bank.bank_id());
                drop(bank);
                let label = self.label();
                self.harness
                    .drive_leader(move |leader| leader.abort(working_slot))
                    .unwrap_or_else(|err| panic!("leader abort failed ({label}): {err}"));
                self.aborted_generations.push(before);
            }
            Op::LeaderNextSlot => {
                if !leader_mode
                    || !self.program.leads_next_slot
                    || self.next_slot_started
                    || working_bank.is_some()
                {
                    return false;
                }
                // Within the window the loop starts the next slot once it completed this one,
                // which froze it; if this one never completed, the loop gave up on the window.
                if self.frozen_bank().is_none() {
                    return false;
                }
                let child = Self::CHILD_SLOT;
                let started = self
                    .harness
                    .drive_leader(move |leader| leader.start(child, slot, None, false));
                match started {
                    Ok(()) => self.next_slot_started = true,
                    Err(err) if verbose() => {
                        eprintln!("{}: the loop refused slot {child}: {err}", self.label())
                    }
                    Err(_) => {}
                }
            }
            Op::WindowCertifiedPast => {
                if !leader_mode || self.window_certified_past {
                    return false;
                }
                let block_id = self.harness.next_block_id();
                self.harness
                    .leader
                    .as_ref()
                    .expect("leader mode")
                    .certify_past_window(slot, block_id);
                self.window_certified_past = true;
            }
            Op::Broadcast => {
                if !leader_mode {
                    return false;
                }
                self.harness.broadcast();
            }
            Op::Unassigned => return false,
            Op::RootLagging => {
                if leader_mode
                    || self.rooted
                    || self.harness.tss_gate_is_open()
                    || self.frozen_bank().is_none()
                    || self
                        .harness
                        .bank_forks
                        .read()
                        .unwrap()
                        .block_id(slot)
                        .is_none()
                {
                    return false;
                }
                self.harness.set_root(slot);
                self.rooted = true;
                self.root_history_pending = true;
            }
            Op::LeaderStartOtherParentVersion => {
                if !leader_mode
                    || self.leader_started
                    || working_bank.is_some()
                    || self
                        .harness
                        .bank(optimistic)
                        .is_none_or(|bank| !bank.is_frozen())
                {
                    return false;
                }
                // A version of the parent replay has not switched to: no bank anywhere has it.
                let other_version = self.harness.next_block_id();
                let started = self.harness.drive_leader(move |leader| {
                    leader.start(slot, optimistic, Some(other_version), true)
                });
                if started.is_ok() {
                    self.findings.push(Finding {
                        cell: "L1 leader start",
                        detail: format!(
                            "the loop started slot {slot} on slot {optimistic} although the \
                             window names block id {other_version}, a version replay never froze"
                        ),
                        known: None,
                    });
                    self.leader_started = true;
                    self.leader_optimistic = Some(Block {
                        slot: optimistic,
                        block_id: self.harness.block_id(optimistic),
                    });
                }
            }
            Op::LeaderSetIdentity => {
                // The loop reads a new identity at a window start, so not while it holds a
                // working bank.
                if !leader_mode || self.identity_moved || working_bank.is_some() {
                    return false;
                }
                self.harness.move_leader_identity();
                self.identity_moved = true;
            }
        }
        true
    }

    /// Startup replay purges the pre-UpdateParent history of a slot with a marker before it
    /// exposes the slot (R14 x C4), and does so while waiting for TSS.
    fn check_startup_purge(&mut self) {
        let slot = Self::SLOT;
        let Some(meta) = self.harness.blockstore.meta(slot).unwrap() else {
            return;
        };
        if !meta.has_update_parent() {
            return;
        }
        // Startup replay purges a slot's pre-marker history when it queues the slot as a child
        // (`process_next_slots`). The slot it starts from is never queued, so a slot that is
        // already the root keeps whatever rows the live purge left behind. That is a real gap,
        // reported separately; the oracle only covers the slots startup actually walks.
        if slot <= self.harness.bank_forks.read().unwrap().root() {
            return;
        }
        let surviving: Vec<Signature> = self
            .harness
            .model
            .transfers
            .get(&slot)
            .into_iter()
            .flatten()
            .filter(|transfer| {
                transfer
                    .shred_index
                    .is_some_and(|index| index < meta.replay_fec_set_index)
            })
            .map(|transfer| transfer.signature)
            .filter(|signature| {
                self.harness
                    .blockstore
                    .read_transaction_status((*signature, slot))
                    .unwrap()
                    .is_some()
            })
            .collect();
        for signature in surviving {
            self.findings.push(Finding {
                cell: "R14 x C4 startup purge",
                detail: format!("pre-marker {signature} at slot {slot} survived the restart"),
                known: None,
            });
        }
    }

    fn label(&self) -> String {
        format!("program {:#x}", self.program.label)
    }

    fn after_step(&mut self, what: &str) {
        self.step += 1;
        let elapsed = self.step_timer.elapsed();
        if verbose() && elapsed > Duration::from_millis(300) {
            eprintln!(
                "{} step {} ({what}) took {elapsed:?}",
                self.label(),
                self.step
            );
        }
        self.step_timer = std::time::Instant::now();
        assert!(
            !self.harness.tss_exit.load(Ordering::Relaxed),
            "I4: TSS exited after step {what} ({})",
            self.label()
        );
        self.check_in_memory_stores(what);
    }

    /// The known open case a finding about `signature` matches, if any: rows of a generation the
    /// root prune removed (R5 x C4; fixed by #16167 except where a crash loses the purge, see
    /// `crash_lost`), or of a leader bank the loop aborted (R4 x C4).
    fn known_for(&self, signature: Signature) -> Option<&'static str> {
        let generations = self.harness.model.generations.values().flatten();
        let mut pruned = false;
        let mut aborted = false;
        for generation in generations {
            if !generation.signatures.contains(&signature) {
                continue;
            }
            pruned |= self.pruned_generations.contains(&generation.bank_id);
            aborted |= self.aborted_generations.contains(&generation.bank_id);
        }
        if pruned {
            Some("R5 x C4: rows of a root-pruned generation stay")
        } else if aborted {
            Some("R4 x C4: aborted leader bank rows stay, the slot cannot root")
        } else {
            None
        }
    }

    /// I1 at confirmed commitment through RPC. Under Alpenglow the confirmed bank is the root,
    /// so the only known offender is the pruned prefix's surviving rows (R5 x C4) once the
    /// recreated slot roots.
    fn check_confirmed_reads(&mut self, what: &str) {
        for violation in self.harness.rpc_confirmed_soundness_violations() {
            self.findings.push(Finding {
                cell: "RPC confirmed",
                detail: format!(
                    "{} served {} at slot {} after {what}",
                    violation.query, violation.signature, violation.slot
                ),
                known: self
                    .crash_lost(violation.slot)
                    .or_else(|| self.known_for(violation.signature)),
            });
        }
    }

    /// The computed bank hash must match the footer, including on slots we led, where replay
    /// does not check it for us.
    fn check_footer_hash(&mut self, what: &str) {
        // Only a bank replay froze promises its block's footer hash. `Op::Freeze` models a bank
        // that froze without its block being replayed, so it has nothing to match against, and
        // `frozen_by_replay` is the harness's record of which it was. For a slot someone else
        // led, replay already marked the slot dead on a mismatch, so this is a second opinion;
        // after `Op::SetIdentity` the slot is this node's own and this is the only check there
        // is. `oracles_reach_the_footer_hash_of_own_leader_replays` pins that programs get here.
        let slot = Self::SLOT;
        let Some(bank) = self.harness.bank(slot).filter(|bank| bank.is_frozen()) else {
            return;
        };
        if self.frozen_by_replay != Some(bank.bank_id()) {
            return;
        }
        self.footer_checks += 1;
        if *bank.leader_id() == self.harness.my_pubkey {
            self.own_leader_footer_checks += 1;
        }
        drop(bank);
        if let Some((computed, expected)) = self.harness.footer_hash_violations(slot) {
            self.findings.push(Finding {
                cell: "footer bank hash",
                detail: format!(
                    "slot {slot} froze as {computed} after {what}, but no version built for it \
                     promised that hash ({expected:?})"
                ),
                known: None,
            });
        }
    }

    /// I6 on the stores that must never show a discarded generation, after every step.
    fn check_in_memory_stores(&mut self, what: &str) {
        self.check_footer_hash(what);
        for slot in [Self::SLOT, Self::CHILD_SLOT] {
            for signature in self.harness.status_cache_leaks(slot) {
                self.findings.push(Finding {
                    cell: "C2 status cache",
                    detail: format!(
                        "{signature} visible to the replacement at slot {slot} after {what}"
                    ),
                    known: None,
                });
            }
            for program_id in self.harness.program_cache_leaks(slot) {
                self.findings.push(Finding {
                    cell: "C3 program cache",
                    detail: format!(
                        "{program_id} deployed at slot {slot} by a discarded generation is still \
                         in the program cache after {what}"
                    ),
                    known: None,
                });
            }
            for destination in self.harness.accounts_cache_leaks(slot) {
                self.findings.push(Finding {
                    cell: "C1 accounts cache",
                    detail: format!(
                        "{destination} loadable by the replacement at slot {slot} after {what}"
                    ),
                    known: None,
                });
            }
        }
        let (account_leaks, account_checks) = self.harness.rpc_account_leaks();
        self.rpc_account_checks += account_checks;
        for (commitment, destination, slot) in account_leaks {
            self.findings.push(Finding {
                cell: "C1 accounts via RPC",
                detail: format!(
                    "{destination}, written only by a discarded generation at slot {slot}, has a \
                     balance at {commitment} commitment after {what}"
                ),
                known: None,
            });
        }
        if let Some(stale) = self.harness.commitment_cache_violation() {
            // The case is that a switch replaces the bank in a slot and nothing re-tags the
            // commitment cache, so whatever put the slot there - a notarization, or startup
            // seeding the cache from the working bank - the stale entry is the same bug. Keyed on
            // the switch alone, not on how the slot came to be named.
            let known = (!self.switched_generations.is_empty())
                .then_some("R3 x C8: the commitment cache names a switched-out slot");
            self.findings.push(Finding {
                cell: "C8 commitment cache",
                detail: format!("processed slot {stale} names an unfrozen bank after {what}"),
                known,
            });
        }
    }

    /// The known case for a history finding at `at` after a crash: the crash threw away queued
    /// status writes for the startup root, and startup never replays its root to write them.
    fn crash_lost(&self, at: Slot) -> Option<&'static str> {
        (self.crash_lost_root_history && at == Self::SLOT).then_some(CRASH_LOST_ROOT_HISTORY)
    }

    /// Runs the rooted slot's history checks that `Op::RootLagging` deferred, once TSS caught up.
    fn check_pending_root_history(&mut self, what: &str) {
        if std::mem::take(&mut self.root_history_pending) {
            self.check_rooted_history();
            self.check_confirmed_reads(what);
        }
    }

    /// I1 and I3 on the history rows and through RPC, once the slot rooted and TSS drained.
    fn check_rooted_history(&mut self) {
        let slot = Self::SLOT;
        for (signature, served_slot) in self.harness.finalized_soundness_violations() {
            self.findings.push(Finding {
                cell: "C4 history rows",
                detail: format!("{signature} served as finalized at slot {served_slot}"),
                known: self
                    .crash_lost(served_slot)
                    .or_else(|| self.known_for(signature)),
            });
        }
        for (signature, at) in self.harness.finalized_completeness_violations() {
            self.findings.push(Finding {
                cell: "C4 history rows (missing)",
                detail: format!("rooted {signature} has no row at slot {at}"),
                known: self.crash_lost(at),
            });
        }
        let rooted_bank_id = self.harness.bank(slot).map(|bank| bank.bank_id());
        if rooted_bank_id.is_some() && rooted_bank_id == self.frozen_by_replay {
            let watermark = self
                .harness
                .max_complete_transaction_status_slot
                .load(Ordering::SeqCst);
            assert!(
                watermark >= slot,
                "TSS never saw the freeze of the rooted slot ({}): watermark {watermark}",
                self.label()
            );
        }
        for violation in self.harness.rpc_finalized_soundness_violations() {
            self.findings.push(Finding {
                cell: "RPC finalized",
                detail: format!(
                    "{} served {} at slot {}",
                    violation.query, violation.signature, violation.slot
                ),
                known: self
                    .crash_lost(violation.slot)
                    .or_else(|| self.known_for(violation.signature)),
            });
        }
        for violation in self.harness.rpc_finalized_completeness_violations() {
            self.findings.push(Finding {
                cell: "RPC finalized (missing)",
                detail: format!(
                    "{} did not serve rooted {} at slot {}",
                    violation.query, violation.signature, violation.slot
                ),
                known: self.crash_lost(violation.slot),
            });
        }
    }

    fn finish(self) -> ProgramReport {
        if verbose() {
            eprintln!(
                "{}: {} ops, {} skipped, {} findings, {} footer checks ({} own-leader), {} RPC \
                 account checks",
                self.label(),
                self.program.ops.len(),
                self.skipped,
                self.findings.len(),
                self.footer_checks,
                self.own_leader_footer_checks,
                self.rpc_account_checks
            );
        }
        self.harness.shutdown();
        ProgramReport {
            findings: self.findings,
            #[cfg(test)]
            own_leader_footer_checks: self.own_leader_footer_checks,
            #[cfg(test)]
            rpc_account_checks: self.rpc_account_checks,
            #[cfg(test)]
            skipped: self.skipped,
            #[cfg(test)]
            applied: self.applied,
        }
    }
}

pub fn run_program(program: &Program) -> Vec<Finding> {
    run_program_report(program).findings
}

/// What one program run produced: its findings, and for tests, how often the footer-hash oracle
/// compared a bank replay froze at a slot this node led, so they can pin that programs keep
/// reaching the one place it is the only check.
#[derive(Default)]
struct ProgramReport {
    findings: Vec<Finding>,
    #[cfg(test)]
    own_leader_footer_checks: usize,
    #[cfg(test)]
    rpc_account_checks: usize,
    #[cfg(test)]
    skipped: u32,
    /// The ops that ran, in order (the rest were skipped).
    #[cfg(test)]
    applied: Vec<Op>,
}

fn run_program_report(program: &Program) -> ProgramReport {
    // Building the harness costs a ledger directory, a TSS thread and the fixture's banks. A
    // program with nothing to run would pay all of it to do nothing, so it returns first.
    if !program.can_do_work() {
        return ProgramReport::default();
    }
    let tree = tr(0) / tr(1) / tr(2);
    let harness = match (program.leader, program.leads_next_slot) {
        (false, _) => Harness::new(tree),
        (true, false) => Harness::new_leader(tree),
        (true, true) => Harness::new_window_leader(tree),
    };
    ProgramRun {
        program,
        harness,
        step: 0,
        skipped: 0,
        step_timer: std::time::Instant::now(),
        findings: Vec::new(),
        next_shred_index: FEC_SET_SHREDS,
        prefix_batches: 0,
        withheld: None,
        marker: MarkerState::NotInserted,
        completion_inserted: false,
        child_built: false,
        switched: false,
        pruned: false,
        rooted: false,
        restarted: false,
        crashed: false,
        ledger_rooted: false,
        invoked: false,
        alternate_complete: None,
        leader_started: false,
        leader_optimistic: None,
        parent_ready_sent: false,
        next_slot_started: false,
        window_certified_past: false,
        aborted_generations: Vec::new(),
        pruned_generations: Vec::new(),
        notarized_generations: Vec::new(),
        switched_generations: Vec::new(),
        frozen_by_replay: None,
        identity_taken_over: false,
        root_history_pending: false,
        crash_lost_root_history: false,
        identity_moved: false,
        footer_checks: 0,
        own_leader_footer_checks: 0,
        rpc_account_checks: 0,
        #[cfg(test)]
        applied: Vec::new(),
    }
    .run()
}

fn verbose() -> bool {
    std::env::var_os("FLH_HARNESS_VERBOSE").is_some()
}

#[cfg(test)]
mod tests {
    use {super::*, solana_entry::block_component::VersionedBlockFooter};

    /// Runs the pruned-prefix sequence: a slot executes a prefix on an optimistic parent, a
    /// competing root prunes that generation, the delayed UpdateParent marker reparents the slot,
    /// and replay recreates and roots it. Before #16167 the prefix transaction's history row
    /// survived all of it. Returns the finalized-soundness violations after the replacement roots.
    fn run_root_pruned_update_parent() -> Vec<(Signature, Slot)> {
        // Slots 1 and 2 are siblings under the root. Slot 4 is the first slot of a leader window
        // (UpdateParent is only valid there). Its prefix builds optimistically on 2, the higher
        // losing fork; the cluster roots 1; the marker re-parents 4 onto 1.
        // The marker shred keeps header parent 2, which passes the blockstore's root check.
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        harness.insert_block_header(slot, optimistic_parent);
        let signature = harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.bank(slot).unwrap().parent_slot(), optimistic_parent);
        assert_eq!(
            harness.replay(slot).unwrap(),
            1,
            "prefix must execute one transaction"
        );
        harness.drain_tss();
        assert!(
            harness
                .blockstore
                .read_transaction_status((signature, slot))
                .unwrap()
                .is_some(),
            "TSS must have written the prefix transaction's row"
        );

        // R5: the competing root prunes the in-progress generation at `slot`.
        harness.set_root(rooted_parent);
        assert!(harness.bank(slot).is_none());
        assert!(harness.progress.get(&slot).is_none());

        // The delayed marker arrives; the restart path returns early (no bank, no progress).
        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 2 * FEC_SET_SHREDS);
        let meta = harness.blockstore.meta(slot).unwrap().unwrap();
        assert!(meta.has_update_parent(), "marker not recorded: {meta:?}");
        assert_eq!(meta.replay_fec_set_index, 2 * FEC_SET_SHREDS);
        assert_eq!(
            meta.parent_slot,
            Some(rooted_parent),
            "slot meta not reparented: {meta:?}"
        );
        assert_eq!(
            meta.parent_block_id,
            harness.block_id(rooted_parent).to_hash()
        );
        assert_eq!(
            harness.update_parent_receiver.len(),
            1,
            "blockstore must emit one UpdateParent signal"
        );
        assert!(
            harness
                .blockstore
                .get_slots_since(&[rooted_parent])
                .unwrap()
                .get(&rooted_parent)
                .is_some_and(|children| children.as_slice().contains(&slot)),
            "slot must now chain from the new parent"
        );
        harness.handle_update_parent_interrupts();
        harness.drain_tss();

        // Replay recreates the slot from the reparented metadata, at the marker offset.
        harness.generate_new_bank_forks();
        let replacement = harness
            .bank(slot)
            .expect("slot must be recreated on the rooted side");
        assert_eq!(replacement.parent_slot(), rooted_parent);
        assert_eq!(
            harness
                .progress
                .get(&slot)
                .unwrap()
                .replay_progress
                .read()
                .unwrap()
                .num_shreds,
            u64::from(2 * FEC_SET_SHREDS)
        );
        harness.record_empty_generation(slot);

        harness.freeze_for_test(slot);
        harness.set_root(slot);
        harness.drain_tss();
        assert!(harness.blockstore.is_root(slot));

        let violations = harness.finalized_soundness_violations();
        harness.shutdown();
        violations
    }

    /// Startup replay purges a slot's pre-marker history only when it queues the slot as a child
    /// (`process_next_slots`), so it never cleans the slot it starts from. Before #16167 that
    /// mattered: rooting the slot and restarting there left the discarded prefix rows finalized
    /// forever, so a restart was never a mitigation for the pruned-prefix bug. #16167 purges when
    /// the replacement bank is created, long before the slot can root.
    #[test]
    fn pruned_prefix_rows_are_gone_before_a_restart_at_the_slot() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        harness.insert_block_header(slot, optimistic_parent);
        let prefix = harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();

        // R5: the competing root prunes the in-progress generation, so the delayed marker's restart
        // path returns early and no history purge is ever issued (the pruned-prefix bug, fixed by
        // #16167).
        harness.set_root(rooted_parent);
        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 2 * FEC_SET_SHREDS);
        harness.handle_update_parent_interrupts();
        harness.drain_tss();
        // The shadow bank in `build_completion` writes at the slot, so build it while the root
        // prune has left the slot without a bank.
        harness.reset_entry_chain(slot, rooted_parent);
        let completion = harness.build_completion(slot, rooted_parent, 1, BlockLocation::Original);
        harness.insert_completion(
            slot,
            optimistic_parent,
            &completion,
            3 * FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        harness.generate_new_bank_forks();
        let result = harness.replay(slot);
        harness.process_replay_result(slot, result);
        assert!(harness.bank(slot).unwrap().is_frozen());
        harness.drain_tss();
        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix, slot))
                .unwrap()
                .is_none(),
            "the pruned-prefix bug (#16167) reproduces again: the prefix row survived recreation"
        );

        // The slot roots, so a restart loads a snapshot at the slot itself.
        harness.set_root(slot);
        harness.restart(/*drained:*/ true);
        assert_eq!(harness.bank_forks.read().unwrap().root(), slot);
        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix, slot))
                .unwrap()
                .is_none(),
            "the prefix row came back after the restart"
        );
        // And no client can see it either: the real RPC processor serves nothing stale.
        harness.drain_tss();
        let rpc_violations = harness.rpc_finalized_soundness_violations();
        assert!(
            rpc_violations.is_empty(),
            "stale finalized reads after the restart: {rpc_violations:?}"
        );
        harness.shutdown();
    }

    #[test]
    fn pruned_prefix_root_pruned_update_parent_leaves_no_prefix_history() {
        let violations = run_root_pruned_update_parent();
        // Fixed by #16167: replay purges the slot's history before inserting the replacement
        // bank, so the root-pruned generation's rows never reach the recreated slot.
        assert!(
            violations.is_empty(),
            "the pruned-prefix bug (#16167) reproduces again: {violations:?}"
        );
    }

    /// R2: the UpdateParent marker is met mid-replay (the signal was not drained first). The real
    /// abandoned-bank handling must purge the prefix's history and clear the in-memory stores
    /// before replay recreates the slot at the marker offset.
    #[test]
    fn r2_abandoned_bank_purges_prefix_and_clears_caches() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        harness.insert_block_header(slot, optimistic_parent);
        let signature = harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 2 * FEC_SET_SHREDS);

        let result = harness.replay(slot);
        assert!(
            matches!(
                result,
                Err(BlockstoreProcessorError::BlockComponentProcessor(
                    BlockComponentProcessorError::AbandonedBank(_)
                ))
            ),
            "replay must hit the marker mid-replay: {result:?}"
        );
        harness.process_replay_result(slot, result);
        assert!(
            harness.bank(slot).is_none(),
            "abandoned bank must be cleared"
        );
        harness.drain_tss();
        assert!(
            harness
                .blockstore
                .read_transaction_status((signature, slot))
                .unwrap()
                .is_none(),
            "prefix history row must be purged"
        );

        harness.generate_new_bank_forks();
        let replacement = harness
            .bank(slot)
            .expect("slot recreated at the marker offset");
        assert_eq!(replacement.parent_slot(), rooted_parent);
        assert!(harness.status_cache_leaks(slot).is_empty());
        assert!(harness.accounts_cache_leaks(slot).is_empty());
        harness.record_empty_generation(slot);

        harness.freeze_for_test(slot);
        harness.set_root(slot);
        harness.drain_tss();
        assert!(harness.finalized_soundness_violations().is_empty());
        harness.shutdown();
    }

    /// R3: a notarized frozen generation is switched out for a certified alternate version. The
    /// switch purges the old version's history synchronously and clears the in-memory stores, but
    /// nothing re-tags the commitment cache, so the processed slot names the unfrozen replacement
    /// (fix in review: #16366).
    #[test]
    fn r3_switch_bank_purges_history_but_leaves_commitment_cache_stale() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let parent = 1;

        harness.insert_block_header(slot, parent);
        let signature_a = harness.insert_transfer_batch(slot, parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();
        harness.freeze_for_test(slot);
        let block_id_a = harness.block_id(slot);
        harness
            .blockstore
            .set_double_merkle_root(slot, BlockLocation::Original, block_id_a.to_hash())
            .unwrap();
        harness.notarize(slot);
        assert_eq!(harness.commitment_cache_violation(), None);

        let block_id_b = BlockId::new_unique();
        let _signature_b = harness.insert_alternate_version(slot, parent, block_id_b);
        harness.request_switch(slot, block_id_b);
        harness.process_switch_bank_events();
        assert!(harness.pending_switch.is_none(), "switch must complete");
        assert!(
            harness.bank(slot).is_none(),
            "old generation must be cleared"
        );
        assert!(
            harness
                .blockstore
                .read_transaction_status((signature_a, slot))
                .unwrap()
                .is_none(),
            "switched-out version's history must be purged before the shreds are replaced"
        );

        harness.generate_new_bank_forks();
        let replacement = harness
            .bank(slot)
            .expect("slot recreated from the alternate");
        assert_eq!(replacement.parent_slot(), parent);
        assert!(!replacement.is_frozen());
        assert!(harness.status_cache_leaks(slot).is_empty());
        assert!(harness.accounts_cache_leaks(slot).is_empty());
        // The bug is open on this tree: the processed commitment still names the slot and the
        // bank there is unfrozen. When the cache gains a block-id tag this flips to `None`.
        assert_eq!(
            harness.commitment_cache_violation(),
            Some(slot),
            "the switched-out commitment slot no longer reproduces (#16366 landed?); update this \
             test"
        );
        harness.record_empty_generation(slot);

        harness.freeze_for_test(slot);
        harness.set_root(slot);
        harness.drain_tss();
        assert!(harness.finalized_soundness_violations().is_empty());
        harness.shutdown();
    }

    /// R3 with a descendant: the switch clears the child slot's bank, progress and history rows
    /// along with the switched-out generation's.
    #[test]
    fn r3_switch_clears_descendant_generation() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let child = 5;
        let parent = 1;

        harness.insert_block_header(slot, parent);
        let signature_a = harness.insert_transfer_batch(slot, parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.freeze_for_test(slot);
        harness.insert_block_header(child, slot);
        let child_signature = harness.insert_transfer_batch(child, slot, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(child).unwrap(), 1);
        harness.drain_tss();
        assert_eq!(
            harness.rooted_history_slot(child_signature),
            None,
            "unrooted rows are not finalized history"
        );
        assert!(
            harness
                .blockstore
                .read_transaction_status((child_signature, child))
                .unwrap()
                .is_some()
        );

        let block_id_a = harness.block_id(slot);
        harness
            .blockstore
            .set_double_merkle_root(slot, BlockLocation::Original, block_id_a.to_hash())
            .unwrap();
        let block_id_b = BlockId::new_unique();
        harness.insert_alternate_version(slot, parent, block_id_b);
        harness.request_switch(slot, block_id_b);
        harness.process_switch_bank_events();
        assert!(harness.pending_switch.is_none(), "switch must complete");
        assert!(harness.bank(slot).is_none());
        assert!(harness.bank(child).is_none(), "descendant bank must go");
        assert!(harness.progress.get(&child).is_none());
        for (signature, at) in [(signature_a, slot), (child_signature, child)] {
            assert!(
                harness
                    .blockstore
                    .read_transaction_status((signature, at))
                    .unwrap()
                    .is_none(),
                "rows of slot {at} must be purged with the switch"
            );
        }
        harness.generate_new_bank_forks();
        assert!(harness.bank(slot).is_some());
        assert!(
            harness.bank(child).is_none(),
            "the child is not recreated under an unfrozen replacement"
        );
        assert!(harness.status_cache_leaks(slot).is_empty());
        assert!(harness.accounts_cache_leaks(slot).is_empty());
        harness.record_empty_generation(slot);
        harness.freeze_for_test(slot);
        harness.set_root(slot);
        harness.drain_tss();
        assert!(harness.finalized_soundness_violations().is_empty());
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        harness.shutdown();
    }

    /// Under Alpenglow the confirmed bank follows the votor root, so a notarised but switched-out
    /// generation is never visible at confirmed commitment, and after the switched-in version
    /// roots the confirmed reads match the finalized ones.
    #[test]
    fn rpc_confirmed_reads_follow_the_root() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let parent = 1;
        let confirmed = CommitmentConfig::confirmed();

        harness.insert_block_header(slot, parent);
        let signature_a = harness.insert_transfer_batch(slot, parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.freeze_for_test(slot);
        let block_id_a = harness.block_id(slot);
        harness
            .blockstore
            .set_double_merkle_root(slot, BlockLocation::Original, block_id_a.to_hash())
            .unwrap();
        harness.notarize(slot);
        harness.drain_tss();
        assert_eq!(
            harness
                .optimistically_confirmed_bank
                .read()
                .unwrap()
                .bank
                .slot(),
            0,
            "notarisation does not move the confirmed bank"
        );
        assert_eq!(harness.rpc_signature_status(signature_a, confirmed), None);
        assert!(harness.rpc_confirmed_soundness_violations().is_empty());

        let block_id_b = BlockId::new_unique();
        harness.insert_alternate_version(slot, parent, block_id_b);
        harness.request_switch(slot, block_id_b);
        harness.process_switch_bank_events();
        assert!(harness.pending_switch.is_none(), "switch must complete");
        harness.generate_new_bank_forks();
        harness.record_empty_generation(slot);
        harness.freeze_for_test(slot);
        harness.set_root(slot);
        harness.drain_tss();
        assert_eq!(
            harness
                .optimistically_confirmed_bank
                .read()
                .unwrap()
                .bank
                .bank_id(),
            harness.bank(slot).unwrap().bank_id(),
            "the root is the confirmed bank"
        );
        assert_eq!(
            harness
                .confirmed_tracker
                .lock()
                .unwrap()
                .highest_confirmed_slot,
            slot,
            "the real tracker processed the notification, rather than the harness deciding for it"
        );
        assert_eq!(harness.rpc_signature_status(signature_a, confirmed), None);
        assert!(harness.rpc_confirmed_soundness_violations().is_empty());
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        harness.shutdown();
    }

    /// A restart rebuilds the history watermark from the ledger root (`validator.rs:2807`).
    /// Every frozen bank lifts the watermark with `fetch_max`, across forks, and nothing lowers
    /// it, so the previous process can leave it above the ledger root. Carrying that over would
    /// let finalized reads admit a slot a restarted validator withholds until startup replay
    /// reaches it, which is the gate #15418 added.
    #[test]
    fn restart_rebuilds_the_history_watermark_from_the_ledger_root() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let parent = 1;
        harness.set_root(parent);
        // An incomplete block: enough for a bank that freezes and lifts the watermark, but not
        // something startup will replay, so the restart cannot earn the watermark back.
        harness.insert_block_header(slot, parent);
        harness.insert_transfer_batch(slot, parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.freeze_for_test(slot);
        // Replay sends this when a bank freezes, and TSS lifts the watermark with `fetch_max`
        // (`transaction_status_service.rs:415-418`). `freeze_for_test` freezes the bank without
        // going through replay, so send it here.
        harness
            .tss_sender
            .send_transaction_status_freeze_message(&harness.bank(slot).unwrap());
        harness.drain_tss();
        assert_eq!(
            harness
                .max_complete_transaction_status_slot
                .load(Ordering::SeqCst),
            slot,
            "freezing the slot lifted the watermark to it"
        );
        assert!(
            harness.blockstore.max_root() < slot,
            "the ledger root is still below it"
        );

        harness.restart(/*drained:*/ true);

        assert_eq!(
            harness
                .max_complete_transaction_status_slot
                .load(Ordering::SeqCst),
            harness.blockstore.max_root(),
            "the restart rebuilt the watermark from the ledger root"
        );
        harness.shutdown();
    }

    /// A restart seeds the confirmed bank from the root it loaded, like the validator does at
    /// `validator.rs:1166-1167`. Carrying the previous process's bank over would leave the
    /// confirmed bank below the root, which is a state no validator starts in, and it made
    /// confirmed reads of the root's own transactions look like soundness violations.
    #[test]
    fn restart_seeds_the_confirmed_bank_from_the_loaded_root() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let parent = 1;
        harness.set_root(parent);
        harness.insert_block_header(slot, parent);
        // The shadow bank in `build_completion` writes at the slot, so build the whole block
        // before anything gives the slot a live bank.
        let completion = harness.build_completion(slot, parent, 1, BlockLocation::Original);
        harness.insert_completion(
            slot,
            parent,
            &completion,
            FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        harness.generate_new_bank_forks();
        let result = harness.replay(slot);
        harness.process_replay_result(slot, result);
        assert!(
            harness.bank(slot).unwrap().is_frozen(),
            "the block completes"
        );
        harness
            .blockstore
            .set_double_merkle_root(
                slot,
                BlockLocation::Original,
                harness.block_id(slot).to_hash(),
            )
            .unwrap();
        harness.drain_tss();

        // Root the slot in the ledger only, so the restart is what advances the forks root to it.
        harness.ledger_root(slot);
        harness.restart(/*drained:*/ true);

        let root = harness.bank_forks.read().unwrap().root();
        assert_eq!(root, slot, "startup advances the root to the ledger root");
        assert_eq!(
            harness
                .optimistically_confirmed_bank
                .read()
                .unwrap()
                .bank
                .slot(),
            root,
            "the restart seeds the confirmed bank from the loaded root"
        );
        assert!(harness.rpc_confirmed_soundness_violations().is_empty());
        harness.shutdown();
    }

    /// Sigverify drops every shred of a slot this node leads, repair and block-id repair
    /// included (`turbine/src/sigverify_shreds.rs:463-470`), so once a program takes over the
    /// slot's identity no op may put more of its block in the blockstore. Without that the
    /// harness would build blocks no validator can receive and report what they do.
    #[test]
    fn taking_over_the_slot_identity_stops_its_shreds_arriving() {
        let shred_ops = [
            Op::PrefixBatch,
            Op::GapBatch,
            Op::Marker,
            Op::AlternateComplete,
        ];
        let program = |take_over: bool| Program {
            label: 0,
            optimistic_is_higher: true,
            leader: false,
            leads_next_slot: false,
            ops: take_over
                .then_some(Op::SetIdentity)
                .into_iter()
                .chain(shred_ops.iter().copied())
                .collect(),
        };
        assert_eq!(
            run_program_report(&program(false)).skipped,
            1,
            "control: without the takeover the shreds arrive (only the alternate is refused, as \
             the slot still has a live bank)"
        );
        assert_eq!(
            run_program_report(&program(true)).skipped,
            u32::try_from(shred_ops.len()).unwrap(),
            "after the takeover every op that delivers the slot's shreds must be refused"
        );
    }

    /// The footer-hash oracle is the only check on a block of a slot this node led (see
    /// `own_leader_replay_freezes_a_footer_its_block_does_not_compute`), and from its
    /// introduction until 2026-11-08 no program reached it, because programs never froze a
    /// block by replaying it. These seeds take over the slot's identity and then replay its
    /// block to completion (re-derived 2026-11-12, 135 seeds in 4000 do). Re-derive them
    /// whenever the op encoding or the generator changes:
    /// a verbose sweep (`FLH_HARNESS_VERBOSE`) prints "N footer checks (M own-leader)" per
    /// program.
    #[test]
    fn oracles_reach_the_footer_hash_of_own_leader_replays() {
        for seed in [15, 30, 36] {
            let report = run_program_report(&Program::random(seed));
            assert!(
                report.own_leader_footer_checks > 0,
                "seed {seed} no longer replays an own-leader block to completion, so the \
                 footer-hash oracle is back to checking nothing where it is the only check"
            );
            let unknown: Vec<String> = report
                .findings
                .iter()
                .filter(|finding| finding.known.is_none())
                .map(|finding| format!("[{}] {}", finding.cell, finding.detail))
                .collect();
            assert!(unknown.is_empty(), "seed {seed}: {}", unknown.join("; "));
        }
    }

    /// Programs must keep reaching the loop's window paths the fixed tests cover: a second slot
    /// produced within the window and completed, and a slot given up because the cluster
    /// certified past the window. Also the paths rev 13 added: a start on a parent version replay
    /// never froze, an identity move between slots, and an abort of slot 5. Re-derive the seeds
    /// whenever the op encoding or the generator changes (as of 2026-11-12, in 4000 seeds: 113,
    /// 91 and 26 reach the new ones).
    #[test]
    fn programs_reach_the_loops_window_paths() {
        let ran_then = |applied: &[Op], first: Op, then: Op| {
            applied
                .iter()
                .position(|op| *op == first)
                .is_some_and(|at| applied[at..].contains(&then))
        };
        // A seed, the path it must reach, and how to tell from the ops that ran.
        type PathCheck = (u64, &'static str, fn(&[Op]) -> bool);
        let new_paths: [PathCheck; 3] = [
            (22, "start on another parent version", |applied| {
                applied.contains(&Op::LeaderStartOtherParentVersion)
            }),
            (22, "identity move between slots", |applied| {
                applied.contains(&Op::LeaderSetIdentity)
            }),
            (279, "abort of slot 5", |applied| {
                applied
                    .iter()
                    .position(|op| *op == Op::LeaderNextSlot)
                    .is_some_and(|at| applied[at..].contains(&Op::LeaderAbort))
            }),
        ];
        for (seed, path, reached) in new_paths {
            let report = run_program_report(&Program::random(seed));
            assert!(
                reached(&report.applied),
                "seed {seed} no longer reaches the {path}"
            );
            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| finding.known.is_some()),
                "seed {seed}: {:?}",
                report.findings
            );
        }
        for seed in [33, 55] {
            let report = run_program_report(&Program::random(seed));
            assert!(
                ran_then(&report.applied, Op::LeaderNextSlot, Op::LeaderComplete),
                "seed {seed} no longer produces a second slot within the window"
            );
            assert!(
                ran_then(&report.applied, Op::WindowCertifiedPast, Op::LeaderComplete),
                "seed {seed} no longer has the loop give up a window the cluster moved past"
            );
            let unknown: Vec<String> = report
                .findings
                .iter()
                .filter(|finding| finding.known.is_none())
                .map(|finding| format!("[{}] {}", finding.cell, finding.detail))
                .collect();
            assert!(unknown.is_empty(), "seed {seed}: {}", unknown.join("; "));
        }
    }

    /// A classifier for an open bug must cover every path that reaches it, not just the one it
    /// was written for. This program reaches the commitment-cache bug through a restart rather
    /// than a notarization: the restart seeds the cache from the working bank
    /// (`validator.rs:1158-1163`), a switch then replaces that bank, and nothing re-tags the
    /// cache. A classifier keyed on "notarized and then switched" misses it, the finding comes
    /// back unclassified, and the target crashes on a bug we already know about, once per
    /// variant. A fuzzing run was once flooded with crashes that way.
    ///
    /// The crash leg of the restart purge is the same kind of case: it is only reachable when
    /// TSS lags behind a root (`Op::RootLagging`) and the process then crashes, so 11 seeds in
    /// 4000 reach it. These seeds must come back classified as the crash leg, with nothing left
    /// unclassified; 400 also serves the stale prefix rows, 594 only misses rows.
    #[test]
    fn known_bug_classifiers_cover_every_path_that_reaches_them() {
        for seed in [400, 594] {
            let findings = run_program(&Program::random(seed));
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.known == Some(CRASH_LOST_ROOT_HISTORY)),
                "seed {seed} no longer reaches the crash leg, so its classifier is unguarded"
            );
            let unknown: Vec<String> = findings
                .iter()
                .filter(|finding| finding.known.is_none())
                .map(|finding| format!("[{}] {}", finding.cell, finding.detail))
                .collect();
            assert!(unknown.is_empty(), "seed {seed}: {}", unknown.join("; "));
        }
        // Re-derive these whenever the op alphabet or the generator changes. A seed names a
        // program only through the generator, so adding ops reshuffles what every seed
        // produces. The pair (424, 477) was correct when written and had drifted to producing
        // **zero** findings by 2026-10-27, which the old assertion could not detect because
        // "nothing unclassified" is also true of "nothing at all". The assertion below is what
        // catches that. 706, 4215 reach the bug through the restart (rare: 1 seed in 4000,
        // as of 2026-11-12); 20 reaches it through a notarization. Narrowing the classifier to
        // "a notarized generation was switched out" must fail on the restart seeds.
        for seed in [706, 4215, 20] {
            let program = Program::random(seed);
            let findings = run_program(&program);
            let unknown: Vec<String> = findings
                .iter()
                .filter(|finding| finding.known.is_none())
                .map(|finding| format!("[{}] {}", finding.cell, finding.detail))
                .collect();
            assert!(
                unknown.is_empty(),
                "seed {seed} reaches a known open bug by a path its classifier misses: {}",
                unknown.join("; ")
            );
            // Asserting only that nothing is unclassified passes just as happily when the seed
            // stops reaching the bug at all, which is how an `Op::Freeze` change silently removed
            // the program route to the commitment-cache case on 2026-10-27. Pin the coverage
            // itself: these seeds exist because they reach the commitment-cache cell.
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.cell == "C8 commitment cache"),
                "seed {seed} no longer reaches the commitment-cache bug at all, so this test \
                 would pass vacuously; it is pinned here precisely to catch that"
            );
        }
    }

    /// The UpdateParent restart queues its history purge with
    /// `wait_until_finished: false`. A process that crashes with that purge still queued never
    /// performs it. (A graceful exit used to lose it too, because `TransactionStatusService`
    /// stopped on the exit flag without draining; #16227 drains on join, which closes that leg.)
    /// Startup only purges the history of slots it walks as children (`process_next_slots`,
    /// `blockstore_processor.rs:1877`), never the slot it starts from, so once the slot is the
    /// root the abandoned prefix rows are permanent and served as finalized.
    #[test]
    fn crash_with_a_queued_purge_strands_the_prefix_at_the_startup_root() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        // The prefix executes on the optimistic parent and its rows reach the blockstore.
        harness.insert_block_header(slot, optimistic_parent);
        let prefix = harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();
        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix, slot))
                .unwrap()
                .is_some(),
            "the prefix row must be on disk before the purge is queued"
        );

        // The marker arrives and replay queues the purge without waiting for it. TSS is behind,
        // so the purge is still in the queue when the process goes away.
        harness.set_root(rooted_parent);
        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 2 * FEC_SET_SHREDS);
        harness.close_tss_gate();
        harness.handle_update_parent_interrupts();

        // The slot is completed and rooted, so the next startup begins from it. The gate stays
        // shut the whole way: the purge must still be unwritten when the process goes away.
        harness.reset_entry_chain(slot, rooted_parent);
        let completion = harness.build_completion(slot, rooted_parent, 1, BlockLocation::Original);
        harness.insert_completion(
            slot,
            optimistic_parent,
            &completion,
            3 * FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        harness.generate_new_bank_forks();
        let result = harness.replay(slot);
        harness.process_replay_result(slot, result);
        assert!(harness.bank(slot).unwrap().is_frozen());
        harness.set_root(slot);

        // The process exits with the purge unwritten, and startup never revisits its own root.
        harness.restart(/*drained:*/ false);
        assert_eq!(harness.bank_forks.read().unwrap().root(), slot);
        let survived = harness
            .blockstore
            .read_transaction_status((prefix, slot))
            .unwrap()
            .is_some();
        harness.drain_tss();
        let violations = harness.rpc_finalized_soundness_violations();
        eprintln!(
            "prefix row survived the crash restart: {survived}; finalized violations: {}",
            violations.len()
        );
        assert!(
            survived,
            "the queued purge was performed after all; re-read the exit path"
        );
        assert!(
            violations
                .iter()
                .any(|violation| violation.signature == prefix && violation.slot == slot),
            "the stranded prefix must be served as finalized: {violations:?}"
        );
        harness.shutdown();
    }

    /// Writes the seeded programs out as fuzzer inputs, so the fleet starts from sequences that
    /// reach the discard paths instead of rediscovering them from uniform bytes. Not a test of
    /// the code under test; it only runs when `FLH_CORPUS_DIR` points somewhere.
    #[test]
    fn write_seed_corpus() {
        let Some(dir) = std::env::var_os("FLH_CORPUS_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let seeds: u64 = std::env::var("FLH_CORPUS_SEEDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(512);
        let mut written = 0;
        let mut skipped = 0;
        for seed in 0..seeds {
            let program = Program::random(seed);
            let bytes = program.to_bytes();
            // Only inputs the decoder reads back as the same program are useful seeds.
            let decoded = Program::from_bytes(&bytes);
            if decoded.ops != program.ops
                || decoded.leader != program.leader
                || decoded.optimistic_is_higher != program.optimistic_is_higher
            {
                skipped += 1;
                continue;
            }
            if !program.can_do_work() {
                skipped += 1;
                continue;
            }
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&bytes, &mut hasher);
            let name = format!("seed-{:016x}", std::hash::Hasher::finish(&hasher));
            std::fs::write(dir.join(name), &bytes).unwrap();
            written += 1;
        }
        eprintln!(
            "wrote {written} corpus inputs to {} ({skipped} skipped)",
            dir.display()
        );
        assert!(
            written > 0,
            "the generator produced no usable corpus inputs"
        );
    }

    /// Replays a fuzzer artifact in the debug harness: `FLH_HARNESS_INPUT_HEX` is the input's
    /// bytes in hex, `FLH_HARNESS_INPUT_RUNS` how many times to run it (default 10, since
    /// fleet crashes that fail minimisation are usually timing dependent).
    #[test]
    fn fuzz_input_replays_clean() {
        let Some(hex) = std::env::var_os("FLH_HARNESS_INPUT_HEX") else {
            return;
        };
        if std::env::var_os("FLH_HARNESS_LOG").is_some() {
            agave_logger::setup_with_default("warn");
        }
        let bytes = bytes_from_hex(&hex.to_string_lossy());
        let runs: u32 = std::env::var("FLH_HARNESS_INPUT_RUNS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10);
        let program = Program::from_bytes(&bytes);
        eprintln!("{program:#?}");
        for run in 0..runs {
            let started = std::time::Instant::now();
            let findings = run_program(&program);
            let unknown: Vec<String> = findings
                .iter()
                .filter(|finding| finding.known.is_none())
                .map(|finding| format!("[{}] {}", finding.cell, finding.detail))
                .collect();
            eprintln!(
                "run {run}: {:?}, {} findings ({} known)",
                started.elapsed(),
                findings.len(),
                findings.len() - unknown.len()
            );
            assert!(unknown.is_empty(), "run {run}: {}", unknown.join("; "));
        }
    }

    fn bytes_from_hex(hex: &str) -> Vec<u8> {
        let hex = hex.replace(' ', "");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    /// Fuzzer inputs that crashed an earlier version of this harness, all through harness bugs:
    /// `LeaderAbort` named slot 4 while the loop was producing slot 5, so it cleared slot 4's
    /// completed bank (the harness then read stale history, cache leaks, and a commitment cache
    /// naming the recreated, unfrozen slot 4), and broadcast read a leader slot's block id back
    /// from the blockstore after a root had pruned its fork, so slot 5's header had no parent
    /// block id. The inputs were captured under corpus format 3 and re-encoded for format 4 (each
    /// op byte reduced modulo format 3's 34 leader ops, which `Op::LEADER_TABLE` keeps in order).
    #[test]
    fn leader_side_harness_bug_inputs_run_clean() {
        for (case, hex) in [
            (
                "abort cleared slot 4, accounts cache",
                "060f12191a131b1d201111111111111e1e00031f1a1d12050f060f05120e1111",
            ),
            (
                "broadcast had no block id for slot 4",
                "06191a1a1b111d200d0500010a111a211212031d1f0303051f060b0e0311",
            ),
            (
                "abort cleared slot 4, history",
                "06191a121a1b12191d201a191f031e1f0d0f0f130e12",
            ),
            (
                "abort cleared slot 4, commitment cache",
                "070303190f1a1f121c131d12201f110311140b1e1b1e0e0006",
            ),
        ] {
            let program = Program::from_bytes(&bytes_from_hex(hex));
            assert!(
                program.leader && program.leads_next_slot,
                "input {case:?} decodes differently"
            );
            let unknown: Vec<String> = run_program(&program)
                .iter()
                .filter(|finding| finding.known.is_none())
                .map(|finding| format!("[{}] {}", finding.cell, finding.detail))
                .collect();
            assert!(unknown.is_empty(), "input {case:?}: {}", unknown.join("; "));
        }
    }

    /// A window naming a version of the parent that replay never froze: `maybe_start_leader`
    /// finds the block id differs (`ParentBlockIdMismatch`), the loop waits for a switch that
    /// never comes, and the start gives up (`ReplayIsBehind`) with nothing created at the slot.
    #[test]
    fn a_start_on_a_parent_version_replay_never_froze_is_refused() {
        let mut harness = Harness::new_leader(tr(0) / tr(1) / tr(2));
        let (slot, parent) = (4, 2);
        let other_version = harness.next_block_id();
        let started = harness
            .drive_leader(move |leader| leader.start(slot, parent, Some(other_version), true));
        assert!(
            started.is_err(),
            "the loop must not start on a parent version replay never froze"
        );
        assert!(
            harness.bank(slot).is_none(),
            "a refused start created a bank"
        );
        harness.shutdown();
    }

    /// After `set-identity` moves this node off the slot's leader, the loop refuses to start
    /// the slot (`LeaderIdentityMismatch`), having refreshed its identity the way it does at a
    /// window start (#16637).
    #[test]
    fn after_moving_off_the_leader_identity_the_loop_refuses_the_slot() {
        let mut harness = Harness::new_leader(tr(0) / tr(1) / tr(2));
        let (slot, parent) = (4, 2);
        let parent_block_id = harness.block_id(parent);
        harness.move_leader_identity();
        let started = harness
            .drive_leader(move |leader| leader.start(slot, parent, Some(parent_block_id), true));
        let err = started.expect_err("the loop must refuse a slot this node no longer leads");
        assert!(err.contains("not the scheduled leader"), "{err}");
        assert!(
            harness.bank(slot).is_none(),
            "a refused start created a bank"
        );
        harness.shutdown();
    }

    /// The RPC account oracle reads something when a discarded generation exists, and finds
    /// nothing on this tree: a root on the other sibling prunes the slot's generation, and
    /// neither processed nor confirmed reads see the account its transfer wrote.
    #[test]
    fn rpc_reads_do_not_see_accounts_of_an_abandoned_generation() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let (optimistic_parent, rooted_parent) = (2, 1);
        harness.insert_block_header(slot, optimistic_parent);
        harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();
        harness.freeze_for_test(slot);
        harness.set_root(rooted_parent);
        let (leaks, checked) = harness.rpc_account_leaks();
        assert!(
            checked > 0,
            "the pruned generation's account was never read"
        );
        assert!(leaks.is_empty(), "{leaks:?}");
        harness.shutdown();
    }

    /// Programs reach the RPC account oracle (about half of them, as of 2026-11-12).
    #[test]
    fn programs_reach_the_rpc_account_oracle() {
        let report = run_program_report(&Program::random(1));
        assert!(
            report.rpc_account_checks > 0,
            "seed 1 no longer gives the RPC account oracle anything to read"
        );
    }

    fn cached_generations_at(harness: &Harness, slot: Slot) -> Vec<BankId> {
        harness
            .cached_generations()
            .into_iter()
            .filter_map(|(bank_id, cached_slot)| (cached_slot == slot).then_some(bank_id))
            .collect()
    }

    /// `completion` with its footer promising `bank_hash`, a hash its block does not compute to.
    /// The harness's record of the promise is updated with it, as the oracle reads that record.
    fn with_footer_hash(
        harness: &mut Harness,
        slot: Slot,
        mut completion: Vec<BlockComponent>,
        location: BlockLocation,
        bank_hash: Hash,
    ) -> Vec<BlockComponent> {
        let index = completion
            .iter()
            .position(|component| component.as_marker().is_some_and(|m| m.is_footer()))
            .expect("a completion carries a footer");
        let VersionedBlockMarker::V1(marker) = completion[index].as_marker().unwrap();
        let VersionedBlockFooter::V1(footer) = marker.as_block_footer().unwrap();
        completion[index] = BlockComponent::new_block_marker(
            VersionedBlockMarker::from_block_footer(BlockFooterV1 {
                bank_hash,
                ..footer.clone()
            }),
        );
        harness
            .model
            .footer_bank_hash
            .insert((slot, location), bank_hash);
        completion
    }

    /// Replay checks a completed block against its footer only when someone else led the slot
    /// (`replay_stage.rs:1523-1528`). After this node takes over the identity that led it (an
    /// operator's failover), a full block of the slot is its own: replay still creates the bank,
    /// because the block is full (`replay_stage.rs:2046-2052`), and freezes it whatever the
    /// footer says. The same block whose footer kills the slot under the old identity is
    /// accepted in silence under the new one, and the footer-hash oracle is what reports it.
    /// Flip the second half when replay checks own-leader footers.
    #[test]
    fn own_leader_replay_freezes_a_footer_its_block_does_not_compute() {
        let replay_block_with_a_wrong_footer = |take_over: bool| {
            let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
            let slot = 4;
            let parent = 1;
            harness.insert_block_header(slot, parent);
            let completion = harness.build_completion(slot, parent, 1, BlockLocation::Original);
            let promised = Hash::new_unique();
            let completion = with_footer_hash(
                &mut harness,
                slot,
                completion,
                BlockLocation::Original,
                promised,
            );
            harness.insert_completion(
                slot,
                parent,
                &completion,
                FEC_SET_SHREDS,
                BlockLocation::Original,
            );
            assert!(harness.blockstore.is_full(slot));
            if take_over {
                harness.set_identity();
            }
            harness.generate_new_bank_forks();
            let result = harness.replay(slot);
            assert_eq!(result.as_ref().ok(), Some(&1), "{result:?}");
            harness.process_replay_result(slot, result);
            (harness, promised)
        };

        let (harness, _) = replay_block_with_a_wrong_footer(false);
        assert!(
            harness.blockstore.is_dead(4),
            "someone else led the slot, so replay checks the footer and kills the slot"
        );
        harness.shutdown();

        let (harness, promised) = replay_block_with_a_wrong_footer(true);
        let bank = harness.bank(4).expect("own-leader replay keeps the bank");
        assert!(
            bank.is_frozen() && !harness.blockstore.is_dead(4),
            "replay now rejects an own-leader footer; flip this half of the test"
        );
        assert_eq!(
            harness.footer_hash_violations(4),
            Some((bank.hash(), vec![promised])),
            "the oracle must report what replay accepted"
        );
        drop(bank);
        harness.shutdown();
    }

    /// A node that leads two consecutive slots produces the second within its window: the loop
    /// starts it on its own first slot once that completed (`produce_intra_window_slot` passes no
    /// block id), banking stage records into it, and it completes without waiting for votor,
    /// since only the window's first slot was built on an optimistic parent.
    #[test]
    fn the_loop_produces_the_next_slot_within_its_window() {
        let mut harness = Harness::new_window_leader(tr(0) / tr(1) / tr(2));
        let (slot, next_slot, optimistic_parent) = (4, 5, 2);
        let parent_block = Block {
            slot: optimistic_parent,
            block_id: harness.block_id(optimistic_parent),
        };
        harness
            .drive_leader(move |leader| {
                leader.start(slot, optimistic_parent, Some(parent_block.block_id), true)
            })
            .unwrap();
        harness.leader_record().unwrap();
        harness
            .leader
            .as_ref()
            .unwrap()
            .parent_ready(slot, parent_block);
        harness
            .drive_leader(move |leader| leader.complete(slot, Some(parent_block)))
            .unwrap();
        assert!(harness.bank(slot).unwrap().is_frozen());

        harness
            .drive_leader(move |leader| leader.start(next_slot, slot, None, false))
            .unwrap();
        let next = harness
            .bank(next_slot)
            .expect("the loop inserted the next slot");
        assert_eq!(next.parent_slot(), slot);
        assert!(!next.should_replay_from_blockstore());
        drop(next);
        assert!(
            harness.leader_record().unwrap(),
            "banking stage records into it"
        );
        harness
            .drive_leader(move |leader| leader.complete(next_slot, None))
            .unwrap();
        assert!(
            harness.bank(next_slot).unwrap().is_frozen(),
            "a slot within the window completes without a ParentReady"
        );
        harness.drain_tss();
        let recorded = harness.model.generations[&next_slot][0].signatures[0];
        assert!(
            harness
                .blockstore
                .read_transaction_status((recorded, next_slot))
                .unwrap()
                .is_some()
        );

        let refused =
            harness.drive_leader(move |leader| leader.start(next_slot, slot, None, false));
        assert!(
            refused.is_err_and(|err| err.contains("Already contain bank")),
            "maybe_start_leader refuses a slot that already has a bank"
        );
        harness.shutdown();
    }

    /// Votor certifying a parent past this node's window means the cluster has moved on. The
    /// loop aborts the slot it is producing the next time it looks (`abort_working_bank`, an R4
    /// sender: the bank is cleared through the controller) and refuses to start the next one
    /// (`ClusterCertifiedBlocksAfterWindow`).
    #[test]
    fn the_loop_gives_up_a_window_the_cluster_certified_past() {
        let mut harness = Harness::new_window_leader(tr(0) / tr(1) / tr(2));
        let (slot, next_slot, optimistic_parent) = (4, 5, 2);
        let parent_block = Block {
            slot: optimistic_parent,
            block_id: harness.block_id(optimistic_parent),
        };
        harness
            .drive_leader(move |leader| {
                leader.start(slot, optimistic_parent, Some(parent_block.block_id), true)
            })
            .unwrap();
        harness.leader_record().unwrap();
        let block_id = harness.next_block_id();
        harness
            .leader
            .as_ref()
            .unwrap()
            .certify_past_window(slot, block_id);
        let completed =
            harness.drive_leader(move |leader| leader.complete(slot, Some(parent_block)));
        assert!(
            completed.is_err_and(|err| err.contains("moved past slot 4")),
            "the loop reports the window it gave up"
        );
        assert!(
            harness.bank(slot).is_none(),
            "the loop aborted the slot instead of waiting for a ParentReady that will not come"
        );
        assert!(harness.leader.as_ref().unwrap().working_bank().is_none());

        let refused = harness.drive_leader(move |leader| {
            leader.start(slot, optimistic_parent, Some(parent_block.block_id), true)
        });
        assert!(
            refused.is_err_and(|err| err.contains("Cluster has certified blocks")),
            "the loop refuses to start a window the cluster certified past"
        );
        let refused =
            harness.drive_leader(move |leader| leader.start(next_slot, slot, None, false));
        assert!(refused.is_err());
        harness.shutdown();
    }

    /// The real block creation loop (`start_loop`) for one window, the part of the leader side
    /// the fuzzer drives only in steps: votor's ParentReady for slots 4 and 5 arrives, the loop
    /// picks the window, produces slot 4 on the certified parent (`produce_first_slot`) and slot
    /// 5 on slot 4 (`produce_intra_window_slot`), completing each when its block timer runs out,
    /// and stops on exit. Not part of the fuzzer, because those timers are wall-clock time.
    #[test]
    fn the_real_loop_produces_a_window_from_parent_ready() {
        let mut harness = Harness::new_window_leader(tr(0) / tr(1) / tr(2));
        let parent = Block {
            slot: 2,
            block_id: harness.block_id(2),
        };
        let leader = harness.leader.as_ref().unwrap();
        let window_sender = leader.window_sender();
        let exit = Arc::new(AtomicBool::new(false));
        let bank_forks = harness.bank_forks.clone();
        let window_produced = |slot: Slot| {
            bank_forks
                .read()
                .unwrap()
                .get(slot)
                .is_some_and(|bank| bank.is_frozen())
        };
        std::thread::scope(|scope| {
            let votor = scope.spawn(|| {
                window_sender
                    .send(LeaderWindowInfo {
                        start_slot: 4,
                        end_slot: 5,
                        parent_block: parent,
                        block_timer: std::time::Instant::now(),
                    })
                    .unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while !(window_produced(4) && window_produced(5))
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                exit.store(true, Ordering::Relaxed);
            });
            let loop_exit = exit.clone();
            harness.drive_leader(move |leader| leader.run_loop(loop_exit));
            votor.join().unwrap();
        });
        let first = harness.bank(4).expect("the loop produced slot 4");
        let second = harness
            .bank(5)
            .expect("the loop produced slot 5 within the window");
        assert!(first.is_frozen() && second.is_frozen());
        assert_eq!(
            first.parent_slot(),
            2,
            "slot 4 builds on the certified parent"
        );
        assert_eq!(second.parent_slot(), 4, "slot 5 builds on slot 4");
        assert!(!first.should_replay_from_blockstore() && !second.should_replay_from_blockstore());
        drop((first, second));
        harness.broadcast();
        assert!(harness.blockstore.is_full(4) && harness.blockstore.is_full(5));
        harness.shutdown();
    }

    /// Rooting retires the forks it prunes through `DropBankService`, and since #16508 dropping a
    /// bank is what queues its write-cache purge, so a pruned fork is gone after the next ABS
    /// pass. A harness that kept those banks would keep their cache forever.
    #[test]
    fn root_prune_purges_the_pruned_fork_after_an_abs_pass() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let pruned = 2;
        assert!(!cached_generations_at(&harness, pruned).is_empty());
        harness.set_root(1);
        assert!(
            harness.bank(pruned).is_none(),
            "rooting 1 prunes its sibling"
        );
        harness.run_queued_purges();
        assert_eq!(
            cached_generations_at(&harness, pruned),
            vec![],
            "the pruned fork's write cache outlived the first ABS pass after the root"
        );
        harness.shutdown();
    }

    /// A slot that startup replay discards used to keep its accounts-cache entry: the discard
    /// removed the bank from bank forks but purged nothing, and the scheduler that ran the bank
    /// kept it alive, so the entry outlived startup with no bank at the slot and the next bank
    /// created there stored into it (#16180). #16180 clears the bank the way
    /// `ReplayStage::clear_slots` does, so the slot is purged with it.
    ///
    /// Two later changes reshape what is checked. #16102 keys the write cache by `BankId`, so
    /// the original collision cannot happen; what remains is that the discarded generation is
    /// purged at all. #16508 moves that purge from the discard into the bank's drop, which a
    /// validator hands to the accounts background service, so the property is "gone after the
    /// first ABS pass once the bank has dropped", not "gone when the discard returns", and the drop
    /// waits for the pooled scheduler that replayed the bank (up to about 190 s for a bank startup
    /// discards, see the end of the test). The test checks that the old process's generation is
    /// gone after the restart (a new process has none of it) and that a later bank at the slot
    /// sees nothing of the generation startup discards, the property #16180's own test checks.
    #[test]
    fn restart_purges_the_accounts_of_a_dead_slot_it_discards() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let parent = 1;
        harness.set_root(parent);
        // The version the switch moves to is complete, but its footer promises a bank hash its
        // block does not compute, so startup replay executes all of it and fails it only at
        // freeze, once the scheduler has finished. A version that fails earlier (no footer, say)
        // is discarded while its transactions may still be running, so whether it wrote
        // anything would be a race. Built first: the completion's shadow bank needs the slot
        // empty.
        let block_id_b = BlockId::new_unique();
        let location_b = BlockLocation::Alternate {
            block_id: block_id_b.to_hash(),
        };
        let completion_b = harness.build_completion(slot, parent, 1, location_b);
        let switched_in = harness.model.transfers[&slot].last().unwrap().signature;
        let completion_b = with_footer_hash(
            &mut harness,
            slot,
            completion_b,
            location_b,
            Hash::new_unique(),
        );

        harness.insert_block_header(slot, parent);
        harness.insert_transfer_batch(slot, parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();
        harness.freeze_for_test(slot);
        let block_id_a = harness.block_id(slot);
        harness
            .blockstore
            .set_double_merkle_root(slot, BlockLocation::Original, block_id_a.to_hash())
            .unwrap();
        let switched_out = harness.bank(slot).unwrap().bank_id();
        let header_b = harness.header_component(parent);
        harness.insert_component_at_location(slot, parent, &header_b, 0, false, location_b);
        harness.insert_completion(slot, parent, &completion_b, FEC_SET_SHREDS, location_b);
        harness
            .blockstore
            .set_double_merkle_root(slot, location_b, block_id_b.to_hash())
            .unwrap();
        harness.request_switch(slot, block_id_b);
        harness.process_switch_bank_events();
        assert!(harness.bank(slot).is_none());

        harness.restart(/*drained:*/ true);
        assert!(harness.blockstore.is_dead(slot));
        assert!(harness.bank(slot).is_none());
        assert!(
            !cached_generations_at(&harness, slot).contains(&switched_out),
            "a new process holds nothing the old process's schedulers kept"
        );
        assert!(
            !cached_generations_at(&harness, slot).is_empty(),
            "startup built a generation at the slot and discarded it; without one there is \
             nothing to check"
        );
        let destination = harness.model.destination(switched_in);
        let root_bank = harness.bank_forks.read().unwrap().root_bank();
        let accounts_cache = &root_bank.rc.accounts.accounts_db.accounts_cache;
        assert!(
            cached_generations_at(&harness, slot).iter().any(|bank_id| {
                accounts_cache
                    .bank_cache(*bank_id)
                    .is_some_and(|cache| cache.contains_key(&destination))
            }),
            "startup executes the switched-in version's transfer before it fails the block; \
             without that write there is nothing to check"
        );
        // Not checked: that the discarded generation's write cache is purged soon. Since #16508
        // that happens when its bank drops, and the idle pooled scheduler that replayed it keeps
        // it until the pool retires that scheduler, measured on 2026-11-09 at about 190 s
        // (`DEFAULT_MAX_POOLING_DURATION`, 180 s, plus a 10 s cleaner pass), or until that
        // scheduler's next session, which the pool may give to another bank first. What a
        // validator relies on meanwhile is that a later bank at the slot, which repair of the
        // canonical version would create, sees nothing of it.
        let later = Bank::new_from_parent(root_bank.clone(), SlotLeader::default(), slot);
        assert!(
            later.get_account(&destination).is_none(),
            "the startup-discard bug (#16180) reproduces again: a later bank at the slot loads an \
             account only the discarded version wrote"
        );
        assert!(
            later.get_signature_status(&switched_in).is_none(),
            "the startup-discard bug (#16180) reproduces again: a later bank at the slot sees the \
             discarded version's transaction in the status cache"
        );
        drop(later);
        harness.shutdown();
    }

    /// A restart after an UpdateParent keeps the marker slot clean: the pruned prefix's rows are
    /// already gone (#16167 purges them when the replacement bank is created), startup replay
    /// purges the pre-marker history again (waiting for TSS) before it exposes the slot, then
    /// replays the completed block from the marker, and the recreated generation roots clean.
    #[test]
    fn restart_purges_pruned_prefix_before_exposing_the_slot() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        harness.insert_block_header(slot, optimistic_parent);
        let prefix_signature =
            harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();
        harness.set_root(rooted_parent);
        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 2 * FEC_SET_SHREDS);
        harness.handle_update_parent_interrupts();
        harness.reset_entry_chain(slot, rooted_parent);
        let completion = harness.build_completion(slot, rooted_parent, 1, BlockLocation::Original);
        harness.insert_completion(
            slot,
            optimistic_parent,
            &completion,
            3 * FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        let suffix_signature = harness.model.transfers[&slot].last().unwrap().signature;
        harness.generate_new_bank_forks();
        let result = harness.replay(slot);
        assert_eq!(result.as_ref().ok(), Some(&1), "{result:?}");
        harness.process_replay_result(slot, result);
        assert!(harness.bank(slot).unwrap().is_frozen());
        harness.drain_tss();
        // Fixed by #16167: the purge now runs when the replacement bank is created, so the
        // pruned prefix row is gone before the restart rather than healed by it.
        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix_signature, slot))
                .unwrap()
                .is_none(),
            "the pruned-prefix bug (#16167) reproduces again: the pruned prefix row survived"
        );
        let before_restart = harness.bank(slot).unwrap().bank_id();

        harness.restart(/*drained:*/ true);
        let after_restart = harness.bank(slot).expect("startup replays the full slot");
        assert_ne!(after_restart.bank_id(), before_restart);
        assert!(after_restart.is_frozen());
        assert_eq!(after_restart.parent_slot(), rooted_parent);
        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix_signature, slot))
                .unwrap()
                .is_none(),
            "startup purges the pre-marker history before exposing the slot"
        );
        assert!(harness.status_cache_leaks(slot).is_empty());
        assert!(harness.accounts_cache_leaks(slot).is_empty());

        assert_eq!(
            after_restart.block_id(),
            Some(harness.block_id(slot)),
            "the rebuilt bank keeps the block's id"
        );
        drop(after_restart);
        harness.set_root(slot);
        harness.drain_tss();
        assert!(harness.finalized_soundness_violations().is_empty());
        assert!(harness.finalized_completeness_violations().is_empty());
        assert_eq!(harness.rooted_history_slot(suffix_signature), Some(slot));
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        harness.shutdown();
    }

    /// R9 end to end on the leader side: the loop starts slot 4 on the optimistic sibling,
    /// banking stage records two transfers, votor certifies the other sibling, and completing the
    /// block performs the sad handover: the UpdateParent marker is emitted, the bank is replaced
    /// through the real replay-side controller, the recorded transactions' history is purged by
    /// signature, and the shreds keep the original header parent while the slot meta follows the
    /// marker. The recreated generation roots clean.
    #[test]
    fn leader_sad_handover_replaces_bank_and_purges_history() {
        let mut harness = Harness::new_leader(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;
        let parent_block_id = harness.block_id(optimistic_parent);
        harness
            .drive_leader(move |leader| {
                leader.start(slot, optimistic_parent, Some(parent_block_id), true)
            })
            .unwrap();
        let first = harness.bank(slot).expect("leader bank inserted");
        assert_eq!(first.parent_slot(), optimistic_parent);
        assert!(!first.should_replay_from_blockstore());
        let first_id = first.bank_id();
        drop(first);
        harness.leader_record().unwrap();
        harness.leader_record().unwrap();
        harness.drain_tss();
        let recorded: Vec<Signature> = harness.model.generations[&slot][0].signatures.clone();
        assert_eq!(recorded.len(), 2);
        for signature in &recorded {
            assert!(
                harness
                    .blockstore
                    .read_transaction_status((*signature, slot))
                    .unwrap()
                    .is_some(),
                "banking stage's rows are written before the handover"
            );
        }

        let optimistic_block = Block {
            slot: optimistic_parent,
            block_id: harness.block_id(optimistic_parent),
        };
        let certified = Block {
            slot: rooted_parent,
            block_id: harness.block_id(rooted_parent),
        };
        harness
            .leader
            .as_ref()
            .unwrap()
            .parent_ready(slot, certified);
        harness
            .drive_leader(move |leader| leader.complete(slot, Some(optimistic_block)))
            .unwrap();
        let replacement = harness
            .bank(slot)
            .expect("handover recreated the leader bank");
        assert_ne!(replacement.bank_id(), first_id);
        assert_eq!(replacement.parent_slot(), rooted_parent);
        assert!(
            replacement.is_frozen(),
            "the replay side froze the completed bank"
        );
        assert_eq!(
            harness.leader.as_ref().unwrap().take_rescheduled(),
            1,
            "the handed-over transactions go back to banking stage as one batch"
        );
        harness.drain_tss();
        assert!(
            harness
                .history_rows_of_discarded_generations(slot)
                .is_empty(),
            "the leader purge removes the recorded transactions' rows"
        );
        assert!(harness.status_cache_leaks(slot).is_empty());
        assert!(harness.accounts_cache_leaks(slot).is_empty());

        harness.broadcast();
        let meta = harness.blockstore.meta(slot).unwrap().unwrap();
        assert!(meta.has_update_parent(), "the marker was broadcast");
        assert_eq!(
            meta.parent_slot,
            Some(rooted_parent),
            "slot meta follows the marker"
        );
        assert!(meta.is_full(), "the completion was broadcast");
        let header_shred = harness.blockstore.get_data_shred(slot, 0).unwrap().unwrap();
        assert_eq!(
            Shred::new_from_serialized_shred(header_shred)
                .unwrap()
                .parent()
                .unwrap(),
            optimistic_parent,
            "the shred header keeps the original parent"
        );
        drop(replacement);
        harness.handle_update_parent_interrupts();
        let after_signal = harness.bank(slot).unwrap();
        assert!(
            after_signal.is_frozen() && after_signal.parent_slot() == rooted_parent,
            "our own marker does not restart our own bank"
        );
        assert!(
            after_signal.block_id().is_some(),
            "broadcast set the block id"
        );
        drop(after_signal);

        harness.set_root(slot);
        harness.drain_tss();
        assert!(harness.finalized_soundness_violations().is_empty());
        assert!(harness.finalized_completeness_violations().is_empty());
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        for signature in &recorded {
            assert_eq!(
                harness.rpc_transaction_slot(*signature, CommitmentConfig::finalized()),
                None
            );
        }
        harness.shutdown();
    }

    /// R4 with a late broadcast: the loop aborts the working bank after banking stage recorded
    /// into it, and broadcast ships what PoH had produced only afterwards. The slot gets shreds
    /// without a footer, never becomes full, replay never creates a bank for it, and the aborted
    /// generation's rows can never be served as finalized.
    #[test]
    fn leader_abort_then_late_broadcast_never_completes_the_slot() {
        let mut harness = Harness::new_leader(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let parent_block_id = harness.block_id(optimistic_parent);
        harness
            .drive_leader(move |leader| {
                leader.start(slot, optimistic_parent, Some(parent_block_id), true)
            })
            .unwrap();
        harness.leader_record().unwrap();
        let recorded = harness.model.generations[&slot][0].signatures[0];
        harness
            .drive_leader(move |leader| leader.abort(slot))
            .unwrap();
        assert!(harness.bank(slot).is_none(), "the abort cleared the bank");
        assert!(harness.leader.as_ref().unwrap().working_bank().is_none());

        harness.broadcast();
        let meta = harness.blockstore.meta(slot).unwrap().unwrap();
        assert!(
            !meta.is_full(),
            "an aborted block has no footer or last shred"
        );
        assert!(
            meta.received > 0,
            "the late broadcast still shipped the prefix"
        );
        harness.generate_new_bank_forks();
        assert!(
            harness.bank(slot).is_none(),
            "replay leaves an incomplete own-leader slot to the loop"
        );
        harness.drain_tss();
        assert!(
            harness
                .blockstore
                .read_transaction_status((recorded, slot))
                .unwrap()
                .is_some(),
            "no purge runs on abort (R4 x C4): the row stays"
        );
        assert_eq!(harness.rooted_history_slot(recorded), None);
        assert!(harness.finalized_soundness_violations().is_empty());
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        harness.shutdown();
    }

    /// R5 on the leader's own working bank: a competing root prunes the slot the loop is
    /// producing. Banking stage's next commit is cancelled (nothing is recorded), completion
    /// finds the bank retired and clears PoH, and the generation's rows can never be served.
    #[test]
    fn root_prune_retires_the_leader_working_bank() {
        let mut harness = Harness::new_leader(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;
        let parent_block_id = harness.block_id(optimistic_parent);
        harness
            .drive_leader(move |leader| {
                leader.start(slot, optimistic_parent, Some(parent_block_id), true)
            })
            .unwrap();
        assert!(harness.leader_record().unwrap(), "a live bank records");
        let recorded = harness.model.generations[&slot][0].signatures[0];
        harness.drain_tss();

        harness.set_root(rooted_parent);
        assert!(
            harness.bank(slot).is_none(),
            "the prune removed the leader bank"
        );
        assert!(
            harness.leader.as_ref().unwrap().working_bank().is_some(),
            "PoH still holds it until the loop notices"
        );
        assert!(
            !harness.leader_record().unwrap(),
            "a commit on the retired bank is cancelled before anything is recorded"
        );
        // Votor's ParentReady still arrives for the window; completion then finds the bank
        // retired instead of writing a footer.
        let optimistic_block = Block {
            slot: optimistic_parent,
            block_id: BlockId::new_unique(),
        };
        harness
            .leader
            .as_ref()
            .unwrap()
            .parent_ready(slot, optimistic_block);
        let completed =
            harness.drive_leader(move |leader| leader.complete(slot, Some(optimistic_block)));
        assert!(completed.is_err(), "completion finds the bank retired");
        assert!(
            harness.leader.as_ref().unwrap().working_bank().is_none(),
            "the loop cleared PoH"
        );
        harness.drain_tss();
        assert!(
            harness
                .blockstore
                .read_transaction_status((recorded, slot))
                .unwrap()
                .is_some(),
            "the prune path sends no purge (the pruned-prefix family); the slot cannot root"
        );
        assert_eq!(harness.rooted_history_slot(recorded), None);
        assert!(harness.finalized_soundness_violations().is_empty());
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        harness.shutdown();
    }

    const DEFAULT_SEEDS: u64 = 48;

    /// Random programs over the discard paths against the slot-keyed stores. Findings that match
    /// a known open case are reported but do not fail; anything else fails with the seed to
    /// replay. `FLH_HARNESS_SEEDS` overrides the seed count, `FLH_HARNESS_VERBOSE` prints each
    /// program and its timings.
    #[test]
    fn random_discard_programs() {
        let seeds: u64 = std::env::var("FLH_HARNESS_SEEDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_SEEDS);
        let workers: u64 = 2;
        let known = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers)
                .map(|worker| {
                    scope.spawn(move || {
                        let mut known: BTreeSet<&'static str> = BTreeSet::new();
                        for seed in (worker..seeds).step_by(workers as usize) {
                            let program = Program::random(seed);
                            if verbose() {
                                eprintln!("seed {seed} starts: {program:?}");
                            }
                            let started = std::time::Instant::now();
                            let findings = run_program(&program);
                            if verbose() {
                                eprintln!(
                                    "seed {seed}: {:?} findings={} {program:?}",
                                    started.elapsed(),
                                    findings.len()
                                );
                            }
                            let unknown: Vec<String> = findings
                                .iter()
                                .filter(|finding| finding.known.is_none())
                                .map(|finding| format!("[{}] {}", finding.cell, finding.detail))
                                .collect();
                            known.extend(findings.iter().filter_map(|finding| finding.known));
                            assert!(
                                unknown.is_empty(),
                                "seed {seed}: {}\nprogram: {program:#?}",
                                unknown.join("; ")
                            );
                        }
                        known
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .collect::<BTreeSet<&'static str>>()
        });
        if seeds >= DEFAULT_SEEDS {
            // Every open bug the oracles still reach must come back classified. Counting them in
            // aggregate is not enough: a classifier can go narrow after a harness change and the
            // bug it used to match then crashes the target instead, once per variant, which once
            // flooded a fuzzing run with crashes. When a bug is fixed, delete its line here and
            // flip the test that asserts it reproduces.
            let expected = [
                "R3 x C8: the commitment cache names a switched-out slot",
                "R4 x C4: aborted leader bank rows stay, the slot cannot root",
            ];
            let missing: Vec<&str> = expected
                .into_iter()
                .filter(|case| !known.contains(case))
                .collect();
            assert!(
                missing.is_empty(),
                "these open bugs were never classified over {seeds} seeds, so they now crash the \
                 target instead: {missing:?} (classified: {known:?})"
            );
        }
    }

    /// R1 followed by a real completion: the restart recreates the slot at the marker, the suffix
    /// executes, the footer's shadow-computed hash matches, the block freezes and roots, and the
    /// suffix transaction is served as finalized history (I3) while the prefix one is not (I1).
    #[test]
    fn m3_restart_then_suffix_completes_freezes_and_roots() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        harness.insert_block_header(slot, optimistic_parent);
        let prefix_signature =
            harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        // An incomplete batch keeps replay short of the marker, so the signal path restarts (R1).
        let withheld =
            harness.insert_incomplete_transfer_batch(slot, optimistic_parent, 2 * FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();

        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 3 * FEC_SET_SHREDS);
        harness.handle_update_parent_interrupts();
        assert!(
            harness.bank(slot).is_none(),
            "R1 must clear the prefix bank"
        );
        harness.drain_tss();
        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix_signature, slot))
                .unwrap()
                .is_none(),
            "R1 must purge the prefix history"
        );

        // Repair delivers the withheld prefix shred; until then the suffix is unreadable.
        harness
            .blockstore
            .insert_shreds(vec![withheld], true)
            .unwrap();
        harness.reset_entry_chain(slot, rooted_parent);
        let completion = harness.build_completion(slot, rooted_parent, 1, BlockLocation::Original);
        harness.insert_completion(
            slot,
            optimistic_parent,
            &completion,
            4 * FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        let suffix_signature = harness.model.transfers[&slot].last().unwrap().signature;
        harness.generate_new_bank_forks();
        assert_eq!(harness.bank(slot).unwrap().parent_slot(), rooted_parent);

        let result = harness.replay(slot);
        assert_eq!(
            result.as_ref().ok(),
            Some(&1),
            "suffix must execute: {result:?}"
        );
        harness.process_replay_result(slot, result);
        let bank = harness.bank(slot).expect("bank survives completion");
        assert!(
            bank.is_frozen(),
            "footer hash must match and the bank must freeze"
        );
        assert!(!harness.blockstore.is_dead(slot));
        assert_eq!(bank.expected_bank_hash(), Some(bank.hash()));
        if bank.block_id().is_none() {
            bank.set_block_id(Some(BlockId::new_unique()));
        }

        harness.set_root(slot);
        harness.drain_tss();
        assert!(harness.finalized_soundness_violations().is_empty());
        assert!(harness.finalized_completeness_violations().is_empty());
        assert_eq!(harness.rooted_history_slot(suffix_signature), Some(slot));
        assert_eq!(harness.rooted_history_slot(prefix_signature), None);
        harness.shutdown();
    }

    /// The pruned prefix through a real block completion: a prefix executes on the optimistic
    /// parent, the competing root prunes that generation, the marker re-parents the slot, and the
    /// recreated block completes, freezes and roots. Returns (prefix, suffix) signatures; TSS is
    /// drained on return.
    fn drive_pruned_prefix_real_completion(harness: &mut Harness) -> (Signature, Signature) {
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        harness.insert_block_header(slot, optimistic_parent);
        let prefix_signature =
            harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();

        harness.set_root(rooted_parent);
        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 2 * FEC_SET_SHREDS);
        harness.handle_update_parent_interrupts();
        harness.reset_entry_chain(slot, rooted_parent);
        let completion = harness.build_completion(slot, rooted_parent, 1, BlockLocation::Original);
        harness.insert_completion(
            slot,
            optimistic_parent,
            &completion,
            3 * FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        let suffix_signature = harness.model.transfers[&slot].last().unwrap().signature;
        harness.generate_new_bank_forks();
        assert_eq!(harness.bank(slot).unwrap().parent_slot(), rooted_parent);

        let result = harness.replay(slot);
        assert_eq!(
            result.as_ref().ok(),
            Some(&1),
            "suffix must execute: {result:?}"
        );
        harness.process_replay_result(slot, result);
        let bank = harness.bank(slot).expect("bank survives completion");
        assert!(
            bank.is_frozen(),
            "footer hash must match (dead: {})",
            harness.blockstore.is_dead(slot)
        );
        if bank.block_id().is_none() {
            bank.set_block_id(Some(BlockId::new_unique()));
        }
        harness.set_root(slot);
        harness.drain_tss();
        (prefix_signature, suffix_signature)
    }

    /// The pruned prefix's row survives and is served alongside the canonical suffix once the
    /// recreated block roots.
    #[test]
    fn pruned_prefix_with_real_completion() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let (prefix_signature, suffix_signature) =
            drive_pruned_prefix_real_completion(&mut harness);

        assert!(harness.finalized_completeness_violations().is_empty());
        assert_eq!(harness.rooted_history_slot(suffix_signature), Some(slot));
        let violations = harness.finalized_soundness_violations();
        assert!(
            violations.is_empty(),
            "the pruned-prefix bug (#16167) reproduces again: {violations:?}"
        );
        let _ = prefix_signature;
        harness.shutdown();
    }

    fn violation_summary(violations: &[RpcViolation]) -> Vec<(&'static str, Signature, Slot)> {
        violations
            .iter()
            .map(|violation| (violation.query, violation.signature, violation.slot))
            .collect()
    }

    /// The pruned prefix as a client sees it. Before #16167 `getSignatureStatuses` and
    /// `getSignaturesForAddress` served the pruned prefix transaction as finalized at the rooted
    /// slot. `getBlock` and `getTransaction` read the slot's entries from the marker on
    /// (#14432), so the prefix is absent from the block and its stale status row makes the
    /// blockstore report `TransactionStatusSlotMismatch`, which `getTransaction` turns into
    /// "not found".
    #[test]
    fn rpc_does_not_serve_pruned_prefix_as_finalized() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let (prefix_signature, suffix_signature) =
            drive_pruned_prefix_real_completion(&mut harness);

        assert!(harness.rpc_finalized_completeness_violations().is_empty());
        assert_eq!(
            harness.rpc_block(slot, CommitmentConfig::finalized()),
            Ok(Some(vec![(suffix_signature, true)]))
        );
        // Fixed by #16167: the discarded prefix is gone from every read path, so the slot's
        // only rooted transaction is the suffix the recreated block actually executed.
        assert!(matches!(
            harness.blockstore.get_rooted_transaction(prefix_signature),
            Ok(None) | Err(BlockstoreError::TransactionStatusSlotMismatch)
        ));
        assert!(
            violation_summary(&harness.rpc_finalized_soundness_violations()).is_empty(),
            "the pruned-prefix bug (#16167) reproduces again through RPC"
        );
        harness.shutdown();
    }

    /// Drives the R1 restart with a real completion while the TSS gate is closed: the prefix row is
    /// written, then the restart purge, the suffix batch and the freeze all queue behind the gate
    /// and the recreated block roots. Returns (prefix, suffix) signatures with the gate still
    /// closed.
    fn drive_restart_with_tss_lagging(harness: &mut Harness) -> (Signature, Signature) {
        let slot = 4;
        let optimistic_parent = 2;
        let rooted_parent = 1;

        harness.insert_block_header(slot, optimistic_parent);
        let prefix_signature =
            harness.insert_transfer_batch(slot, optimistic_parent, FEC_SET_SHREDS);
        let withheld =
            harness.insert_incomplete_transfer_batch(slot, optimistic_parent, 2 * FEC_SET_SHREDS);
        harness.generate_new_bank_forks();
        assert_eq!(harness.replay(slot).unwrap(), 1);
        harness.drain_tss();

        harness.close_tss_gate();
        harness.insert_update_parent(slot, optimistic_parent, rooted_parent, 3 * FEC_SET_SHREDS);
        harness.handle_update_parent_interrupts();
        assert!(
            harness.bank(slot).is_none(),
            "R1 must clear the prefix bank"
        );
        harness
            .blockstore
            .insert_shreds(vec![withheld], true)
            .unwrap();
        harness.reset_entry_chain(slot, rooted_parent);
        let completion = harness.build_completion(slot, rooted_parent, 1, BlockLocation::Original);
        harness.insert_completion(
            slot,
            optimistic_parent,
            &completion,
            4 * FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        let suffix_signature = harness.model.transfers[&slot].last().unwrap().signature;
        harness.generate_new_bank_forks();
        let result = harness.replay(slot);
        assert_eq!(
            result.as_ref().ok(),
            Some(&1),
            "suffix must execute: {result:?}"
        );
        harness.process_replay_result(slot, result);
        let bank = harness.bank(slot).expect("bank survives completion");
        assert!(bank.is_frozen(), "footer hash must match");
        if bank.block_id().is_none() {
            bank.set_block_id(Some(BlockId::new_unique()));
        }
        harness.set_root(slot);
        (prefix_signature, suffix_signature)
    }

    /// The window between a root and TSS catching up: the restart purge is correct but queued,
    /// so the discarded prefix's rows are still stored. Before #15418, `getSignatureStatuses` and
    /// `getSignaturesForAddress` served them as finalized. #15418 gates finalized history on a
    /// watermark TSS advances only once it has seen the same generation frozen and rooted, and
    /// TSS has seen neither yet, so nothing from the slot is served until it catches up.
    #[test]
    fn rpc_finalized_reads_while_tss_lags_behind_restart() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let finalized = CommitmentConfig::finalized();
        let (prefix_signature, suffix_signature) = drive_restart_with_tss_lagging(&mut harness);

        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix_signature, slot))
                .unwrap()
                .is_some(),
            "the purge is still queued, so the discarded prefix row is stored and only the gate \
             keeps it from being served"
        );
        assert_eq!(
            violation_summary(&harness.rpc_finalized_soundness_violations()),
            vec![],
            "#15418's frozen-and-rooted gate no longer holds back the discarded prefix"
        );
        assert_eq!(
            harness.rpc_block(slot, finalized),
            Err(format!(
                "Server error: Block status not yet available for slot {slot}"
            ))
        );
        assert_eq!(
            harness
                .rpc_signature_status(suffix_signature, finalized)
                .map(|status| status.slot),
            None,
            "with history search at finalized, #15418 gates even the status cache's answer \
             (`rpc.rs:1927-1929`), so the suffix waits for TSS like the rest of the slot"
        );

        harness.open_tss_gate();
        harness.drain_tss();
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        assert!(harness.rpc_finalized_completeness_violations().is_empty());
        assert_eq!(
            harness.rpc_block(slot, finalized),
            Ok(Some(vec![(suffix_signature, true)]))
        );
        harness.shutdown();
    }

    /// The blockstore-writes watermark is one number across forks: a frozen block on the losing
    /// fork lifts it past the recreated slot, so before #15418 `getBlock` at finalized consulted
    /// the blockstore before the rooted block's status rows existed, and the missing metadata
    /// surfaced as "block not available" (a null block once a later root landed) instead of
    /// "not yet available", while the signature queries served the discarded prefix. #15418 gates
    /// finalized reads on a watermark keyed by (slot, bank id) and by root, which the losing fork
    /// cannot lift, so every query stays in "not yet available" until TSS is done.
    #[test]
    fn rpc_get_block_watermark_lifted_by_losing_fork() {
        let mut harness = Harness::new(tr(0) / tr(1) / tr(2));
        let slot = 4;
        let losing_slot = 5;
        let losing_parent = 2;
        let finalized = CommitmentConfig::finalized();

        harness.insert_block_header(losing_slot, losing_parent);
        let completion =
            harness.build_completion(losing_slot, losing_parent, 1, BlockLocation::Original);
        harness.insert_completion(
            losing_slot,
            losing_parent,
            &completion,
            FEC_SET_SHREDS,
            BlockLocation::Original,
        );
        harness.generate_new_bank_forks();
        let result = harness.replay(losing_slot);
        assert_eq!(result.as_ref().ok(), Some(&1), "{result:?}");
        harness.process_replay_result(losing_slot, result);
        assert!(harness.bank(losing_slot).unwrap().is_frozen());
        harness.drain_tss();
        assert_eq!(
            harness
                .max_complete_transaction_status_slot
                .load(Ordering::SeqCst),
            losing_slot
        );

        let (prefix_signature, suffix_signature) = drive_restart_with_tss_lagging(&mut harness);
        assert!(
            harness.bank(losing_slot).is_none(),
            "rooting the recreated slot prunes the losing fork"
        );
        assert!(
            harness
                .blockstore
                .read_transaction_status((prefix_signature, slot))
                .unwrap()
                .is_some(),
            "the purge is still queued, so the discarded prefix row is stored and only the gate \
             keeps it from being served"
        );
        assert_eq!(
            violation_summary(&harness.rpc_finalized_soundness_violations()),
            vec![],
            "the losing fork lifted #15418's frozen-and-rooted gate past the recreated slot"
        );
        assert!(
            harness
                .max_complete_transaction_status_slot
                .load(Ordering::SeqCst)
                >= slot,
            "the losing fork still lifts the plain writes watermark past the slot, so the old \
             window is set up and only the new gate closes it"
        );
        assert!(matches!(
            harness.blockstore.get_rooted_block(slot, true),
            Err(BlockstoreError::MissingTransactionMetadata)
        ));
        assert_eq!(
            harness.rpc_block(slot, finalized),
            Err(format!(
                "Server error: Block status not yet available for slot {slot}"
            )),
            "getBlock must wait for the frozen-and-rooted watermark, not reach the blockstore"
        );

        harness.open_tss_gate();
        harness.drain_tss();
        assert!(harness.rpc_finalized_soundness_violations().is_empty());
        assert!(harness.rpc_finalized_completeness_violations().is_empty());
        assert_eq!(
            harness.rpc_block(slot, finalized),
            Ok(Some(vec![(suffix_signature, true)]))
        );
        harness.shutdown();
    }
}
