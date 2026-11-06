# rskj → rustock: where everything lives

A map for someone who knows rskj and wants to change rustock. For each rskj
component it names the Java package and the classes that matter, then the
rustock crate and the files that answer to them.

Two things worth knowing before reading it.

**rskj has two package roots.** `co.rsk.*` is Rootstock's own code;
`org.ethereum.*` is inherited from ethereumJ and heavily modified. rustock has
no equivalent split — the distinction is historical, not architectural, and
what matters is whether the behaviour is RSK's or Ethereum's, which the
inherited packages no longer tell you.

**Sizes are not comparable.** rustock is ~105,100 lines of Rust against
rskj's ~130,800 lines of Java, but rustock has no DI container, no builder
classes, and gets the EVM interpreter from `revm` rather than implementing it.
A component that looks smaller here usually is not.

---

## The map

### Consensus execution

| | rskj | rustock |
|---|---|---|
| Block execution | `co.rsk.core.bc.BlockExecutor`, `TransactionExecutorFactory`, `org.ethereum.core.TransactionExecutor` | `crates/execution/src/executor.rs` (`RskExecutor::execute_block`) |
| Block processing / import | `co.rsk.core.bc.BlockChainImpl`, `co.rsk.net.BlockSyncService` | `crates/execution/src/processor.rs` (`BlockProcessor`) |
| EVM interpreter | `org.ethereum.vm.VM`, `org.ethereum.vm.program.Program` | `revm` (external), re-shaped by `crates/execution/src/rsk_instructions.rs` |
| Gas / handler semantics | `org.ethereum.vm.GasCost`, `TransactionExecutor` refund logic | `crates/execution/src/rsk_handler.rs` |
| Hard-fork activation | `org.ethereum.config.blockchain.upgrades.ActivationConfig`, `ConsensusRule` | `crates/execution/src/hardfork.rs` |
| Account / contract state | `co.rsk.db.MutableRepository`, `RepositoryLocator` | `crates/execution/src/state.rs`, `database.rs` |

`rsk_instructions.rs` is where RSK's opcode divergences from Ethereum live —
the ones `revm` would otherwise get right for Ethereum and wrong for RSK.

### The unitrie

| | rskj | rustock |
|---|---|---|
| Node format, encoding | `co.rsk.trie.Trie`, `TrieDTO`, `NodeReference` | `crates/trie/src/node.rs`, `varint.rs` |
| Key mapping | `co.rsk.trie.TrieKeyMapper` | `crates/trie/src/key_mapper.rs` |
| Paths / shared prefixes | `co.rsk.trie.TrieKeySlice` | `crates/trie/src/path.rs`, `shared_path.rs` |
| Account encoding | `co.rsk.core.types.ints.*`, `AccountState` | `crates/trie/src/account.rs` |
| Pre-unitrie conversion | `co.rsk.trie.OrchidTrie*` | `crates/trie/src/orchid_converter.rs` |
| Storage backend | `org.ethereum.datasource.*`, `co.rsk.db.*` | `crates/storage/src/trie_store.rs`, `cached_trie_store.rs` |

### The two-way peg (Bridge)

The largest component on both sides. rskj `co.rsk.peg` (~21,900 lines) →
rustock `crates/execution/src/bridge/` (~22,700 lines).

| | rskj | rustock |
|---|---|---|
| Dispatch table, ABI | `Bridge.java`, `BridgeMethods.java` | `bridge/mod.rs` |
| Core logic | `BridgeSupport.java` | `bridge/peg.rs` |
| Storage layout | `BridgeStorageProvider.java`, `BridgeStorageIndexKey.java` | `bridge/storage.rs` |
| Serialisation | `BridgeSerializationUtils.java` | `bridge/serialization.rs` |
| Federation | `peg/federation/*` (`FederationSupport`, `FederationStorageProvider`) | `bridge/federation.rs`, `governance.rs` |
| BTC header chain | `BtcBlockStoreWithCache`, `RepositoryBtcBlockStoreWithCache` | `bridge/btc_chain.rs`, `btc_store.rs`, `btc_block_cache.rs` |
| Peg-out queue and building | `ReleaseRequestQueue`, `PegoutsWaitingForConfirmations`, `ReleaseTransactionBuilder` | `bridge/release_tx.rs` |
| Peg-in classification | `peg/pegin/*`, `PegUtils`, `btcLockSender/*` | `bridge/peg.rs`, `rskj_sender_compat.rs` |
| Peg-in instructions (flyover) | `peg/pegininstructions/*` | `bridge/pegin_instructions.rs` |
| Merkle proofs | `PartialMerkleTreeFormatUtils`, `MerkleBranch`, plus `co.rsk.bitcoinj.core.PartialMerkleTree` from the **bitcoinj-thin** dependency | `bridge/pmt.rs`, over `crates/core/src/partial_merkle_tree.rs` |
| Whitelist / locking cap / fees | `peg/whitelist/*`, `peg/lockingcap/*`, `peg/feeperkb/*` | `bridge/governance.rs` |
| Voting | `peg/vote/*` (`ABICallSpec`, `ABICallElection`) | `bridge/vote.rs` |
| Local-call getters | `BridgeSupport` getters, `BridgeState` | `bridge/getters.rs` |
| Events | `BridgeEvents.java` | `bridge/events.rs` |
| Constants | `peg/constants/*` | `bridge/constants.rs` |

### Other precompiles

| | rskj | rustock |
|---|---|---|
| Registry, dispatch | `org.ethereum.vm.PrecompiledContracts` | `crates/execution/src/precompiles.rs` |
| REMASC | `co.rsk.remasc.RemascContract`, `Remasc`, `RemascStorageProvider` | `crates/execution/src/remasc.rs` |
| Block header contract | `co.rsk.pcc.blockheader.BlockHeaderContract` | `precompiles.rs` (`BLOCK_HEADER_ADDR`) |
| HDWalletUtils | `co.rsk.pcc.bto.HDWalletUtils` | `precompiles.rs` (`HD_WALLET_UTILS_ADDR`) |
| Environment | `co.rsk.pcc.environment.Environment` | `precompiles.rs` (`ENVIRONMENT_ADDR`) |
| secp256k1 add/mul | `co.rsk.pcc.secp256k1.*` | `precompiles.rs` (`SECP256K1_*_ADDR`) |
| altBN128 | `co.rsk.pcc.altBN128.*` | `revm` (external) |

### Block validation

rskj builds validation from composable rule objects (`BlockValidatorImpl` over
`BlockCompositeRule` over ~25 `*Rule` classes). rustock states the same rules
as functions.

| | rskj | rustock |
|---|---|---|
| Header rules | `BlockDifficultyRule`, `BlockTimeStampValidationRule`, `GasLimitRule`, `ExtraDataRule` | `crates/core/src/validation/header_rules.rs` |
| Body rules | `BlockTxsValidationRule`, `BlockTxsMaxGasPriceRule`, `BlockRootValidationRule` | `crates/core/src/validation/block_rules.rs` |
| Uncles | `BlockUnclesValidationRule`, `BlockUnclesHashValidationRule`, `FamilyUtils` | `crates/core/src/validation/uncles.rs` |
| Difficulty | `co.rsk.core.DifficultyCalculator` | `crates/core/src/validation/difficulty.rs` |
| Merged mining | `ProofOfWorkRule`, `BtcHeaderSizeRule`, `Rskip92MerkleProofValidator`, `GenesisMerkleProofValidator`, plus bitcoinj-thin's `BtcBlock` and `PartialMerkleTree` | `crates/core/src/validation/merged_mining.rs`, `crates/core/src/btc_block.rs`, `crates/core/src/partial_merkle_tree.rs` |
| Fork detection | `ForkDetectionDataRule`, `ConsensusValidationMainchainView` | `crates/core/src/validation/fork_detection.rs` |

### Networking

| | rskj | rustock |
|---|---|---|
| RLPx / ECIES / frames | `org.ethereum.net.rlpx.*` (`EncryptionHandshake`, `FrameCodec`) | `crates/networking/src/rlpx/` |
| devp2p handshake, Hello | `org.ethereum.net.p2p.*`, `HandshakeHandler` | `crates/networking/src/handshake.rs`, `protocol/p2p.rs` |
| Node discovery (v4) | `co.rsk.net.discovery.*` (`PeerExplorer`, `NodeDistanceTable`) | `crates/networking/src/discovery/` |
| Wire messages | `co.rsk.net.messages.*`, `org.ethereum.net.eth.message.*` | `crates/networking/src/protocol/rsk.rs`, `eth.rs` |
| Peer registry | `co.rsk.net.Peer`, `ChannelManager` | `crates/networking/src/peers.rs` |
| Outbound dialling | `org.ethereum.net.server.PeerClient`, `SyncPool` | `crates/networking/src/outbound.rs` |
| Peer scoring and bans | `co.rsk.scoring.*` (`PeerScoring`, `PeerScoringManager`, `InetAddressTable`) | `crates/networking/src/scoring.rs` |

### Sync

| | rskj | rustock |
|---|---|---|
| Sync state machine | `co.rsk.net.SyncProcessor` + `net/sync/*SyncState` classes | `crates/sync/src/service.rs` (`SyncState` enum, one `tick`) |
| Skeleton / chunk download | `DownloadingSkeletonSyncState`, `ChunksDownloadHelper`, `ChunkTask` | `crates/sync/src/tracker.rs` |
| Connection point search | `ConnectionPointFinder`, `FindingConnectionPointSyncState` | `crates/sync/src/service.rs` |
| Peer bookkeeping | `PeersInformation` | `crates/sync/src/service.rs`, `crates/networking/src/peers.rs` |
| Header import | `BlockSyncService`, `NetBlockStore` | `crates/sync/src/manager.rs` |
| Message handling | `NodeMessageHandler`, `MessageVisitor` | `crates/sync/src/handler.rs` |
| Transaction pool | `org.ethereum.core.TransactionPoolImpl`, `PendingState` | `crates/sync/src/txpool.rs` |
| Account rate limiting | `co.rsk.net.handler.quota.*` (`TxQuotaChecker`, `TxVirtualGasCalculator`) | `crates/sync/src/quota.rs` |
| Transaction relay | `co.rsk.net.TransactionGateway` | `crates/sync/src/tx_relay.rs` |
| Gas price suggestion | `org.ethereum.listener.GasPriceTracker` | `crates/sync/src/gas_price.rs` |
| Snapshot sync, server | `co.rsk.net.SnapshotProcessor` (`processStateChunkRequest`, `processSnapStatusRequest`) | `crates/sync/src/snap/server.rs` |
| Snapshot sync, client | `SnapshotProcessor` (`processStateChunkResponse`), `net/sync/SnapSyncState` | `crates/sync/src/snap/client.rs`, `session.rs`, `driver.rs` |
| Chunk proof | `co.rsk.trie.TrieDTOInOrderRecoverer.verifyChunk` (heuristic reconstruction) | `crates/trie/src/snapshot_proof.rs` (linear replay) |
| Trie traversal by offset | `co.rsk.trie.TrieDTOInOrderIterator`, `TrieDTO` | `crates/trie/src/snapshot.rs` |
| Snap messages (types 20-25) | `co.rsk.net.messages.Snap*Message` | `crates/networking/src/protocol/snap.rs` |
| rskj's snapshot node encoding | `co.rsk.trie.TrieDTO`, `TrieDTOInOrderIterator` | `crates/trie/src/snapshot_legacy.rs` |
| Snap request queueing | `SnapSyncRequestManager`, `SnapshotPeersInformation` | `crates/sync/src/snap/driver.rs` |
| Snap header verification | `SnapshotProcessor.validateBlockHeaders` (serial) | `crates/sync/src/snap/headers.rs` (pipelined by skeleton) |

rustock's sync has no rskj counterpart for three of its files — see
"rustock-only" below.

rustock serves rskj clients in rskj's own chunk format, verified byte-for-byte
against vectors generated by running rskj's code (`crates/trie/tests/rskj-vectors/`).
The reverse works too: a rustock client rebuilds each rskj chunk bottom-up,
checks it at the state root, and places it in the trie from the sizes the
rebuilt nodes commit to (`docs/snapshot-sync.md`, "Reading rskj's chunks").

Snapshot sync is the same six p2p commands and the same trust model, with
three differences documented in `docs/snapshot-sync.md`: chunks are verified
by replaying the traversal (linear) rather than by rebuilding the subtree from
a `children_size` heuristic (quadratic); nodes travel in consensus form, so a
verified node is written straight to the store with nothing to reconstruct;
and the chunk request names the state root, so peers cannot disagree about
which state is being downloaded.

### Mining

| | rskj | rustock |
|---|---|---|
| Block template | `co.rsk.mine.BlockToMineBuilder`, `MinerServer` | `crates/execution/src/mining/template.rs`, `server.rs` |
| Coinbase / merged-mining tags | `co.rsk.mine.MinerUtils`, `RskMiningConstants` | `crates/execution/src/mining/coinbase.rs` |
| Merkle proof | `co.rsk.mine.MerkleProofBuilder` (+ Hop/Genesis variants) | `crates/execution/src/mining/merkle.rs` |
| Uncle selection | `co.rsk.core.bc.SelectionRule`, `MiningMainchainView` | `crates/execution/src/mining/uncles.rs` |
| Fork-detection data | `co.rsk.mine.ForkDetectionDataCalculator` | `crates/execution/src/mining/fork_detection.rs` |
| Work submission RPC | `co.rsk.rpc.modules.mnr.MnrModule` | `crates/rpc/src/mnr.rs` |

### Storage and pruning

| | rskj | rustock |
|---|---|---|
| Block store | `org.ethereum.db.IndexedBlockStore` | `crates/storage/src/lib.rs` (`BlockStore`) |
| Receipt store | `org.ethereum.db.ReceiptStore` | `crates/storage/src/lib.rs` (`CF_RECEIPTS`) |
| State pruning / GC | `co.rsk.core.bc.GarbageCollector`, `co.rsk.trie.MultiTrieStore` | `crates/storage/src/epoch_store.rs` |

The epoch design is **rskj's, not an invention**: `MultiTrieStore.collect`
saves the oldest trie worth keeping into the second-to-last epoch, disposes
the last, and rotates. `epoch_store.rs` follows it. Worth saying because the
shape looks unusual next to a conventional reference-counted pruner, and the
reason it is that shape is that rskj chose it first.
| Block pruning | (none — rskj keeps all blocks) | `crates/storage/src/pruner.rs` |
| Position markers | `KEY_HEAD`-equivalents scattered across `BlockChainImpl` | `crates/storage/src/position.rs` (`Transition`, `Validated`) |

### JSON-RPC

| | rskj | rustock |
|---|---|---|
| Dispatch | `org.ethereum.rpc.Web3Impl`, `co.rsk.rpc.netty.JsonRpcWeb3ServerHandler` | `crates/rpc/src/server.rs` |
| HTTP transport | `co.rsk.rpc.netty.Web3HttpServer` (Netty) | `crates/rpc/src/server.rs` (axum) |
| `eth_*` | `co.rsk.rpc.modules.eth.EthModule` | `crates/rpc/src/eth.rs`, `call.rs`, `tx.rs` |
| `eth_getLogs`, filters | `org.ethereum.rpc.Web3Impl` + `co.rsk.logfilter.*` | `crates/rpc/src/logs.rs`, `crates/core/src/bloom.rs` |
| WebSocket transport | `co.rsk.rpc.netty.Web3WebSocketServer`, `RskWebSocketJsonRpcHandler` | `crates/rpc/src/ws.rs` |
| `eth_subscribe` | `co.rsk.rpc.modules.eth.subscribe.*` (`EthSubscribeRequest`, `LogsNotificationEmitter`, `BlockHeaderNotificationEmitter`) | `crates/rpc/src/subscribe.rs` |
| Chain event fan-out | `org.ethereum.listener.EthereumListener` + `CompositeEthereumListener` | `crates/core/src/events.rs` (one typed channel) |
| `debug_*` | `co.rsk.rpc.modules.debug.DebugModuleImpl` | `crates/rpc/src/debug.rs` |
| `trace_*` | `co.rsk.rpc.modules.trace.TraceModuleImpl`, `TraceTransformer` | `crates/rpc/src/trace.rs` |
| `txpool_*` | `co.rsk.rpc.modules.txpool.TxPoolModuleImpl` | `crates/rpc/src/txpool.rs` |
| `rsk_*` | `co.rsk.rpc.modules.rsk.RskModuleImpl` | `crates/rpc/src/rsk.rs` |
| `mnr_*` | `co.rsk.rpc.modules.mnr.MnrModuleImpl` | `crates/rpc/src/mnr.rs` |
| `sco_*` | `Web3Impl.sco_*` over `PeerScoringManager` | `crates/rpc/src/sco.rs` |
| VM tracing | `org.ethereum.vm.trace.*` (`DetailedProgramTrace`, `ProgramTraceProcessor`) | `crates/execution/src/tracer.rs` |

---

## rskj components with no rustock counterpart

Split by *why*, because the three kinds call for different responses.

### Genuine gaps

Three entries left this table. On 2026-09-25: **WebSocket RPC and
`eth_subscribe`** (#121, closed by #123 — `crates/rpc/src/ws.rs` and
`subscribe.rs`) and the per-block half of the **log bloom index** (#122,
#124); what remains of the second is the grouped range index, kept below.
On 2026-09-26: **snapshot sync** (#84), now in `crates/sync/src/snap/` on
both sides — see the Sync table.

| rskj | classes | what is missing |
|---|---|---|
| **Grouped log bloom index** | `co.rsk.logfilter.BlocksBloomStore`, `BlocksBloom`, `BlocksBloomProcessor` | rskj keeps one ORed bloom per *group* of blocks, so a wide `eth_getLogs` can discard a whole group with one test. rustock tests each block's own header bloom (#124) — same answers, one read per block rather than per group. The grouped index needs new storage and a confirmation-depth invariant; **issue #122** stays open for it. |
| **Metrics and profiling** | `co.rsk.metrics.profilers.*`, `co.rsk.metrics.jmx.*`, `HashRateCalculator` | No JMX, no profiler hooks, no hash-rate estimate. rustock has structured `tracing` logs and periodic summaries instead, which is not the same thing for an operator with a dashboard. |
| **Parallel transaction execution** | `co.rsk.core.bc.ParallelizeTransactionHandler`, `ReadWrittenKeysTracker` | RSKIP144. Testnet-only today (`reed810`), so not a mainnet consensus gap — but it becomes one the day it activates. Tracked as **issue #48**. |
| **Union Bridge** | `co.rsk.peg.union.*` (`UnionBridgeSupport`, `UnionBridgeStorageProvider`), ~10 Bridge methods | RSKIP502, also `reed810`/testnet-only. rustock's Bridge table has no union methods at all. The largest *unfiled* gap; see the note below. |

### Deliberately not ported

| rskj | classes | why not |
|---|---|---|
| Wallet / account management | `co.rsk.core.Wallet`, `co.rsk.rpc.modules.personal.*` | A node should not hold keys. `eth_sendTransaction`, `eth_sign` and `personal_*` answer as unsupported; sign externally and use `eth_sendRawTransaction`. |
| Solidity compiler | `org.ethereum.solidity.*`, `eth_compileSolidity` | Removed from Ethereum's own API years ago. |
| Test-only state control | `co.rsk.core.SnapshotManager`, `co.rsk.rpc.modules.evm.*` (`evm_snapshot`, `evm_revert`, `evm_increaseTime`) | Regtest conveniences that let an RPC caller rewrite chain state. |
| Network state export | `co.rsk.core.NetworkStateExporter` | A debug dump of the whole state as JSON. rustock's `dump_state` / `diff_state` diagnostics cover the same need read-only. |
| DI container | `co.rsk.RskContext` (~2,000 lines of wiring) | Rust builds the object graph in `crates/cli/src/main.rs` directly. |

### Structural differences, not gaps

- **Composable validation rules.** rskj's ~25 `*Rule` classes compose through
  `BlockCompositeRule`; rustock states the same rules as functions in
  `crates/core/src/validation/`. Same rules, no object graph.
- **Sync state classes.** rskj has a class per sync state
  (`DownloadingHeadersSyncState`, `FindingConnectionPointSyncState`, …);
  rustock has one `SyncState` enum and a single `tick`. That was deliberate —
  the transitions are the part that has broken repeatedly, and an enum makes
  the whole set readable in one place.
- **Listeners.** rskj's `EthereumListener` fan-out (`org.ethereum.listener.*`)
  is an interface with a dozen methods and a dozen implementors. rustock calls
  the two consumers that matter (`GasPriceTracker`, the peg-out watcher)
  directly from the execution path, so "a block was executed" and "the tracker
  saw it" cannot drift apart, and has **one typed channel**
  (`crates/core/src/events.rs`) for the one consumer that genuinely needs
  fan-out: `eth_subscribe`. It lives in `core` because the sync service
  publishes and the RPC layer consumes and neither crate depends on the
  other.

---

## rustock components with no rskj counterpart

These are not ports. Several exist *because* rustock is a second
implementation and needs to prove it agrees with the first.

| rustock | files | what it is |
|---|---|---|
| **Whole-chain replay** | `crates/cli/examples/replay_bench.rs`, `replay_block.rs`, `diff_roots.rs` | Re-executes mainnet block by block and compares each state root against the header. The instrument the whole port rests on — it turns "we believe this matches rskj" into a measurement, and found Bridge divergences no unit test would have. rskj has no need for it. |
| **Coherence invariants** | `crates/sync/src/invariant.rs` | Eight stated relations (I1–I8) over the node's three position markers, checked after every commit. Four are now *repaired* automatically, not only reported. rskj has no equivalent assertion layer. |
| **Position transitions** | `crates/storage/src/position.rs` | `Transition` / `Validated`: the three position markers can only move through one type that writes them in a single batch. rskj writes its equivalents from many places. |
| **Rollback as a pure function** | `crates/sync/src/rollback.rs` | `choose_resume_point` and `fork_point`, simulated over thousands of generated chains (`crates/storage/tests/position_simulator.rs`). |
| **Typed chain-event channel** | `crates/core/src/events.rs` | One `broadcast` channel with two variants, replacing rskj's `EthereumListener` interface. Bounded per subscriber, and a consumer that falls behind is disconnected rather than silently skipped. |
| **Φ progress watchdog** | `crates/sync/src/watchdog.rs` | A progress measure with an escalation ladder, for the node that believes it is syncing and is not. |
| **Supply conservation** | `crates/execution/src/supply.rs` | Per-block and per-transaction check that execution did not create rBTC from nothing. A bug that mints rBTC would otherwise be invisible — state roots would agree with an rskj carrying the same bug. |
| **Block pruning** | `crates/storage/src/pruner.rs` | rskj keeps all blocks. rustock can delete headers, bodies, receipts and index entries below a floor. |
| **rskj database import** | `crates/storage/src/rskj_import.rs` | Reads a running rskj node's RocksDB and converts it to rustock's layout. |
| **Segmented trie tooling** | `crates/storage/src/trie_tool.rs`, `cli/examples/build_segments.rs`, `audit_chunk.rs` | Splits the trie into self-contained, independently readable chunks. |
| **Bridge event index** | `crates/execution/src/bridge/events.rs` + `cli/examples/bridge_events.rs` | Peg activity queryable by height and type rather than by re-scanning receipts. |
| **Alerting** | `crates/alerts/` | Peg-outs above a threshold, and node health: stalled, behind, or ahead of every peer. Emails. |
| **Read-only diagnostics** | `crates/cli/examples/` (38 tools, 17 read-only) | `resume_point`, `height_peek`, `diff_state` and friends, openable against a live or wedged production database with no lock and no WAL replay. |
| **The compatibility catalogue** | `docs/` (33 documents) | Every place rustock had to reproduce something that is in no specification, with rskj source citations. |

---

## Where to look when you want to change X

| you want to change | start at |
|---|---|
| what a Bridge method returns | `crates/execution/src/bridge/mod.rs` dispatch table, then `getters.rs` or `peg.rs` |
| an opcode's gas or semantics | `crates/execution/src/rsk_instructions.rs` |
| when a fork activates | `crates/execution/src/hardfork.rs` |
| a validation rule | `crates/core/src/validation/` |
| an RPC answer's shape | the namespace file in `crates/rpc/src/`, then `docs/rskj-vs-geth.md` |
| how sync decides what to do next | `crates/sync/src/service.rs` — one `tick`, one `SyncState` |
| what a peer's misbehaviour costs | `crates/networking/src/scoring.rs` |
| a wire message | `crates/networking/src/protocol/rsk.rs` |
| what a subscriber is pushed | `crates/rpc/src/subscribe.rs`, then `docs/websocket-subscriptions.md` |

And before changing anything that touches consensus: `docs/consensus-port-log.md`
records what was already found the hard way, and whole-chain replay is how you
find out whether you broke it.
