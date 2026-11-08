# Rustock

> [!WARNING]
> ## ⚠️ Experimental AI-assisted prototype — DO NOT use in production
>
> Rustock is a **prototype** implemented in an **AI-assisted manner**. It should **never be used in production**. The code has **not been reviewed in depth** and has **not been security audited**. It **may — and will — break and contain bugs**.
>
> **Use at your own risk.**

A Rootstock (RSK) full node implementation in Rust. Rustock syncs and validates blocks from the RSK network using Bitcoin merged mining proofs, executes every transaction against an RSK-compatible Unitrie world state, follows the chain tip in real time, and exposes an rskj-compatible JSON-RPC interface with full state, call, and log support.

**Coming from rskj?** [docs/rskj-to-rustock-map.md](docs/rskj-to-rustock-map.md)
maps the two codebases package by package — the rskj class you already know on
one side, the rustock file that answers to it on the other — and lists what
each side has that the other does not.

## Features

- **Full block sync**: Skeleton-based bulk header sync with parallel chunk downloads across multiple peers, followed by block body downloads and real-time tip following via `NewBlockHashes`.
- **EVM execution**: REVM-based block execution pipeline that reproduces RSK semantics — transaction validation, gas accounting, state transitions, receipt generation, and per-block REMASC reward distribution.
- **Unitrie world state**: A from-scratch implementation of RSK's Unitrie (radix-2 binary trie with shared paths and embedded values), including `eth_getProof`-friendly node access, key mapping for accounts/code/storage, and RocksDB-backed persistence with a write cache.
- **All RSK precompiles**: secp256k1 recovery, block header introspection, HD wallet utilities, the BTC–RSK Bridge (two-way peg, federation management, BTC SPV header chain, governance), and REMASC.
- **Consensus validation**: Full verification of Bitcoin merged mining (AuxPow) proofs, difficulty adjustment, gas limits, timestamps, and all RSK consensus rules including activation-height-gated RSKIPs.
- **Chain reorganization**: Detects competing forks, compares total difficulty, and rewrites canonical chain pointers when a heavier fork is found.
- **Transaction pool**: Validates pending transactions against the live state (nonce, balance, intrinsic gas, chain ID), tracks pending nonces per sender, and exposes status to the RPC layer.
- **P2P networking**: Full RLPx encryption (inbound and outbound), Kademlia-based UDP discovery, peer exchange, and persistent node tables.
- **Transaction relay**: Receives transaction messages from peers, validates and admits them to the pool, and rebroadcasts to all other connected peers.
- **Serving peers**: Responds to `BlockHeadersRequest`, `BlockHashRequest`, `SkeletonRequest` and `BodyRequest`, and — for peers that negotiated them — the six snapshot messages and the `rsk/63` extensions.
- **JSON-RPC server**: rskj-compatible HTTP API with `eth`, `net`, `web3`, `rpc`, and `rsk` modules — including state queries, `eth_call` / `eth_estimateGas`, transaction and receipt lookups, log filtering, and persistent filters.
- **Snapshot sync**: Joins the chain by downloading a recent state trie instead of executing from genesis — as a client and as a server. The header chain to the checkpoint is verified first under the same proof-of-work rules as a full sync, and every chunk of state is checked against that chain's state root. Interoperates with rskj in both directions ([docs/cross-client-snap-sync.md](docs/cross-client-snap-sync.md)).
- **Header freezer**: Settled headers, and the uncle headers they reference, move out of RocksDB into append-only files with a fixed-width index, so a run of consecutive blocks is a run of adjacent bytes ([docs/freezer.md](docs/freezer.md)).
- **Block pruning**: Deletes history below a configurable depth, automatically or on request, clamped to a floor the block-info precompiles and reorg re-execution require ([docs/block-pruning.md](docs/block-pruning.md)).
- **Protocol extensions (`rsk/63`)**: Announces the range of blocks this node can serve, and can carry the uncle headers a trunk header references — which is what lets a node compute cumulative work from a header walk, since in RSK uncle difficulty counts toward total difficulty.
- **Storage**: RocksDB-backed persistence for headers, bodies, receipts, total difficulty, canonical chain mappings, Bridge events, and Unitrie nodes.

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (edition 2021)
- RocksDB system libraries (usually handled automatically by `rust-rocksdb`)
- A C/C++ toolchain plus `libclang` — `librocksdb-sys` compiles vendored C++, and
  `zstd-sys` generates its bindings with `bindgen`, which needs `libclang.so` and
  clang's builtin headers at build time:

  ```bash
  # Debian/Ubuntu
  sudo apt install build-essential clang libclang-dev
  # Fedora/RHEL
  sudo dnf install gcc gcc-c++ clang-devel
  # macOS (ships with the Xcode command line tools)
  xcode-select --install
  ```

  If `bindgen` still reports `Unable to find libclang`, point it at the library
  explicitly, e.g. `export LIBCLANG_PATH=/usr/lib/llvm-21/lib`.

### Building

```bash
cargo build --workspace --release
```

### Docker

The `Dockerfile` builds `rustock-cli` on Ubuntu 22.04 (glibc 2.35) with the
toolchain `rust-toolchain.toml` pins, for `linux/amd64` and `linux/arm64`:

```bash
docker build -t rustock .
docker run --rm rustock rustock-cli --help
```

The image has no entrypoint; the binary is `/usr/local/bin/rustock-cli`.

### Running

Start the full node on RSK Mainnet (default):

```bash
cargo run -p rustock-cli --release -- --port 30303 --data-dir ./data --log-to-stdout
```

Logs are written to `<data-dir>/rustock.log` by default (with daily rotation). Use `--log-to-stdout` for console output.

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `30303` | P2P listen port |
| `--data-dir` | `./data` | Data directory for RocksDB and logs |
| `--network-id` | `30` | Network ID (`30` = mainnet, `31` = testnet, anything else = regtest) |
| `--secret-key` | auto-generated | Hex-encoded secp256k1 private key |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn`, `error`, or RUST_LOG-style directives |
| `--log-to-stdout` | `false` | Log to console instead of file |
| `--rpc-port` | `4444` | JSON-RPC HTTP port |
| `--rpc-host` | `127.0.0.1` | JSON-RPC bind address |
| `--no-rpc` | `false` | Disable the JSON-RPC server |
| `--external-ip` | none | External IP to advertise in discovery (e.g. `203.0.113.42`) |

Commonly used beyond the basics:

| Flag | Default | Description |
|------|---------|-------------|
| `--snap-sync` | `false` | Join by downloading a recent state instead of executing from genesis |
| `--snap-server` | `false` | Serve snapshots of this node's state to peers that ask |
| `--prune-blocks` | `false` | Delete block history below `--prune-keep-depth` as the node runs |
| `--prune-keep-depth` | `100000` | Blocks of history to keep; clamped up to 8,000 |
| `--freezer` | `true` | `false` keeps settled headers in RocksDB instead of the freezer |
| `--read-only` | `false` | Open both databases read-only and write nothing |
| `--follow-up` | `true` | `false` serves what is held and does not sync, execute or follow |
| `--mine` | `false` | Build blocks and serve the `mnr_*` merged-mining namespace |
| `--rpc-admin` | `false` | Enable the administrative RPC methods |
| `--bootnodes` | network default | Peers to dial; with `--closed-network`, the only ones |

That is a selection. The node has ~96 flags, every one of them documented with
its default in [`node.example.toml`](node.example.toml), which is the reference
rather than this table. [`node-light.example.toml`](node-light.example.toml) is
a smaller starting point, and [`alerts.example.toml`](alerts.example.toml)
configures peg-out and node-health alerting.

### Testing

```bash
cargo test --workspace
```

786 tests covering consensus validation, RLP encoding, P2P handshakes, sync state machines, storage, the Unitrie, EVM execution, every RSK precompile (including the full Bridge surface and REMASC), the transaction pool, RPC methods, transaction relay, and chain reorganizations.

### Importing from rskj

A synced rskj database can be imported instead of syncing from peers — about an
hour against days. The two schemas differ structurally (rskj uses one RocksDB
per datasource plus a MapDB index; rustock uses one RocksDB with column
families), so this converts rather than copies:

```bash
rustock --import-rskj /path/to/database/mainnet --data-dir ./data
rustock --metadata-in-memory --data-dir ./data
```

See [`docs/rskj-import.md`](docs/rskj-import.md) for the schema comparison, all
options, and measured performance. [`tools/dump-index`](tools/dump-index) is a
companion Java tool for reading rskj's MapDB index directly, used as an
independent cross-check.

### A regtest chain rskj runs

rustock's regtest is its own chain: its own genesis, no Bridge federation, and
gas limits of its own. To run the chain an rskj regtest node runs, so that
blocks rskj mined connect here, start from rskj's genesis file and its rules:

```bash
rustock --network-id 33 \
  --genesis genesis.json \
  --consensus-rule rskip97=0 \
  --min-gas-limit 3000000 --max-gas-limit 18446744073709551615 \
  --skip-pow-validation
```

`--genesis` takes an rskj genesis JSON file and gives the genesis rskj gives
it, hash included, along with rskj's regtest federation. `--consensus-rule` is
rskj's `blockchain.config.consensusRules` (today `rskip97`), and
`--skip-pow-validation` is its `miner.server.skipPowValidation`, for chains
mined without real merged mining. `--hardfork name=height` is rskj's
`blockchain.config.hardforkActivationHeights`, by rskj's names. The same
settings go in a `[chain]` section of the `--config` file. All of them are
refused on mainnet and testnet.

`--allow-chain-overrides` lifts that refusal for everything but `--genesis`,
for a copy of mainnet or testnet run under rules the chain has not activated
(blocks mined on a snapshot of mainnet's state with reed810 scheduled, say):

```bash
rustock --network-id 30 --allow-chain-overrides \
  --hardfork reed810=9002504 --hardfork tbd1000=9002504 \
  --consensus-rule rskip351=9002504 --consensus-rule rskip535=9002504 \
  --skip-pow-validation ...
```

The overrides reach everything that reads the schedule: header decoding and
hashing, difficulty, execution, REMASC and the Bridge. Names the node reads at
one fixed height per chain (`bahamas`, `afterBridgeSync`, `hop401`) are
accepted at that height only; `orchid060` and `tbd1000` are accepted and
change nothing, and the node says so (`tbd1000` only turns on RSKIP-559,
pegout sorting in the Bridge, which it does not implement). A node started
this way must not follow the real network.

Blocks rskj exported with its `ExportBlocks` tool (`number,hash,td,rlp` per
line, plain or gzipped) can then be imported from an empty data directory:

```bash
rustock --network-id 33 --genesis genesis.json ... \
  --trie-backend external --trie-dir ./trie --data-dir ./data \
  --import-blocks blocks.txt --import-flush-every 10
```

Each block goes through the validation and execution follow mode uses, and
its state root, receipts root, logs bloom, gas used and paid fees are checked
against its header. The import stops at the first block that fails, naming
its number, hash and the check, and exits non-zero. The trie is flushed every
`--import-flush-every` blocks (10, rskj's `blockchain.flushNumberOfBlocks`
default).

`--breakdown-log <file>` adds one line per block in the shape of rskj's
`block connect breakdown best:` debug line, so the two clients' timings can be
compared phase by phase:

```
block connect breakdown best: block=15 hash=c06f… totalMs=41.207 preambleMs=0.002
  initialValidationMs=0.311 executeMs=38.950 postExecuteValidationMs=0.004
  switchChainMs=0.402 saveReceiptsMs=0.517 onBestBlockMs=1.021 txCount=21 gasUsed=…
```

(one line in the file). `totalMs` covers the whole import of the block, the
periodic flush included, as rskj's covers its `onBestBlock` flush. Without the
flag no clock is read.

### Dependency Auditing

Supply chain checks run in CI on every push and pull request, and on a daily
schedule so that advisories published against already-pinned dependencies are
caught even when nobody touches the code. To run the same checks locally:

```bash
cargo install cargo-deny --locked
cargo deny check                  # advisories, bans, licenses, sources
```

The policy lives in [`deny.toml`](deny.toml). What it enforces:

- **crates.io only.** Unknown registries and git dependencies are rejected.
  Published crates.io versions are immutable, so together with the checksums in
  `Cargo.lock` a compromised maintainer cannot alter a version already depended
  on — only publish a new one, which the lockfile will not pick up until
  someone deliberately runs `cargo update`.
- **No yanked crates.** A yank usually signals a withdrawn or compromised
  release.
- **No wildcard version requirements**, which would defeat pinning.
- **Known advisories**, with any exception recorded in `deny.toml` alongside the
  reasoning for it.

`Cargo.lock` is committed and must stay that way: it is the primary supply chain
control, and CI verifies it is current (`cargo metadata --locked`) and that every
non-workspace dependency carries a checksum. Treat lockfile diffs as
security-relevant during review — a malicious dependency arrives through
`Cargo.lock`, not through the Rust source.

Prefer `[workspace.dependencies]` when adding a dependency used by more than one
crate, so two crates cannot silently pin different versions of it.

## JSON-RPC API

The RPC server is compatible with rskj's JSON-RPC 2.0 interface. Supported methods:

**Chain and node info:**

- `eth_blockNumber`, `eth_chainId`, `eth_syncing`, `eth_protocolVersion`
- `eth_gasPrice` (a percentile over recent transactions, not the block minimum
  — see [docs/gas-price.md](docs/gas-price.md)), `eth_mining`, `eth_hashrate`,
  `eth_accounts`, `eth_coinbase`
- `eth_getBlockByHash`, `eth_getBlockByNumber`
- `eth_getBlockTransactionCountByHash`, `eth_getBlockTransactionCountByNumber`
- `eth_getUncleCountByBlockHash`, `eth_getUncleCountByBlockNumber`
- `eth_getUncleByBlockHashAndIndex`, `eth_getUncleByBlockNumberAndIndex`
- `net_version`, `net_peerCount`, `net_listening`, `net_peerList`
- `web3_clientVersion`, `web3_sha3`
- `rpc_modules`
- `rsk_protocolVersion`, `rsk_getRawBlockHeaderByHash`, `rsk_getRawBlockHeaderByNumber`

**State queries** (served from the local Unitrie at any historical block):

- `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`

**Execution:**

- `eth_call`, `eth_estimateGas` (run against a forked state with full precompile and Bridge support)

**Transactions and receipts:**

- `eth_sendRawTransaction` (validates against the pool and broadcasts to peers)
- `eth_getTransactionByHash`, `eth_getTransactionByBlockHashAndIndex`, `eth_getTransactionByBlockNumberAndIndex`
- `eth_getTransactionReceipt`

**Logs and filters:**

- `eth_getLogs`
- `eth_newFilter`, `eth_newBlockFilter`, `eth_newPendingTransactionFilter`
- `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter`

**Pool:**

- `txpool_status`, `txpool_content`, `txpool_inspect`

  These follow rskj's `TxPoolModuleImpl`, not go-ethereum's txpool namespace:
  sender keys are bare hex with no `0x`, each nonce maps to an *array* of
  transactions, and `txpool_status` counts are JSON numbers rather than hex
  strings. See [docs/rskj-vs-geth.md](docs/rskj-vs-geth.md).

**Debug:**

- `debug_wireProtocolQueueSize`, `debug_accountTransactionQuota`
- `debug_traceTransaction`, `debug_traceBlockByHash`, `debug_traceBlockByNumber`
  (within the state-retention window)

  rskj's `debug_*`, not go-ethereum's — the two namespaces barely overlap. See
  [docs/debug-namespace.md](docs/debug-namespace.md).

**Trace:**

- `trace_transaction`, `trace_block`, `trace_get`, `trace_filter`
  (within the state-retention window)

  Call trees, in rskj's shape rather than OpenEthereum's — the differences are
  not cosmetic, and precompile calls (the Bridge included) never appear. See
  [docs/trace-namespace.md](docs/trace-namespace.md).

**Peer scoring:**

- `sco_banAddress`, `sco_unbanAddress`, `sco_bannedAddresses`, `sco_peerList`,
  `sco_clearPeerScoring`, `sco_reputationSummary`, plus `sco_isWelcome`

  A port of rskj's `co.rsk.scoring`. Bans persist across restarts, which
  rskj's do not. See [docs/peer-scoring.md](docs/peer-scoring.md).

**WebSocket + subscriptions:**

- `eth_subscribe` / `eth_unsubscribe` over a WebSocket on its own port
  (`--ws`, default port 4445; off by default, as rskj's is). `newHeads`,
  `logs` (with `removed` on a reorg) and `newPendingTransactions`. Every HTTP
  method works over the socket too. See
  [docs/websocket-subscriptions.md](docs/websocket-subscriptions.md).

**Unsupported** (returns error): mining (`eth_sendTransaction`, `eth_sign`, compilers), and the `personal_*`, `evm_*`, `db_*` namespaces.

## Project Structure

```
crates/
  cli/          Main entry point, CLI argument parsing, genesis bootstrap
  core/         Base types (Header, Block, Transaction, Receipt), consensus rules, chain config
  trie/         RSK Unitrie: nodes, paths, account encoding, key mapping
  execution/    EVM executor, block processor, all RSK precompiles, BTC–RSK Bridge, REMASC
  storage/      RocksDB persistence for headers, bodies, receipts, and trie nodes (with write cache)
  networking/   P2P protocol (RLPx, discovery, sessions, peer management)
  sync/         Sync state machine, header + body pipeline, transaction pool, transaction relay
  rpc/          JSON-RPC HTTP server (axum-based) with state, call, log, and filter support
  alerts/       Peg-out and node-health alerting; an observer with no hook in execution or sync
```

### Log timestamps and timezones

Log timestamps are **UTC by default** and RFC 3339 with one subsecond digit,
so the offset travels with every line rather than being something a reader has
to know.

```
--log-timezone utc        # default: 2026-09-25T21:13:45.9+00:00
--log-timezone -03:00     #          2026-09-25T18:13:45.9-03:00
--log-timezone local      # read from the machine, once, at start-up
```

or `timezone` under `[log]` in the config file. The offset is also stated once
at start-up (`Log timestamps are GMT-03:00`), so a log opened later says what
it is in words as well as in every timestamp.

`local` is resolved **once**, before the runtime starts: the `time` crate will
not determine a local offset in a multithreaded process, because another
thread changing `TZ` concurrently is a data race. A consequence is that
`local` does not follow a daylight-saving transition mid-run. A fixed offset
avoids the question, and is exactly right for zones without DST.

Note this is rustock's own timestamp. Under systemd, `journalctl` prints its
own timestamp first, in the *viewer's* timezone — `TZ=America/Argentina/Buenos_Aires journalctl -u rustock`
shifts that one, with no node configuration at all.

## Limitations and Future Work

Rustock executes blocks and maintains full state, but it is not yet feature-complete relative to rskj. Notable gaps:

- **Mining is single-node only.** Rustock builds blocks, serves the `mnr_*` merged-mining namespace and imports solutions (`--mine`, see [docs/merged-mining.md](docs/merged-mining.md)), but it has no outbound block announcement, so a mined block reaches peers only when they ask for it.
- **No archive mode.** The trie store keeps every node it writes, so historical state is queryable as long as the underlying nodes have not been collected, but there is no explicit archive-vs-pruning policy.
- **Bridge methods are complete but unevenly exercised.** All 70 methods in the Bridge table are dispatched, transaction-callable and local-only alike. The transaction-callable ones are proven by whole-chain replay against mainnet; the local-only getters are proven only by unit tests, because mainnet history does not call them.
- **Tracing needs recent state.** `debug_trace*` and `trace_*` re-execute a
  transaction's block from its parent's state, so they answer only within the
  GC burial depth (4,000 blocks by default) and return an error past it.
  `trace_filter` recomputes rather than reading an index, as rskj does.
- **Peer scoring credits blocks on execution, not on arrival.** A body is
  checked against its header the moment it arrives — the only moment the
  sender is unambiguous — and a mismatch is charged as `INVALID_BLOCK` and
  re-fetched from somebody else. `VALID_BLOCK` waits until the block executes
  to the state root its header claims, which is stricter than rskj, whose
  credit comes from validation. See [docs/peer-scoring.md](docs/peer-scoring.md).
- **No wallet / account management.** `eth_sendTransaction`, `eth_sign`, and the `personal_*` namespace are intentionally not supported — sign transactions externally and submit them via `eth_sendRawTransaction`.

## License

MIT
