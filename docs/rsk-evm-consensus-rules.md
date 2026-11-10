# The RSK EVM: where its consensus rules differ from Ethereum's

A statement of the rules themselves — what any node must do to stay on the
network — organised by the part of the system they affect. It names no client
implementation. Where a rule is surprising, the evidence for it is a mainnet
block, cited by number.

Every rule links to the reference implementation's source at a **pinned
revision**, so line numbers and code remain meaningful:

> **rskj pinned revision:** [`3dc9d977228d938385f0ee7e025162da5c220f1b`](https://github.com/rsksmart/rskj/tree/3dc9d977228d938385f0ee7e025162da5c220f1b)
> (2026-09-09). Links below resolve against that commit, not against `master`.

Two bodies of material feed this document. The design intent and the
chain-level comparison come from **"Similarities and Differences between RSK
and Ethereum"** (Sergio Demian Lerner, Jan 2021,
[Medium](https://medium.com/rootstock-tech-blog/similarities-and-differences-between-rsk-and-ethereum-e480655eff37)).
The consensus-level rules come from replaying mainnet. Where the 2021 article
has been overtaken by a later upgrade, this document says so and gives the
current state — those points are marked **"since 2021"**.

This is a **view over** a larger catalogue, not a replacement for it. Each
entry carries a `§` into:

- [`design-divergences.md`](design-divergences.md) — deliberate, by design
- [`quirks-frozen-bugs.md`](quirks-frozen-bugs.md) — accidental, frozen by history
- [`quirks-java-artifacts.md`](quirks-java-artifacts.md) — artifacts of the reference implementation's language and libraries
- [`rskip-spec-vs-rskj-code.md`](rskip-spec-vs-rskj-code.md) — where the RSKIPs and the deployed code disagree
- [`java-compatibility.md`](java-compatibility.md) — the § index across all of them

If an entry here and the catalogue disagree, **the catalogue is right**: it is
derived from mainnet replay, this is a summary of it.

---

## 0. The rule that generates most of the others

**RSK adopts EVM changes per-RSKIP, never by importing an Ethereum fork.**

An Ethereum hard fork is a bundle. RSK takes individual items out of those
bundles, at heights of its own, and leaves the rest. Gas costs in particular
are **fork-independent constants**: they do not change when a network upgrade
activates unless an RSKIP says so.

The consequence for an implementer: you cannot map an RSK upgrade onto an
Ethereum spec and inherit its behaviour. Every such mapping is an
approximation, and the places it is wrong are consensus failures. The table
below is a statement about *opcode availability*, not about gas schedules.

| Upgrade | Mainnet block | Closest Ethereum spec | What RSK actually took |
|---|---|---|---|
| genesis | 0 | Byzantium | REVERT, STATICCALL, RETURNDATASIZE |
| orchid | 729,000 | Byzantium | RSK-specific only |
| wasabi100 | 1,591,000 | Byzantium | RSKIP125 created-contract nonce |
| twoToThree | 2,018,000 | Byzantium | RSKIP150 (call-depth 400) |
| papyrus200 | 2,392,700 | Petersburg | SHL/SHR/SAR, CREATE2, CHAINID, SELFBALANCE |
| iris300 | 3,614,800 | Petersburg | RSKIP171, RSKIP197 |
| hop400 | 4,598,500 | Petersburg | RSK-specific only |
| fingerroot500 | 5,468,000 | Petersburg | RSK-specific only |
| arrowhead600 | 6,223,700 | Istanbul | **EIP-2028 only** |
| arrowhead631 | 6,549,300 | Istanbul | RSK-specific only |
| lovell700 | 7,338,024 | Shanghai | PUSH0, initcode metering, TLOAD/TSTORE/MCOPY |
| reed800 | 8,052,200 | Shanghai | RSK-specific only |
| vetiver900 | 8,804,200 | Shanghai | RSK-specific only |

**Source:** [`ActivationConfig.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/config/blockchain/upgrades/ActivationConfig.java),
[`ConsensusRule.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/config/blockchain/upgrades/ConsensusRule.java)

---

## 1. Chain parameters

These are the differences a user or an integrator meets first.

| | Rootstock | Ethereum mainnet |
|---|---|---|
| Block interval | **~30 seconds** | ~12 seconds |
| Block gas limit | **6,800,000** | ~30,000,000 |
| Native currency | **rBTC**, pegged 1:1 to BTC | ether |
| Total supply | **21,000,000 rBTC** | no fixed cap |
| Chain ID | **30** (mainnet), **31** (testnet) | 1 |
| Consensus | merge-mined with Bitcoin | proof of stake |
| Address checksum | **EIP-1191** (chain-ID-salted) | EIP-55 |
| BIP-44 coin type | **137'** mainnet, **37310'** testnet | 60' |

**Minimum gas price is a consensus field, negotiated by miners.** Each block
header carries `minimumGasPrice`, and a miner may move it by at most **1% per
block** relative to the parent. A transaction below the block's minimum is not
valid in it. Ethereum has no equivalent; EIP-1559's base fee is algorithmic,
not miner-negotiated, and RSK did not adopt EIP-1559 at all (§4).

**Source:** [RSKIP09](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP09.md) ·
[Rootstock docs: gas](https://dev.rootstock.io/concepts/rbtc/gas/)

**Addresses are the same 20 bytes as Ethereum's, but the checksum differs.**
RSK implements [EIP-1191](https://eips.ethereum.org/EIPS/eip-1191), which
salts the checksum with the chain ID, so the same 20 bytes checksum
differently on RSK mainnet, RSK testnet and Ethereum. A checksum validator
that assumes [EIP-55](https://eips.ethereum.org/EIPS/eip-55) will reject valid
RSK addresses. Replay protection is
[EIP-155](https://eips.ethereum.org/EIPS/eip-155) as usual.

**Source:** [Rootstock docs: account-based addresses](https://dev.rootstock.io/concepts/account-based-addresses/) ·
[RSKIP57](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP57.md) (testnet derivation path)

**Merge mining.** Blocks are secured by Bitcoin miners; a valid RSK block
header carries a Bitcoin proof of work. The PoW rules changed at orchid
(#729,000): RSKIP92 fixed the merged-mining proof, RSKIP98 removed fallback
mining, RSKIP97 removed the 10-minute difficulty reset.

**Source:** [RSKIP92](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP92.md) ·
[RSKIP98](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP98.md) · §7

---

## 2. Consensus, mining and block rewards

| | Rootstock | Ethereum (1.0, pre-Merge) |
|---|---|---|
| Consensus | DECOR+ variation of Nakamoto, **merge-mined with Bitcoin** | Nakamoto (PoW), now proof of stake |
| Sibling blocks | **GHOST**; reward shared between siblings at the same height | uncles paid by minting new coins |
| Block subsidy | **none** — RSK cannot mint bitcoin | inflationary subsidy |
| Reward payment | **smoothed**, matured over 4,000 blocks | immediate |
| Difficulty adjustment | **1/400 per block** | 1/2048 per block |
| Difficulty bomb | **none** | present until the Merge |
| Uncle rate | ~1 per block is normal | ~4% is healthy |

**There is no block subsidy, so miners earn only transaction fees** — and fees
are not paid to the miner directly. Every block's **last transaction is a call
to the REMASC precompile**, which pays each miner 10% of their accumulated
share per block from a shared account, with a **maturity of 4,000 blocks**.

This is a deliberate defence. Without a subsidy, a chain whose fees are paid
immediately to the block's own miner invites *fee sniping* — mining a sibling
of a high-fee block rather than a child of it. Smoothing rewards across
siblings and over time removes the incentive. It also means **`COINBASE` and
the fee recipient are different addresses** (§5), because the two roles were
separated by design rather than by accident.

Uncles are frequent **on purpose**: RSK does not want Bitcoin miners pressed
to rebuild a block template every time an RSK block appears, so it tolerates
siblings and shares the reward among them. RSK targets a *block density*
including uncles, so the observed interval depends on the uncle rate —
absent uncles the chain produces a block about every 15 seconds.

**Source:** [RSKIP77](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP77.md)
(a smoother difficulty algorithm, proposed and never adopted) ·
[article §Consensus, §Uncles Per Block, §Block Difficulty Adjustment, §Block Transactions and REMASC]

### Proof of work is Bitcoin's, and that changes what a block hash means

An RSK block's proof of work lives in an attached **Bitcoin** header, not in
the RSK header. The consequences are concrete:

- **The RSK block hash does not commit to any proof of work.** A smart
  contract using `BLOCKHASH` as a randomness source is therefore far cheaper
  to manipulate than the same pattern on Ethereum. **Do not use `BLOCKHASH`
  for randomness on RSK.** The article puts Ethereum's cost to cheat at
  roughly $4,000 per query, against roughly $200,000 for querying Bitcoin
  block hashes through the Bridge oracle.
- **The proof is larger but cheaper to check** — about 500 bytes, verifiable
  inside a smart contract, with no multi-gigabyte dataset. That is what makes
  FlyClient-style light clients and decentralised bridges practical, where
  Ethash's memory-hard verification did not.

**Source:** [article §BLOCKHASH as a source of cryptoeconomic randomness, §Block Proof of Work Computation]

---

## 3. The block header

Fields 1–13 are identical to Ethereum's: `parentHash`, `unclesHash`,
`coinbase`, `stateRoot`, `txTrieRoot`, `receiptTrieRoot`, `logsBloom`,
`difficulty`, `number`, `gasLimit`, `gasUsed`, `timestamp`, `extraData`.
After that they diverge completely:

| # | Ethereum | Rootstock |
|---|---|---|
| 14 | `mixHash` | `paidFees` |
| 15 | `nonce` | `minimumGasPrice` |
| 16 | `baseFee` (EIP-1559) | `uncleCount` |
| 17 | — | `ummRoot` |
| 18 | — | `bitcoinMergedMiningHeader` |
| 19 | — | `bitcoinMergedMiningMerkleProof` |
| 20 | — | `bitcoinMergedMiningCoinbaseTransaction` |

- **`paidFees`** — total fees paid by the block's transactions, in BTC wei.
- **`minimumGasPrice`** — §1's miner-voted floor.
- **`ummRoot`** — root of a tree referencing other merge-mined chains, for the
  Universal Merge Mining subsystem.
- The three `bitcoinMergedMining*` fields carry the Bitcoin proof of work: the
  header, the Merkle inclusion proof of the Bitcoin coinbase transaction, and
  the tail of that coinbase carrying the `RSKBLOCK:` tag.

`mixHash` and `nonce` are Ethash artifacts with no RSK equivalent; `baseFee`
has no equivalent because EIP-1559 was not adopted (§4).

**Source:** [article §Block Header, §Universal Merge Mining (UMM) subsystem in RSK]

---

## 4. Gas schedule

**These constants never change, at any height.** In the reference
implementation they are `static final` fields of a single class, which is why
no fork repriced them.

| | RSK | Ethereum, post-repricing |
|---|---|---|
| `SLOAD` | 200 | 800 (EIP-1884) |
| `BALANCE` | 400 | 700 (EIP-1884) |
| `EXTCODEHASH` | 400 | 700 (EIP-1884) |
| `EXTCODECOPY` base | 700 | 100 + cold surcharge (EIP-2929) |
| `SELFDESTRUCT` | 5,000 flat | varies |
| `SELFDESTRUCT` refund | **24,000, forever** | 0 (EIP-3529) |
| new-account surcharge | 25,000 | 25,000, gated on `value > 0` |

**Source:** [`GasCost.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/GasCost.java) · §53, §68 · [article §EVM Similarities and Differences]

**SSTORE keeps Petersburg metering forever.** No
[EIP-2200](https://eips.ethereum.org/EIPS/eip-2200), no
[EIP-3529](https://eips.ethereum.org/EIPS/eip-3529):

```
old == none  && new != 0  ->  20,000
old != none  && new == 0  ->   5,000  + 15,000 refund
otherwise                 ->   5,000
```

There is **no `gasleft <= 2300` reentrancy sentry**, and the refund cap is
Petersburg's, not London's `gas_used / 5`.

**Source:** [`VM.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/VM.java) `doSSTORE` · §53, §68, §71

**[EIP-2929](https://eips.ethereum.org/EIPS/eip-2929) was never adopted.** No
access list, no cold/warm distinction, no surcharge on `SLOAD`, `BALANCE`,
`EXTCODE*`, `CALL`, or a cold `SELFDESTRUCT` beneficiary.
*(§68, §72, §73 — evidence #7,403,649, #7,515,160)*

**[EIP-150](https://eips.ethereum.org/EIPS/eip-150)'s 63/64 gas retention was
never adopted.** A caller may hand a callee *all* of its remaining gas:
`calleeGas = min(remaining, requested + stipend)`. On Ethereum a caller always
retains 1/64, which is why its effective call depth is an emergent
consequence of the gas limit rather than a number.

Two consequences follow, and both are visible to users:

- **The call-stack limit is a fixed 400** (§6), not an indirect limit. There
  is no 1/64 retention to exhaust, so the depth has to be bounded explicitly.
- **`eth_estimateGas` can be exact in a single execution.** Ethereum's
  estimators binary-search the gas limit, executing the transaction around 24
  times, because the 1/64 rule makes the outcome non-monotonic in the limit.
  RSK can detect the `calleeGas == remainingGas` case directly and answer with
  `gasUsed + deductedRefund` after one run.

**Source:** [`rsk_instructions.rs`](../crates/execution/src/rsk_instructions.rs),
[`gas_estimator.rs`](../crates/execution/src/gas_estimator.rs) ·
[article §EVM Similarities and Differences]

**[EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) was never adopted.** No
base fee, no burn. Gas price is governed by §1's miner-negotiated minimum.

**The one Istanbul gas change RSK took** is
[EIP-2028](https://eips.ethereum.org/EIPS/eip-2028) at arrowhead600
(#6,223,700): non-zero calldata drops from 68 to 16 gas per byte. Nothing else
from Istanbul came with it.

**Source:** [RSKIP400](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP400.md) · §53

**Why none of the repricing EIPs were adopted.** Ethereum reprices I/O-heavy
opcodes at most upgrades — EIP-150, EIP-1884, EIP-2200, EIP-2035, EIP-2929,
EIP-2930 — to keep gas tracking real resource cost. RSK's stated alternative
is **storage and access rent charged at the storage-cell level**, which makes
periodic repricing unnecessary and addresses the underlying resource-exhaustion
risk directly. The costs also differ in fact: operations that are slow on an
Ethereum node can be fast on RSK, `EXTCODESIZE` being the article's example,
so inherited Ethereum prices would not have matched RSK's real costs anyway.

**Source:** [article §EVM Similarities and Differences]

> Evidence blocks: #7,338,024 (lovell700 activation), #7,388,594 (SELFDESTRUCT
> refund — exactly 24,000 gas of divergence), #7,403,649, #7,515,160.

---

## 5. Account existence, and the absence of EIP-161

**RSK has no [EIP-158](https://eips.ethereum.org/EIPS/eip-158)/[EIP-161](https://eips.ethereum.org/EIPS/eip-161).
Existence in the state trie is the only test; emptiness is not a concept.**

This is the most consequential difference from a modern EVM, because it
changes the *meaning* of several opcodes rather than their price.

- **The 25,000 new-account surcharge is charged on trie existence, with no
  value condition.** A `CALL` or `SELFDESTRUCT` targeting an account that
  exists but is empty (`nonce=0, balance=0, no code`) is **not** charged. Such
  accounts genuinely occur: a miner paid a zero reward, or an account
  re-created after a same-block self-destruct. *(§38)*
- **`EXTCODEHASH` keys on existence too.** Not in the trie → `0`. In the trie
  with no code → `keccak256("")`. Any active precompile → `keccak256("")`,
  without consulting state. *(§45,
  [RSKIP169](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP169.md))*
- **A zero-value transfer creates the recipient.** Paying an account 0 writes
  a node for it. This is how empty accounts come to exist. *(§13)*
- **Empty accounts are never swept.** Nothing removes them.

**Source:** [`MutableRepository.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/db/MutableRepository.java) `isExist` ·
[`VM.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/VM.java) `doSUICIDE`, `doEXTCODEHASH`

**Self-destructed accounts are deleted at the end of the destroying
transaction, not the end of the block.** A later transaction in the same block
sees the address as nonexistent — and, by the rules above, can re-create it as
a fresh empty account.

**Source:** [`TransactionExecutor.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/core/TransactionExecutor.java) `finalization` · §30

**Contract nonce.** From wasabi100 (#1,591,000) a contract created by the
`CREATE`/`CREATE2` **opcode** starts at nonce 1. A contract created by a
top-level **creation transaction** is unaffected and starts at 0.

**Source:** [RSKIP125](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP125.md) ·
[`Program.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/program/Program.java) `createContract` · §15

**A storage-root marker (`0x01` at `accountKey || 0x00`) is written only for
genuine contract setups** — a creation transaction with non-empty data, or a
successful `CREATE`/`CREATE2`. An empty-data creation transaction does not
write it. The marker is part of the state root, so getting this wrong forks
the state without any opcode behaving differently. *(§10, §10a)*

---

## 6. Call semantics

**The call-stack limit is 400, not 1024**, from twoToThree (#2,018,000,
RSKIP150). On exceeding it the call pushes `0`, refunds the requested child
gas, and returns.

**Source:** [`Program.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/program/Program.java) `getMaxDepth` · §27 · evidence #2,814,761

**Return-data buffer semantics changed at iris300 (#3,614,800).** A genuine
rule change, not a correction:

- **Before:** a call-family instruction that resolves *without running
  anything* — empty-code callee, depth limit, insufficient endowment — leaves
  the **previous** call's return data in the buffer.
  [EIP-211](https://eips.ethereum.org/EIPS/eip-211) clears on every
  call-family instruction; RSK did not. *(§26)*
- **From iris300:** such a call **clears** the buffer. *(§37,
  [RSKIP171](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP171.md))*

**A nested `CREATE`/`CREATE2` constructor's gas refund is discarded.** A
`CALL` merges the child frame's future refund into its parent; a `CREATE` does
not. Refunds earned inside a constructor invoked by the create *opcode* are
lost. *(§65 — evidence #6,362,186)*

**A failing precompile call changed at iris300.** Before: the exception
propagates out of the calling frame, the caller halts exceptionally and
consumes all remaining gas, and nothing is pushed. After: the failure is
handled — `0` is pushed and surplus gas refunded.

**Source:** [RSKIP197](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP197.md) · §40

---

## 7. Block and transaction context

**`COINBASE` returns the block header's miner address — not the gas-fee
recipient.** RSK credits transaction gas fees to the REMASC contract
(`0x0000000000000000000000000000000001000008`), which distributes rewards
later with delayed maturity. The two roles are distinct, and a node that
conflates them forks the first time any contract reads `block.coinbase`.
*(§46)*

**`CHAINID` and `SELFBALANCE` exist from papyrus200** (#2,392,700, RSKIP152
and RSKIP151) at their canonical tiers — 2 and 5 gas — with none of Istanbul's
repricing. Before papyrus200 both are **invalid opcodes**, consuming the
frame's entire gas.

**Source:** [RSKIP152](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP152.md) · §24 · evidence #2,430,894

**Transient storage and `MCOPY` exist from lovell700** (#7,338,024): `TLOAD`
(0x5c), `TSTORE` (0x5d), `MCOPY` (0x5e). These are Ethereum *Cancun* opcodes
present alongside a Shanghai-era feature set — rule 0 in its purest form.

**Source:** [RSKIP446](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP446.md)
([EIP-1153](https://eips.ethereum.org/EIPS/eip-1153)) ·
[RSKIP445](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP445.md)
([EIP-5656](https://eips.ethereum.org/EIPS/eip-5656)) ·
[RSKIP438](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP438.md) (initcode metering) ·
§69 · evidence #7,338,135

### Opcodes RSK added, then removed

RSK launched with EVM extensions of its own — `DUPN`/`SWAPN` for arbitrary
stack access, `REPLACECODE` for secure code upgrades, `TXINDEX` for linking
events, `SEND` for transfers without callbacks. **They were removed in later
upgrades.** The reason was not technical failure: the Solidity compiler did
not support user-defined opcodes, and the community valued Ethereum
compatibility over the improvements. `TXINDEX` was later re-proposed as a
precompile in
[RSKIP192](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP192.md).

Worth knowing when reading old RSK material or old contracts: these opcodes
appear in historical documentation and are not in the chain today.

**Source:** [article §New RSK opcodes: failures or improvements ahead of time?]

**State is committed per transaction.** Each transaction's writes are visible
to the next within the same block; a reverted transaction's writes never reach
the trie. *(`execution-model.md`)*

---

## 8. Precompiled contracts

RSK implements **all of Ethereum's active precompiles**, and adds its own at
addresses well above Ethereum's range:

| Address | Name | Purpose |
|---|---|---|
| `0x…01000006` | `BRIDGE` | register peg-ins, query Bitcoin headers in the best chain |
| `0x…01000008` | `REMASC` | distribute block rewards; called once per block |
| `0x…01000009` | `HD_WALLET_UTILS` | utilities for Bitcoin Token Offerings |
| `0x…01000010` | `BLOCK_HEADER` | query RSK block headers for the past **4,000 blocks** |
| `0x…01000011` | `ENVIRONMENT` | **since 2021** |
| `0x…01000016` | `SECP256K1_ADD` | **since 2021** |
| `0x…01000017` | `SECP256K1_MUL` | **since 2021** |

`BLOCK_HEADER` matters beyond curiosity: `BLOCKHASH` reaches 256 blocks, which
is not enough for layer-two dispute windows. 4,000 blocks is.

**Since 2021.** The article records BLAKE2F (EIP-152) as the one Ethereum
precompile RSK lacked, "planned for the Iris upgrade". It is **present now**,
and RSKIP552 (vetiver900) further refined its data handling. The last three
RSK precompiles above also postdate the article.

**Source:** [`precompiles.rs`](../crates/execution/src/precompiles.rs) ·
[article §Precompiled Contracts]

---

## 9. World state: the unitrie

Ethereum's world state is **many** tries: one account trie, plus a separate
storage trie per contract, linked by hashes. RSK uses a **single** structure,
the *unitrie*, holding accounts, code and storage cells together.

| | Rootstock (unitrie) | Ethereum |
|---|---|---|
| Structure | one trie | account trie + one storage trie per contract |
| Node arity | **binary** | radix-16 |
| Node types | **one** | three (leaf, extension, branch) |
| Account record | nonce, balance | nonce, balance, storageRoot, codeHash |
| Code | a **child node** of the account | referenced by `codeHash` |
| Storage cells | **child nodes** of the account | a separate trie |
| Key material | address recoverable from the key | key is a hash; preimage lost |

The consequences are structural rather than cosmetic:

- **Deleting a contract is deleting one node.** Its code and every storage
  cell hang below the account node, so they go with it.
- **No `codeHash` or `storageRoot` in the account record**, which the article
  puts at over 50% of account space saved.
- **Keys are recoverable.** A unitrie key is
  `0x00 || keccak(addr)[0:10] || addr` for an account, extended with
  `0x00 || keccak(slot)[0:10] || stripped(slot)` for a storage cell. Only
  **80 bits** of hash are used, purely to randomise tree position; the address
  and slot survive in the clear. Ethereum hashes the key and keeps no
  preimage, so a node needs a separate preimage map to debug.
- **A binary trie with one node type** gives shorter membership proofs and
  simpler verification than radix-16 with three.

This is why the state is amenable to storage rent, parallel execution and
garbage collection — the features §4's gas rationale depends on.

**Source:** [`key_mapper.rs`](../crates/trie/src/key_mapper.rs) ·
[article §World State Storage]

---

## 10. Where the EVM ends and the peg begins

The Bridge at `0x0000000000000000000000000000000001000006` is a precompile, so
its behaviour is EVM behaviour for consensus purposes. It carries a large body
of rules of its own — peg-in classification, federation lifecycle, UTXO
selection, signature handling — which are **not** summarised here; see
`consensus-port-log.md` and the Bridge sections of the catalogue.

Two cross-cutting rules are worth knowing even if you never touch the peg:

- **A Bridge method that throws consumes only its `requiredGas`, not all the
  gas.** Called directly as a transaction it produces a *successful* receipt;
  called internally it is a plain failure. *(§50)*
- **Before RSKIP150, precompile output was written to memory without charging
  for the expansion** — an unbounded, gas-free memory write. *(§16)*

**Source:** [`BridgeSupport.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/co/rsk/peg/BridgeSupport.java) ·
[Rootstock docs: PowPeg](https://dev.rootstock.io/concepts/foundations/)

---

## 11. For implementers

Almost every entry above was discovered by a **mainnet block that diverged**,
not by reading a specification. Several contradict the RSKIPs that nominally
describe them; where the written spec and the deployed behaviour disagree, the
network consented to the behaviour, and a node implementing the document would
fork. Those disagreements are catalogued in
[`rskip-spec-vs-rskj-code.md`](rskip-spec-vs-rskj-code.md).

1. **Do not infer a gas cost from an Ethereum fork.** Treat §2 as fixed data.
2. **Do not implement EIP-161 semantics**, including the parts most EVMs now
   treat as unremarkable — the `value > 0` gate on the new-account charge, and
   emptiness as distinct from nonexistence.
3. **Check behaviour against real blocks.** The evidence cited here is block
   numbers because that is the only form of evidence that settled these
   questions. A rule that looks stricter than the chain it must accept is a
   fork, however well argued.

---

## References

**Reference implementation.** [rsksmart/rskj](https://github.com/rsksmart/rskj),
pinned at [`3dc9d977`](https://github.com/rsksmart/rskj/tree/3dc9d977228d938385f0ee7e025162da5c220f1b).
Files cited above:
[`VM.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/VM.java) ·
[`GasCost.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/GasCost.java) ·
[`Program.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/vm/program/Program.java) ·
[`MutableRepository.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/db/MutableRepository.java) ·
[`TransactionExecutor.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/core/TransactionExecutor.java) ·
[`ConsensusRule.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/config/blockchain/upgrades/ConsensusRule.java) ·
[`ActivationConfig.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/org/ethereum/config/blockchain/upgrades/ActivationConfig.java) ·
[`BridgeSupport.java`](https://github.com/rsksmart/rskj/blob/3dc9d977228d938385f0ee7e025162da5c220f1b/rskj-core/src/main/java/co/rsk/peg/BridgeSupport.java)

**RSKIPs.** [rsksmart/RSKIPs](https://github.com/rsksmart/RSKIPs). Cited and
verified to resolve:
[09](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP09.md) ·
[57](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP57.md) ·
[92](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP92.md) ·
[98](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP98.md) ·
[125](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP125.md) ·
[152](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP152.md) ·
[169](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP169.md) ·
[171](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP171.md) ·
[197](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP197.md) ·
[400](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP400.md) ·
[438](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP438.md) ·
[445](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP445.md) ·
[446](https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP446.md)

RSKIP150, RSKIP151 and RSKIP156 are referenced by the deployed code but have
**no document in the public RSKIPs repository** (checked against all 248 files
in `IPs/`). They are cited here by number only, deliberately without a link.

**EIPs.** [EIP-55](https://eips.ethereum.org/EIPS/eip-55) ·
[EIP-155](https://eips.ethereum.org/EIPS/eip-155) ·
[EIP-158](https://eips.ethereum.org/EIPS/eip-158) ·
[EIP-161](https://eips.ethereum.org/EIPS/eip-161) ·
[EIP-211](https://eips.ethereum.org/EIPS/eip-211) ·
[EIP-1153](https://eips.ethereum.org/EIPS/eip-1153) ·
[EIP-1191](https://eips.ethereum.org/EIPS/eip-1191) ·
[EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) ·
[EIP-1884](https://eips.ethereum.org/EIPS/eip-1884) ·
[EIP-2028](https://eips.ethereum.org/EIPS/eip-2028) ·
[EIP-2200](https://eips.ethereum.org/EIPS/eip-2200) ·
[EIP-2929](https://eips.ethereum.org/EIPS/eip-2929) ·
[EIP-3529](https://eips.ethereum.org/EIPS/eip-3529) ·
[EIP-5656](https://eips.ethereum.org/EIPS/eip-5656) ·
[EIP-150](https://eips.ethereum.org/EIPS/eip-150) ·
[EIP-152](https://eips.ethereum.org/EIPS/eip-152) ·
[EIP-2035](https://eips.ethereum.org/EIPS/eip-2035) ·
[EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)

**Official documentation.**
[Concepts](https://dev.rootstock.io/concepts/) ·
[Account-based addresses](https://dev.rootstock.io/concepts/account-based-addresses/) ·
[Gas](https://dev.rootstock.io/concepts/rbtc/gas/) ·
[rBTC](https://dev.rootstock.io/concepts/rbtc/) ·
[Foundations](https://dev.rootstock.io/concepts/foundations/)

**Primary source for the chain-level comparison.** Sergio Demian Lerner,
["Similarities and Differences between RSK and Ethereum"](https://medium.com/rootstock-tech-blog/similarities-and-differences-between-rsk-and-ethereum-e480655eff37),
RootstockLabs: Research & Technology, 11 January 2021. Sections 1-3 and 8-10
above draw on it directly; citations read `[article §Section]`.

Because it predates several network upgrades, three of its statements have
been overtaken and are corrected in place above: BLAKE2F is now implemented,
three further RSK precompiles exist, and transient storage (EIP-1153) - which
the article lists among the repricing EIPs RSK did not need - was adopted at
lovell700 as RSKIP446. Everything else in it was checked against the current
code and holds.

> Note: the Medium page refuses automated fetches (HTTP 403), so the link
> above will not resolve from a crawler. It opens normally in a browser.
