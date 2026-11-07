# rskj tests and their rustock counterparts

One row per rskj test in the consensus packages, with one of three verdicts: **covered**
(the rustock test that asserts the same behaviour), **not applicable** (why rustock needs no
such test), or **gap** (no rustock test; the last column says whether the code has the
behaviour anyway). A gap whose code check found the behaviour missing or different is an
issue; the ones found on 2026-10-30 are filed in rsk-clients-lab's `docs/issues/`.

Why this table exists: two bugs found by rsk-clients-lab on 2026-10-29 (the miner and the
RSKIP252 cap; `eth_gasPrice` and the fee-market gate) each had an rskj test naming the missing
behaviour, in a class other than the one the port had sliced on. Neither shows on mainnet or
regtest, so syncing cannot catch this kind of gap. The test names can.

rskj at e507f45; rustock at the commit this file first appears in. Test methods counted by
`@Test`, `@ParameterizedTest` and `@RepeatedTest` annotations. The mapping was done by reading
each rskj test body and searching rustock by rule name, RSKIP number and the rskj class name
(many rustock tests cite it); the code checks on gaps were then re-verified by hand for the
consensus rules. Keep the table current: a port that adds a test flips its row to covered.

| package | tests | covered | not applicable | gap |
|---|---:|---:|---:|---:|
| `co.rsk.validators` | 77 | 42 | 8 | 27 |
| `co.rsk.mine` | 110 | 54 | 7 | 49 |
| `co.rsk.net.handler.txvalidator and org.ethereum.facade` | 24 | 13 | 5 | 6 |
| total | 211 | 109 | 20 | 82 |

Gaps where the code differs from rskj, in order of weight:

1. RSKIP179, the Bitcoin-to-RSK timestamp link, was not enforced (`BlockTimeStampValidationRuleTest`); fixed the same day, `BitcoinTimestampRule`.
2. The future-timestamp bound was 15 s on every chain; rskj uses 60 s on mainnet, 540 s on testnet and none on regtest. The minimum gas limit was 5,000 against rskj's 3,000,000. Both fixed the same day.
3. A pending transaction the EVM refused aborted the whole template instead of being dropped and evicted (`BlockToMineBuilderInvalidTxEvictionTest`), and the miner never consulted sync state (`MinerManagerTest.mineBlockWhileSyncingBlocks`). Both fixed the same day.
4. Pool admission lacked the 80x per-transaction price cap, the sublist gas limit under RSKIP144, the canonical-nonce check and the free-bridge exemption (`co.rsk.net.handler.txvalidator`). Fixed the same day; the sublist bound is tested at `gas_limit_is_bounded_by_the_larger_sublist_under_rskip144`.
5. Miner behaviours rskj had and rustock did not: submission rate limit, duplicate submission answered OK, template rebuilt on new block and new transactions, the extraData format, the minimum gas price target, eviction of underpriced transactions. All six fixed the same day.

## co.rsk.validators

Paths: rskj tests `rskj-core/src/test/java/co/rsk/validators/`; rustock files relative to the rustock checkout (`crates/...`). `tests.rs` = `crates/core/src/validation/tests.rs`, `block_rules.rs` = `crates/core/src/validation/block_rules.rs`, `header_rules.rs` = `crates/core/src/validation/header_rules.rs`.

| rskj test | verdict | rustock test or reason | code check (gaps only) |
|---|---|---|---|
| BlockDifficultyRuleTest.validWhenCalculatedDifficultyMatches | covered | `test_difficulty_rule` (tests.rs) | |
| BlockDifficultyRuleTest.invalidWhenCalculatedDifficultyDoesntMatch | gap | no rustock test asserts `DifficultyMismatch` | implemented: `crates/core/src/validation/difficulty.rs:16-24` returns `DifficultyMismatch` when `header.difficulty != expected` |
| BlockDifficultyValidationRuleTest.testDifficulty | covered | `test_difficulty_rule`, `test_difficulty_equal_timestamps_increases` (tests.rs; regtest +1/2048 step) | |
| BlockParentGasLimitRuleTest.cantConstructRuleWithZeroGasLimitBoundDivisor | not applicable | Java constructor arg check; rustock divisor is a config constant (1024, `crates/core/src/config.rs:188`) | |
| BlockParentGasLimitRuleTest.cantConstructRuleWithNegativeGasLimitBoundDivisor | not applicable | same; `u64` cannot be negative | |
| BlockParentGasLimitRuleTest.validityWhenGas | covered | `test_gas_limit_rule` (tests.rs; same, +delta ok, +delta+1 rejected) | |
| BlockParentNumberRuleTest.isValid | covered | `test_block_number_rule` (tests.rs) | |
| BlockRootValidationRuleTest.validBlockPasses | covered | `test_process_block_validates_tx_root` (crates/execution/src/processor.rs) | |
| BlockRootValidationRuleTest.calculatedRootMatchesHelperForBothFlags | covered | `the_derived_body_matches_the_committed_transactions_root` (crates/core/src/types/transaction.rs) + processor tx-root test | |
| BlockRootValidationRuleTest.replacedTransactionsListInvalidatesCachedRoot | not applicable | Java `Block` cached-root invalidation; rustock recomputes the root each time (`processor.rs:833`) | |
| BlockRootValidationRuleTest.mismatchedHeaderRootIsRejected | covered | `test_process_block_validates_tx_root` (processor.rs:2489, asserts `TransactionsRootMismatch`) | |
| BlockTimeStampValidationRuleTest.timestampsAreCloseEnough | covered | `timestamps_are_close_enough` (tests.rs), with `bitcoin_timestamp_is_not_checked_before_rskip179`, `a_header_without_a_decodable_bitcoin_header_fails_rskip179`, `testnet_widens_the_window_from_rskip297` | |
| BlockTimeStampValidationRuleTest.blockInThePast | covered | `block_in_the_past` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockInTheFutureLimit | covered | `block_in_the_future_limit` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockInTheFuture | covered | `block_in_the_future` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockTimeLowerThanParentBlockTime | covered | `block_time_against_the_parents` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockTimeLowerThanParentBlockHeaderTime | covered | `block_time_against_the_parents` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockTimeGreaterThanParentBlockTime | covered | `block_time_against_the_parents` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockTimeGreaterThanParentBlockHeaderTime | covered | `block_time_against_the_parents` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockTimeEqualsParentBlockTime | covered | `block_time_against_the_parents` (tests.rs) | |
| BlockTimeStampValidationRuleTest.blockTimeEqualsParentBlockHeaderTime | covered | `block_time_against_the_parents` (tests.rs) | |
| BlockTxsMaxGasPriceRuleTest.isValid_whenRskip252DisabledThenBlockValidRegardlessGasPrice | covered | `block_txs_max_gas_price_enforces_the_100x_cap_from_rskip252` (block_rules.rs; pre-fingerroot500 block accepted) | |
| BlockTxsMaxGasPriceRuleTest.isValid_whenRskip252EnabledThenBlockInvalidDueToTxWithMoreGasPriceThanCap | covered | same test (10_001 > 100x100 rejected) | |
| BlockTxsValidationRuleTest.validNonceSame | gap | no block-level nonce test | implemented via revm: `execute_tx_inner` runs the default revm handler (`crates/execution/src/executor.rs:335-430`), whose state validation rejects `NonceTooLow/NonceTooHigh`; the `EVMError` is mapped at `executor.rs:422` to `ExecutionError::Evm` and surfaces as `ProcessError::Execution` (`processor.rs:22`), failing the block. No `disable_nonce_check` anywhere in `crates/execution` |
| BlockTxsValidationRuleTest.invalidNonceLower | gap | same | implemented (same path; revm `NonceTooLow`) |
| BlockTxsValidationRuleTest.invalidNonceHigher | gap | same | implemented (same path; revm `NonceTooHigh`) |
| BlockTxsValidationRuleTest.validTransactionsWithSameNonceAndDifferentSenders | gap | same | implemented (per-sender account nonce in revm state) |
| BlockTxsValidationRuleTest.validConsecutiveTransactionsFromSameSender | gap | same (closest: `test_rskj_nonce_tracking_across_block`, crates/execution/src/executor.rs, which checks nonce bump not rejection) | implemented: sender nonce bumped per tx (`executor.rs:1650`), next tx validated against it |
| BlockTxsValidationRuleTest.invalidTransactionsFromSameSenderWithSkippedNonce | gap | same | implemented (second tx fails revm `NonceTooHigh`) |
| BlockTxsValidationRuleTest.invalidTransactionsWithSameNonceAndSameSender | gap | same | implemented (second tx fails revm `NonceTooLow`) |
| BlockUnclesValidationRuleTest.rejectBlockWithSiblingUncle | gap | no unit test of `UnclesValidationRule` (`crates/core/src/validation/uncles.rs`); no test references `UncleIsSiblingOrDescendant` | implemented: `uncles.rs:131-133` `if uncle.number >= number -> UncleIsSiblingOrDescendant`; also `uncles.rs:155-159` rejects an uncle whose parent is not an ancestor (the sibling's parent *is* block1, so rejection comes from the number check). Note: the processor wires the rule with EMPTY `header_rules`/`parent_rules` (`crates/execution/src/processor.rs:689-696`) whereas rskj runs `BlockHeaderCompositeRule`/`BlockHeaderParentCompositeRule` on each uncle; only the sync path (`crates/sync/src/uncle_guard.rs:166-172`) passes the verifier's rules |
| BlockUnclesValidationRuleTest.rejectBlockWithUncleHavingHigherNumber | gap | same | implemented: `uncles.rs:131-133` (`uncle.number >= number`) |
| ExtraDataRuleTests.blockWithValidExtraData | covered | `extra_data_rule_caps_at_32_bytes` (block_rules.rs) | |
| ExtraDataRuleTests.blockWithValidNullExtraData | not applicable | `extra_data` is a non-null `Bytes` in rustock; empty bytes trivially pass `header_rules`/`block_rules.rs:125` | |
| ExtraDataRuleTests.blockWithValidLongerExtraDataThanAccepted | covered | `extra_data_rule_caps_at_32_bytes` (33 bytes -> `ExtraDataTooLarge`) | |
| ForkDetectionDataRuleTest.validForBlocksBeforeRskip110UsingMethodThatReceivesBlockAsParameter | gap | no test calls `fork_detection::validate` (only the calculator is tested: `fork_detection_data_*` in crates/execution/src/mining/tests.rs) | implemented: `crates/core/src/validation/fork_detection.rs:102-104` returns `Ok` when `header.number < rskip110_height` |
| ForkDetectionDataRuleTest.validForBlocksBeforeRskip110 | gap | same | implemented: `fork_detection.rs:102-104` |
| ForkDetectionDataRuleTest.invalidForRskip110ActiveButForkDetectionData | gap | same | implemented: `fork_detection.rs:109-114` (number < 449 and `Some(data)` -> `ForkDetectionDataUnreadable`) |
| ForkDetectionDataRuleTest.validForRskip110ActiveButNoForkDetectionDataBecauseNoEnoughBlocksToCalculateIt | gap | same | implemented: `fork_detection.rs:109-114` (`None` -> Ok). Minor edge: rskj validates only when `449 < number` (`ForkDetectionDataRule.java` `requiredBlocks < header.getNumber()`), rustock validates when `number >= 449`, so block 449 itself differs; unreachable on mainnet/testnet since RSKIP110 activates far later |
| ForkDetectionDataRuleTest.invalidForRskip110ActiveAndForkDetectionDataButMissingBlocksForCalculation | gap | same | implemented: `fork_detection.rs:117-121` (short view -> `calculate` returns `None` -> `ForkDetectionDataUnreadable`) |
| ForkDetectionDataRuleTest.validForRskip110ActiveAndForkDetectionData | gap | same | implemented: `fork_detection.rs:116-126` (expected == got -> Ok) |
| ForkDetectionDataRuleTest.invalidForRskip110ActiveAndForkDetectionDataBecauseDataDoesNotMatch | gap | same | implemented: `fork_detection.rs:123-125` -> `ForkDetectionDataMismatch` |
| GasLimitRuleTests.gasLimitGreaterThanMinimumGasLimit | covered | `gas_limit_greater_than_minimum_gas_limit` (tests.rs) | |
| GasLimitRuleTests.gasLimitEqualMinimumGasLimit | covered | `gas_limit_equal_minimum_gas_limit` (tests.rs) | |
| GasLimitRuleTests.gasLimitLessThanMinimumGasLimit | covered | `gas_limit_less_than_minimum_gas_limit` (tests.rs) | |
| PrevMinGasPriceValidatorTest.noParentBlock | not applicable | rustock's `ParentHeaderValidator` always receives a parent; a missing parent is rejected earlier by the sync pipeline | |
| PrevMinGasPriceValidatorTest.genesisBlock | gap | `prev_min_gas_price_allows_one_percent_either_way` does not cover number 0 | implemented: `block_rules.rs:166-168` returns Ok for `header.number == 0` |
| PrevMinGasPriceValidatorTest.noMinGasPrice | not applicable | `minimum_gas_price` is a non-null `U256` in rustock | |
| PrevMinGasPriceValidatorTest.outOfValidMGPRangeBlock | covered | `prev_min_gas_price_allows_one_percent_either_way` (block_rules.rs; 989/1011 rejected around 1000) | |
| PrevMinGasPriceValidatorTest.validMGPInNewBlock | covered | same test (1050 vs parent 1000 is outside +1%, rejected like 1011) | |
| RemascValidationRuleTest.noTxInTheBlock | covered | `remasc_rule_requires_remasc_as_the_last_transaction` (block_rules.rs; empty block err) | |
| RemascValidationRuleTest.noRemascTxInTheBlock | covered | same (absent case) | |
| RemascValidationRuleTest.remascTxIsNotTheLastOne | covered | same (misplaced case) | |
| RemascValidationRuleTest.remascTxInBlock | covered | same (ok case) | |
| TxGasPriceCapTest.isSurpassed_whenMinGasPriceIsZeroThenFalseRegardlessTxGasPrice | covered | `block_txs_max_gas_price_enforces_the_100x_cap_from_rskip252` (zero_min case), FOR_BLOCK only; FOR_TRANSACTION (txpool cap) is outside this package's consensus scope | |
| TxGasPriceCapTest.isSurpassed_whenRemascTransactionThenFalseRegardlessTxGasPrice | gap | the max-gas-price test's `remasc_tx()` has gas price 0, so the exemption is never exercised | implemented: `block_rules.rs:84-86` skips `is_remasc_tx` before the cap compare |
| TxGasPriceCapTest.isSurpassed_whenLessThanCapThenFalse | covered | same test (at_cap ok implies below-cap ok; `>` compare at `block_rules.rs:87`) | |
| TxGasPriceCapTest.isSurpassed_whenEqualsCapThenFalse | covered | same test (at_cap = 10_000 accepted) | |
| TxGasPriceCapTest.isSurpassed_whenMoreThanCapThenTrue | covered | same test (10_001 rejected) | |
| TxsMinGasPriceValidatorTest.blockWithEmptyTxList | covered | `txs_min_gas_price_rejects_an_underpriced_tx` (only_remasc case; loop over zero user txs) | |
| TxsMinGasPriceValidatorTest.blockWithNullMGP | not applicable | `minimum_gas_price` is non-null `U256` | |
| TxsMinGasPriceValidatorTest.blockWithAllValidTx | covered | same test (ok case) | |
| TxsMinGasPriceValidatorTest.blockWithAllInvalidTx | covered | same test (99 < 100 -> `TxGasPriceBelowMinimum`) | |
| TxsMinGasPriceValidatorTest.blockWithSomeInvalidTx | covered | same test (first-failing-tx rejects the block, `block_rules.rs:45`) | |
| ValidGasUsedValidatorTest.blockWithValidGasUsed | covered | `test_gas_used_rule` (tests.rs) | |
| ValidGasUsedValidatorTest.blockWithInvalidGasUsedBiggerThanGasLimit | covered | `test_gas_used_rule` (110 > 100 -> `GasUsedExceedsLimit`); also `test_rskj_invalid_block_bad_gas_used` (processor.rs) | |
| ValidGasUsedValidatorTest.blockWithInvalidGasUsedLessThanZero | not applicable | `gas_used` is `u64`; negative is unrepresentable (RLP decode of a negative is impossible) | |
| ValidTxExecutionSublistsEdgesTest.blockWithRSKIP144Deactivated | covered | `before_activation_anything_is_accepted` (block_rules.rs) | |
| ValidTxExecutionSublistsEdgesTest.blockWithValidEdges | covered | `two_ascending_in_bounds_edges_are_valid` | |
| ValidTxExecutionSublistsEdgesTest.blockWithEmptyEdges | covered | `empty_edges_are_valid` | |
| ValidTxExecutionSublistsEdgesTest.blockWithTooManyEdges | covered | `more_edges_than_execution_threads_is_rejected` | |
| ValidTxExecutionSublistsEdgesTest.blockWithOutOfBoundsEdgesBecauseOfRemascTx | covered | `an_edge_at_the_transaction_count_is_out_of_bounds` | |
| ValidTxExecutionSublistsEdgesTest.blockWithOutOfBoundsEdges | covered | `an_edge_past_the_transaction_list_is_rejected` | |
| ValidTxExecutionSublistsEdgesTest.blockWithNegativeEdge | covered | `a_negative_edge_is_rejected` | |
| ValidTxExecutionSublistsEdgesTest.blockWithEdgeZero | covered | `a_first_edge_of_zero_is_rejected` | |
| ValidTxExecutionSublistsEdgesTest.blockWithRepeatedEdge | covered | `a_repeated_edge_is_rejected` | |
| ValidTxExecutionSublistsEdgesTest.blockWithEdgesNotInOrder | covered | `edges_out_of_order_are_rejected` | |

## co.rsk.mine

Paths: rustock = `clients/rustock`, `tests.rs` = `crates/execution/src/mining/tests.rs`, `template.rs` = `crates/execution/src/mining/template.rs`, `server.rs` = `crates/execution/src/mining/server.rs`, `executor.rs` = `crates/execution/src/executor.rs`, `rpc tests` = `crates/rpc/src/tests.rs`.

| rskj test | verdict | rustock test or reason | code check (gaps only) |
|---|---|---|---|
| AutoMinerClientTest.byDefaultIsDisabled | covered | `a_timed_miner_mines_blocks_on_its_own` (tests.rs) asserts `!is_running()` before start; `starting_twice_runs_one_miner` (rpc tests) | |
| AutoMinerClientTest.minesBlock | covered | `a_pending_transaction_is_mined_without_being_asked` (rpc tests); `a_timed_miner_mines_blocks_on_its_own` (tests.rs) | |
| AutoMinerClientTest.disablesMining | covered | `a_timed_miner_mines_blocks_on_its_own` (tests.rs): stop -> `!is_running()`, no more blocks | |
| BlockToMineBuilderEvictionEndToEndTest.build_whenTxExecutionThrowsError_doesNotPropagateAndEvictsTxFromPool | covered | `build_when_tx_execution_throws_error_does_not_propagate_and_evicts_tx_from_pool` (mining/tests.rs) | |
| BlockToMineBuilderEvictionEndToEndTest.build_afterErrorTxEvicted_subsequentBuildProducesBlockAndIsNotRePoisoned | covered | `build_after_error_tx_evicted_subsequent_build_produces_block_and_is_not_re_poisoned` (mining/tests.rs) | |
| BlockToMineBuilderInvalidTxEvictionTest.build_whenBlockResultHasInvalidTxs_shouldEvictThemFromPool | covered | `build_when_tx_execution_throws_error_does_not_propagate_and_evicts_tx_from_pool` (mining/tests.rs) | |
| BlockToMineBuilderInvalidTxEvictionTest.build_whenBlockResultHasNoInvalidTxs_shouldNotEvictFromPool | covered | `build_when_block_result_has_no_invalid_txs_should_not_evict_from_pool` (mining/tests.rs) | |
| BlockToMineBuilderTest.BuildBlockHasEmptyUnclesWhenCreateAnInvalidBlock | gap | no test for "uncle validation fails -> rebuild without uncles" | NOT implemented / differs: `build_work` (server.rs:426-438) takes `select_uncles` output and `build()` runs only body rules (template.rs:329-336, comment: "ancestry rules (uncles, fork detection) are not run here"); there is no retry without uncles. Mitigated by selection following `FamilyUtils` (uncles.rs:35-55: ancestors, used uncles, generation limit, cap), so an invalid uncle set is unlikely but not guarded. |
| BlockToMineBuilderTest.BuildBlockHasUnclesWhenCreateAnInvalidBlock | covered | `a_losing_sibling_is_selected_as_an_uncle`, `the_uncle_list_is_capped`, `cumulative_difficulty_counts_the_uncles` (tests.rs) | |
| BlockToMineBuilderTest.buildBlockBeforeUMMActivation | covered | `umm_root_appears_once_papyrus_at` -> `umm_root_appears_once_papyrus_is_active` (tests.rs), first assertion (`umm_root.is_none()` before activation) | |
| BlockToMineBuilderTest.buildBlockAfterUMMActivation | covered | `umm_root_appears_once_papyrus_is_active` (tests.rs): `Some(Bytes::new())` after activation; `a_solution_is_imported_with_umm_root_present` | |
| BlockToMineBuilderTest.buildBlockBeforeRskip351 | gap | `a_template_carries_the_header_version_the_chain_activates` only checks version 2 on an all-active chain | implemented: template.rs:302-316 picks version 0 when neither RSKIP351 nor RSKIP535 is active (`version_fields = None`). |
| BlockToMineBuilderTest.buildBlockAfterRskip351 | covered | `a_template_carries_the_header_version_the_chain_activates` (tests.rs) (version 2 on an all-active chain; v1 branch at template.rs:304-305 untested but same ladder) | |
| ForkDataDetectionCalculatorTest.calculateWithMinPossibleBlockchainHeight | covered | `fork_detection_data_commits_to_height_and_uncles` (tests.rs) (length 12, height bytes 8..12, uncle byte) | |
| ForkDataDetectionCalculatorTest.calculateReturnsEmptyWhenNotEnoughBlocks | covered | `fork_detection_data_is_empty_on_a_short_chain` (tests.rs) | |
| ForkDataDetectionCalculatorTest.calculateWithDivisibleBy64height | gap | no test exercises the CPV byte values (height % 64 == 0 case: CPV elements at offsets 63,127,...,446) | implemented: `commit_to_parents_vector` (fork_detection.rs:52-64) is a line-for-line port of rskj (`cpv_start_height`, offset `best - start + i*64`); `bitcoin_hash_least_significant_byte` (fork_detection.rs:68-81) takes `to_byte_array()[0]` = last byte of display hash, same as rskj's `getBytes()[len-1]`. Rustock's fork-detection tests use headers with no BTC header (byte 0), so the CPV content is never asserted. |
| ForkDataDetectionCalculatorTest.calculateWithUnclesOnPreviousBlocks | covered | `fork_detection_data_commits_to_height_and_uncles` (tests.rs): sums only the last 32 blocks' `uncle_count` | |
| ForkDataDetectionCalculatorTest.calculateWithMaxUnclesOnPreviousBlocks | covered | `fork_detection_uncle_count_saturates` (tests.rs): byte 7 saturates at 255 | |
| GasLimitCalculatorTest.NextBlockGasLimitIsDecreasedByAFactor | gap | no test for `next_gas_limit` with a target | differs: this is rskj's `forceTarget=false` path (gas-used driven: `-deltaMax + usedGas*3/2/1024`). rustock `next_gas_limit` (template.rs:715-731) only implements the forced-target step (`target` clamped to parent +/- parent/1024) or inherit (`None`). rskj's default is `forcegaslimit=true` (RskSystemProperties.java:416-418), so the gas-used path is a non-default mode rustock lacks. |
| GasLimitCalculatorTest.NextBlockGasLimitIsNotDecreasedLowerThanMinGasLimit | gap | no test | differs: template.rs:715-731 has no `min_gas_limit` clamp (rskj clamps target to `minGasLimit`, GasLimitCalculator.java). A `gas_limit_target` below `ChainConfig.min_gas_limit` (config.rs:150) would step the header below the minimum and fail `header_rules.rs:100`. Non-default config only. |
| GasLimitCalculatorTest.NextBlockGasLimitIsIncreasedBasedOnGasUsed | gap | no test | differs: gas-used path (forceTarget=false) not implemented, template.rs:715-731. |
| GasLimitCalculatorTest.NextBlockGasLimitIsIncreasedBasedOnFullGasUsed | gap | no test | differs: same, template.rs:715-731. |
| GasLimitCalculatorTest.NextBlockGasLimitIsNotIncreasedMoreThanTargetGasLimit | gap | no test | differs: gas-used path not implemented; the forced path does cap at target (template.rs:727 `target.min(parent + delta)`). |
| GasLimitCalculatorTest.NextBlockGasLimitRemainsTheSame | covered | `a_template_inherits_gas_limit_and_minimum_gas_price` (tests.rs) (parent == target case == inherit) | |
| GasLimitCalculatorTest.NextBlockGasLimitIsIncreasedByMaximumValue | gap | no unit test of the +parent/1024 step | implemented: template.rs:726-727 `target.min(parent_limit + parent_limit/1024)`; consensus side `test_gas_limit_rule` (crates/core/src/validation/tests.rs). |
| GasLimitCalculatorTest.NextBlockGasLimitIsIncreasedToTarget | gap | no test | implemented: template.rs:726-727 (target within one step -> target). |
| GasLimitCalculatorTest.NextBlockGasLimitIsDecreasedToTarget | gap | no test | implemented: template.rs:728-729 `target.max(parent - delta)`. |
| GasLimitCalculatorTest.NextBlockGasLimitIsDecreasedToMinimum | gap | no test | differs: no min clamp, see NotDecreasedLowerThanMinGasLimit (template.rs:715-731). |
| GasLimitCalculatorTest.NextBlockGasLimitIsDecreasedByMaximumValue | gap | no test | implemented: template.rs:728-729 (`parent - parent/1024`, same as rskj deltaMax with bound divisor 1024). |
| MainNetMinerTest.submitBitcoinBlockProofOfWorkNotGoodEnough | covered | `a_solution_that_misses_the_target_is_refused`, `with_pow_validation_an_unsolved_block_is_refused` (tests.rs): `SelfCheck` error, nothing imported | |
| MainNetMinerTest.submitBitcoinBlockInvalidBlockDoesntEliminateCache | gap | `work_handed_out_earlier_can_still_be_answered` and `a_solution_that_misses_the_target_is_refused` each cover half; no test does fail-then-succeed on the same work | implemented: `take_template` (server.rs:661-672) clones from the cache and never removes; a failed `SelfCheck` (server.rs:597-600) returns before any state change, so the template stays answerable. |
| MinerClockTest.timestampForChildIsParentTimestampIfRegtest | not applicable | rskj regtest "fixed clock" (child = parent + adjustment, no wall clock); rustock has no fixed-clock mode: `timestamp_for_child` (template.rs:702-709) always uses wall clock (+ `evm_increaseTime` offset) with `max(parent+1)`. Non-consensus, dev-only semantics. | |
| MinerClockTest.timestampForChildIsClockTimeIfNotRegtest | covered | `a_template_is_never_timestamped_at_or_before_its_parent` (tests.rs) + `timestamp_for_child` = `now.max(parent+1)` (template.rs:707-708) | |
| MinerClockTest.timestampForChildIsTimestampPlusOneIfNotRegtest | covered | `a_template_is_never_timestamped_at_or_before_its_parent` (tests.rs) | |
| MinerClockTest.adjustTimeIfRegtest | not applicable | fixed-clock mode absent (see above); the offset itself is covered by `evm_reset_returns_to_genesis_and_clears_the_clock` (rpc tests) | |
| MinerClockTest.adjustTimeIfNotRegtest | gap | `evm_reset_returns_to_genesis_and_clears_the_clock` (rpc tests) asserts `evm_increaseTime` answers, not that the next block carries the offset | implemented: `dev::increase_time` (crates/execution/src/mining/dev.rs:38-40) adds to `TIME_OFFSET`; `now_with_offset` (dev.rs:54-60) feeds `timestamp_for_child` (template.rs:706). Differs slightly: rskj ignores `seconds <= 0` (MinerClock.java `increaseTime`), rustock applies negative offsets (dev.rs:30-34, deliberate). |
| MinerClockTest.clearTimeIncrease | covered | `evm_reset_returns_to_genesis_and_clears_the_clock` (rpc tests): `time_offset() == 0` after reset | |
| MinerManagerTest.refreshWorkRunOnce | covered | `a_solution_completes_a_block_and_is_imported` (tests.rs); `every_scenario_mines_a_block_this_node_accepts` (workload.rs) | |
| MinerManagerTest.refreshWorkRunTwice | covered | `a_timed_miner_mines_blocks_on_its_own` (tests.rs): consecutive blocks, head advances by `mined` | |
| MinerManagerTest.mineBlockTwiceReusingTheSameWork | covered | `a_repeated_solution_reports_the_block_as_already_present` (tests.rs). Note rskj imports a second sibling block at height 1 (different hash because the BTC solution differs); rustock refuses with `ParentNoLongerHead` (server.rs:570-576) -- deliberate divergence, documented in the test | |
| MinerManagerTest.mineBlockWhileSyncingBlocks | covered | `mine_block_while_syncing_blocks` (mining/tests.rs) | |
| MinerManagerTest.doWork | covered | `a_timed_miner_mines_blocks_on_its_own` (tests.rs); `a_pending_transaction_is_mined_without_being_asked` (rpc tests) | |
| MinerManagerTest.doWorkEvenWithoutMinerServer | not applicable | null-MinerServer wiring (Java null-safety of `MinerClientImpl`); rustock's miner handle is `Option<Arc<..>>` resolved at startup (crates/cli/src/main.rs:3335-3420) | |
| MinerManagerTest.doWorkInThread | covered | `a_timed_miner_mines_blocks_on_its_own` (tests.rs): `is_running()` true after `start()` on its own thread | |
| MinerManagerTest.mineBlock | covered | `a_solution_completes_a_block_and_is_imported`, `a_solution_is_imported_on_a_chain_deep_enough_for_remasc_to_pay` (tests.rs); `evm_reset_returns_to_genesis_and_clears_the_clock` (rpc tests) for the snapshot-reset part | |
| MinerServerTest.buildBlockToMineCheckThatLastTransactionIsForREMASC | covered | `a_template_without_remasc_would_not_validate`, `remasc_transaction_is_recognised_as_remasc` (tests.rs), `the_remasc_transaction_closes_the_sequential_sublist` (partition.rs); `build()` pushes REMASC last (template.rs:191-197) | |
| MinerServerTest.submitBitcoinBlockTwoTags | covered | `compression_picks_the_requested_tag_of_two`, `compression_leaves_the_tag_inside_the_first_tail_block` (crates/core/src/validation/merged_mining.rs); `complete_and_import` uses `compress_coinbase(raw, true)` = last tag (server.rs:580). The "resubmit same PoW for the other header -> ERROR" half maps to `a_repeated_solution_reports_the_block_as_already_present` | |
| MinerServerTest.submitBitcoinBlock | covered | `a_solution_completes_a_block_and_is_imported` (tests.rs): `ImportedBest`, height parent+1 | |
| MinerServerTest.submitBitcoinBlockPartialMerkleWhenBlockIsEmpty | covered | `all_three_submit_forms_accept_the_same_solution` (tests.rs) ("partial" form, coinbase-only block); `a_single_transaction_block_needs_no_proof` | |
| MinerServerTest.submitBitcoinBlockPartialMerkleWhenBlockHasTransactions | covered | `a_partial_merkle_proof_drops_the_coinbase`, `merkle_proofs_fold_back_to_the_root`, `wire_hashes_are_reversed_on_the_way_in` (tests.rs); submit path `submit_bitcoin_block_partial_merkle` (server.rs:543-556) | |
| MinerServerTest.submitBitcoinBlockTransactionsWhenBlockIsEmpty | covered | `all_three_submit_forms_accept_the_same_solution` (tests.rs) ("transactions" form) | |
| MinerServerTest.submitBitcoinBlockTransactionsWhenBlockHasTransactions | covered | `merkle_proofs_fold_back_to_the_root`, `wire_hashes_are_reversed_on_the_way_in`, `a_malformed_wire_hash_is_rejected` (tests.rs) via `proof_from_tx_hashes` (merkle.rs:63) | |
| MinerServerTest.workWithNoTransactionsZeroFees | gap | no test asserts `fees_paid_to_miner == 0` on an empty block (the `fixture(20)` server tests never read the field) | implemented: `fees_paid_to_miner: executed.paid_fees` (template.rs:343) is the executed block's `paid_fees`, zero with only REMASC; reported by `work_to_json` (crates/rpc/src/mnr.rs:108). |
| MinerServerTest.initialWorkTurnsNotifyFlagOn | covered | `a_solution_completes_a_block_and_is_imported` (tests.rs) asserts `work.notify` on first work; `notify_is_reported_once` | |
| MinerServerTest.secondWorkWithNoChangesTurnsNotifyFlagOff | covered | `notify_is_reported_once` (tests.rs); `get_work` clears the flag after one read (server.rs:482-502), `should_notify` (server.rs:469-476) implements the 10% fee threshold | |

## co.rsk.mine (continued)

Paths: rustock = `clients/rustock/crates/...`, rskj = `clients/rskj/rskj-core/src/...`.

| rskj test | verdict | rustock test or reason | code check (gaps only) |
|---|---|---|---|
| MinerServerTest.gasUnitInDollarsIsInitializedOkAtConstructor | gap | (name is misleading: asserts `notify==true` on work rebuilt on a *different parent*). `notify_is_reported_once` (execution/src/mining/tests.rs:917) only checks the first notify and its clearing | implemented: `should_notify` returns true when `last_parent != parent_hash` (execution/src/mining/server.rs:469-476) |
| MinerServerTest.secondBuildBlockToMineTurnsNotifyFlagOff | covered | `second_build_block_to_mine_turns_notify_flag_off` (mining/tests.rs) | |
| MinerServerTest.submitTwoBitcoinBlocksAtSameTimeWithoutRateLimit | covered | `submit_two_bitcoin_blocks_at_same_time_without_rate_limit` (mining/tests.rs) | |
| MinerServerTest.submitTwoBitcoinBlocksAtSameTimeWithRateLimit | covered | `submit_two_bitcoin_blocks_at_same_time_with_rate_limit` (mining/tests.rs) | |
| MinerServerTest.extraDataNotInitializedWithClientData | covered | `extra_data_not_initialized_with_client_data` (mining/extra_data.rs) | |
| MinerServerTest.extraDataWithClientData | covered | `extra_data_with_client_data` (mining/extra_data.rs) | |
| MinerServerTest.extraDataWithClientDataMoreThan32Bytes | covered | `extra_data_with_client_data_more_than_32_bytes` (mining/extra_data.rs) | |
| MinerServerTest.onBestBlockBuildBlockToMine | covered | `on_best_block_build_block_to_mine` (mining/tests.rs) | |
| MinerServerTest.onNewTxBuildBlockToMine | covered | `on_new_tx_build_block_to_mine` (mining/tests.rs) | |
| MinerServerTest.rebuildsOnlyOnceArrivingFeesAreMaterialAgainstTheCandidate | covered | `rebuilds_only_once_arriving_fees_are_material_against_the_candidate` (mining/tests.rs) | |
| MinerServerTest.rebuildsOnEveryBatchWhenThereIsNoCandidateToCompareAgainst | covered | `rebuilds_on_every_batch_when_there_is_no_candidate_to_compare_against` (mining/tests.rs) | |
| MinerServerTest.onNewTxEventsAreThrottledWhenBuildQueueIsBacklogged | not applicable | Java single-thread executor coalescing; rustock has no event-driven rebuild at all (see rows above) | |
| MinerUtilsTest.getAllTransactionsTest | covered | `transactions_are_ordered_by_price_but_never_out_of_nonce_order` (execution/src/mining/tests.rs:658): two txs of one sender both kept, nonce order | |
| MinerUtilsTest.validTransactionRepositoryNonceTest | covered | `filter_transactions_skips_a_sender_past_a_nonce_gap_but_not_past_a_mined_leftover` (tests.rs:733): expected nonce read from state via `nonce_of` | |
| MinerUtilsTest.validTransactionAccWrapNonceTest | covered | same test: nonce 1 then 2 accepted after the in-block `next_nonce` map advances | |
| MinerUtilsTest.invalidNonceTransactionTest | covered | same test: wrong nonce skipped, sender's later txs blocked only by a gap; nothing is evicted | |
| MinerUtilsTest.invalidGasPriceTransactionTest | covered | `invalid_gas_price_transaction_test`, `an_underpriced_pending_transaction_is_evicted` (mining/tests.rs) | |
| MinerUtilsTest.harmfulTransactionTest | not applicable | null gasPrice cannot exist with rustock's `U256` field | |
| MinerUtilsTest.filterTransactions_whenRskip252DisabledThenTxIncludedRegardlessGasPrice | covered | `filter_transactions_when_rskip252_disabled_then_tx_included_regardless_gas_price` (tests.rs:710) | |
| MinerUtilsTest.filterTransactions_whenRskip252EnabledThenTxWithMoreGasPriceThanCapExcluded | covered | `filter_transactions_when_rskip252_enabled_then_tx_with_more_gas_price_than_cap_excluded` (tests.rs:696) | |
| MinerUtilsTest.getAllTransactionsCheckOrderTest | covered | `transactions_are_ordered_by_price_but_never_out_of_nonce_order` + `transaction_ordering_is_stable_for_equal_prices` (tests.rs:658, 677); same-nonce higher-price-first is in `order_by_price_sender_and_nonce` (template.rs:585-589) though not asserted on its own | |
| MinerUtilsTest.getAllTransactions_withNonCanonicalNonce_discardsAndReturnsValidTxs | gap | no miner-level test | implemented at a different layer: a nonce wider than 8 bytes fails RLP decode (`decode_u64_lenient` -> `Overflow`, core/src/rlp_compat.rs:78-80) so it never reaches the pool; leading-zero nonces are deliberately tolerated (rlp_compat.rs:3-5), which rskj's canonical check would discard |
| MinerUtilsTest.getAllTransactions_allValid_noDiscarding | covered | `filter_transactions_skips_a_sender_past_a_nonce_gap_but_not_past_a_mined_leftover` / `transactions_are_ordered_...` (all valid txs kept) | |
| MinimumGasPriceCalculatorTest.increaseMgp | covered | `increase_mgp` (mining/tests.rs) | |
| MinimumGasPriceCalculatorTest.decreaseMGP | covered | `decrease_mgp` (mining/tests.rs) | |
| MinimumGasPriceCalculatorTest.mgpOnRage | covered | `mgp_on_range` (mining/tests.rs) | |
| MinimumGasPriceCalculatorTest.previousMgpEqualsTarget | covered | `previous_mgp_equals_target` (mining/tests.rs) | |
| MinimumGasPriceCalculatorTest.previousValueIsZero | covered | `previous_value_is_zero` (mining/tests.rs) | |
| MinimumGasPriceCalculatorTest.previousValueIsSmallTargetIsZero | covered | `previous_value_is_small_target_is_zero` (mining/tests.rs) | |
| MinimumGasPriceCalculatorTest.cantGetMGPtoBeNegative | covered | `cant_get_mgp_to_be_negative` (mining/tests.rs); the target is unsigned here | |
| SubmissionRateLimitHandlerTest.ofMiningConfig_WhenRateLimitIsZero_ThenHandlerShouldBeDisabled | covered | `of_mining_config_when_rate_limit_is_zero_then_handler_should_be_disabled` (mining/tests.rs) | |
| SubmissionRateLimitHandlerTest.ofMiningConfig_WhenRateLimitIsNegative_ThenHandlerShouldBeDisabled | covered | `of_mining_config_when_rate_limit_is_zero_then_handler_should_be_disabled` (mining/tests.rs); the window is unsigned here | |
| SubmissionRateLimitHandlerTest.ofMiningConfig_WhenRateLimitIsPositive_ThenHandlerShouldBeEnabled | covered | `of_mining_config_when_rate_limit_is_positive_then_handler_should_be_enabled` (mining/tests.rs) | |
| SubmissionRateLimitHandlerTest.isSubmissionAllowed_WhenDisabled_ThenShouldReturnTrue | covered | `is_submission_allowed_when_disabled_then_should_return_true` (mining/tests.rs) | |
| SubmissionRateLimitHandlerTest.isSubmissionAllowed_WhenEnabledAndLimitNotExceeded_ThenShouldReturnTrue | covered | `is_submission_allowed_when_enabled_and_limit_not_exceeded_then_should_return_true` (mining/tests.rs) | |
| SubmissionRateLimitHandlerTest.isSubmissionAllowed_WhenEnabledAndLimitExceeded_ThenShouldReturnFalse | covered | `is_submission_allowed_when_enabled_and_limit_exceeded_then_should_return_false` (mining/tests.rs) | |
| TimedMinerClientMiningTest.minesBlockSuccessfully | covered | `a_timed_miner_mines_blocks_on_its_own` (tests.rs:1901): get work + submit through the server | |
| TimedMinerClientMiningTest.handlesMiningErrorsGracefully | gap | no test that a failing `mine_block` keeps the miner running | implemented: `Err(e) => warn!` and the loop continues (execution/src/mining/timed.rs:296-299) |
| TimedMinerClientMiningTest.stopsMiningWhenStopped | covered | `a_timed_miner_mines_blocks_on_its_own`: `mined()` unchanged 400 ms after `stop()` | |
| TimedMinerClientMiningTest.usesExponentialDistribution | covered | `the_draw_is_exponential`, `the_empirical_median_is_near_the_configured_one` (timed.rs tests) + >=3 blocks in 1.5 s at 100 ms median (tests.rs:1913-1917) | |
| TimedMinerClientSimpleTest.testConstructor | covered | `a_timed_miner_mines_blocks_on_its_own`: `!is_running()` before start (tests.rs:1907) | |
| TimedMinerClientSimpleTest.testStartAndStop | covered | same test (start -> running, stop -> not running) | |
| TimedMinerClientSimpleTest.testMultipleStartStopCycles | gap | no restart test (only start-twice idempotence, tests.rs:1909) | implemented: `start` CAS on `running` (timed.rs:214-220) after `stop` stores false (timed.rs:273). Edge: a restart within one 100 ms sleep slice lets the old thread re-read `running==true` and keep going (timed.rs:231-240 check the shared flag, no per-thread generation) -> two threads |
| TimedMinerClientSimpleTest.testConstructorWithDifferentDurations | not applicable | constructor smoke test; `median()` is a plain getter (timed.rs:200) | |
| TimedMinerClientTest.byDefaultIsDisabled | covered | `a_timed_miner_mines_blocks_on_its_own` (tests.rs:1907) | |
| TimedMinerClientTest.startsMining | covered | same (tests.rs:1908-1910) | |
| TimedMinerClientTest.stopsMining | covered | same (tests.rs:1912-1913) | |
| TimedMinerClientTest.canStartAndStopMultipleTimes | gap | no restart test | see testMultipleStartStopCycles (timed.rs:214-240, 273) |
| TimedMinerClientTest.constructorWithCustomMedianTime | covered | `the_median_of_the_draw_is_the_configured_median`, `the_first_target_sets_the_baseline_and_later_ones_scale_the_median` (timed.rs tests) | |
| TransactionModuleTest.sendTransactionMustNotBeMined | covered | `an_idle_chain_is_not_mined` (rpc/src/tests.rs:5295) + `test_eth_sign_transaction_produces_a_transaction_from_the_sender`; `eth_send_transaction` only relays (rpc/src/sign.rs:77-99), no block without a miner | |
| TransactionModuleTest.sendTransactionMustBeMined | covered | `a_pending_transaction_is_mined_without_being_asked` (rpc/src/tests.rs:5305). Note: rskj autoMine mines inside the RPC call; rustock's `AutoMiner` polls with a 250 ms tick (rpc/src/evm.rs:303-312, cli main.rs) | |
| TransactionModuleTest.sendSeveralTransactionsWithAutoMining | covered | `a_pending_transaction_is_mined_without_being_asked` (one tx -> 1..3 blocks, then idle) | |
| TransactionModuleTest.sendRawTransactionWithAutoMining | covered | `test_eth_send_raw_transaction_with_submitter` + `a_pending_transaction_is_mined_without_being_asked` | |
| TransactionModuleTest.sendRawTransactionWithoutAutoMining | covered | `test_eth_send_raw_transaction_with_submitter` (tx reaches the pool) + `an_idle_chain_is_not_mined` | |
| TransactionModuleTest.testGasEstimation | covered | `the_estimate_covers_the_allowance_a_call_asks_for` and the estimation suite around rpc/src/tests.rs:5515-5700 (CALL-with-value estimate; exact 33264+stipend figure not asserted) | |

## co.rsk.net.handler.txvalidator and org.ethereum.facade

Paths: rskj = `rsk-clients-lab/clients/rskj/rskj-core`, rustock = `rsk-clients-lab/clients/rustock`. Rustock's pool admission is `TransactionPool::validate_tx` at `crates/sync/src/txpool.rs:515-566`; `TRANSACTION_GAS_CAP` at :13; `is_remasc_tx` :859; `intrinsic_gas` :871.

| rskj test | verdict | rustock test or reason | code check (gaps only) |
|---|---|---|---|
| TxValidatorAccountBalanceValidatorTest.validAccountBalance | covered | `test_add_pending_transaction` (txpool.rs:1335; balance >= gasPrice*gasLimit admitted), `test_aggregate_balance_exceeded` (:1642, first tx accepted) | |
| TxValidatorAccountBalanceValidatorTest.invalidAccountBalance | covered | `test_insufficient_balance_rejected` (txpool.rs:1619), `test_null_sender_insufficient_funds` (:1895) | |
| TxValidatorAccountBalanceValidatorTest.balanceIsNotValidatedIfFreeTx | covered | `balance_is_not_validated_if_free_tx` (sync/txpool.rs) | |
| TxValidatorAccountStateValidatorTest.validAccountState | not applicable | `AccountState.deleted` is never set to true anywhere in rskj main code (only `setDeleted` setter exists, AccountState.java:118); rustock's `AccountState` has no such flag | |
| TxValidatorAccountStateValidatorTest.invalidAccountState | not applicable | same: dead flag in rskj, no counterpart in rustock | |
| TxValidatorGasLimitValidatorTest.validGasLimit | covered | every admitted tx (e.g. `test_add_pending_transaction`, gas 21000 <= 8M header limit); note rskj compares to `max(sublistGasLimit)` once RSKIP144+351 are active (TxPendingValidator.java:77-79) while rustock compares to the full `header.gas_limit` (txpool.rs:534-538) -- see Summary | |
| TxValidatorGasLimitValidatorTest.invalidGasLimit | covered | `test_high_gas_limit_rejected` (txpool.rs:1493, 9M > 8M -> `GasLimitExceeded`) | |
| TxValidatorIntrinsicGasLimitValidatorTest.validIntrinsicGasPrice | covered | `test_intrinsic_gas_*` for tx1-tx3 and `valid_intrinsic_gas_price_for_a_free_bridge_tx_with_zero_gas_limit` for tx4 (sync/txpool.rs) | |
| TxValidatorIntrinsicGasLimitValidatorTest.invalidIntrinsicGasPrice | covered | `test_intrinsic_gas_exceeded` (txpool.rs:1630), `test_intrinsic_gas_with_calldata` (:1325, 16/4 per byte), `test_intrinsic_gas_contract_creation` (:1318) | |
| TxValidatorMaximumGasPriceValidatorTest.validate_whenRskip252DisabledThenTxValidRegardlessGasPrice | covered | `validate_when_rskip252_disabled_then_tx_valid_regardless_gas_price` (sync/txpool.rs) | |
| TxValidatorMaximumGasPriceValidatorTest.validate_whenRskip252EnabledThenTxWithMoreGasPriceThanCapInvalid | covered | `validate_when_rskip252_enabled_then_tx_with_more_gas_price_than_cap_invalid` (sync/txpool.rs) | |
| TxValidatorMinimumGasPriceValidatorTest.validMinimumGasPrice | covered | `test_add_pending_transaction` (gas price == header minimum 59_240_000 admitted, txpool.rs:1335/:922), bumped replacements above it (`test_same_nonce_bumped_accepted` :1474) | |
| TxValidatorMinimumGasPriceValidatorTest.invalidMinimumGasPrice | covered | `test_low_gas_price_rejected` (txpool.rs:1608 -> `GasPriceTooLow`); the `null` gas price case is not applicable (U256, cannot be null) | |
| TxValidatorNonceEncodingValidatorTest.validateNonceEncoding | covered | `validate_nonce_encoding` and `a_non_canonical_nonce_is_refused_on_admission` (sync/txpool.rs) | |
| TxValidatorNonceRangeValidatorTest.oneSlotRange | covered | `test_nonce_range_one_slot` (txpool.rs:1696; state nonce 1, slots 1: 0 too low, 1 ok, 2 too high) | |
| TxValidatorNonceRangeValidatorTest.fiveSlotsRange | covered | `test_nonce_range_five_slots` (txpool.rs:2003; 1..=5 ok, 0 and 6 refused) | |
| TxValidatorNonceRangeValidatorTest.illegalAccountSlotsValue_Zero | covered | `illegal_account_slots_value_zero` (sync/txpool.rs), `account_slots_of_zero_are_refused` (cli/main.rs) | |
| TxValidatorNonceRangeValidatorTest.illegalAccountSlotsValue_Negative | not applicable | `account_slots` is `u64`; a negative value cannot be expressed (clap rejects it at parse) | |
| TxValidatorNotNullValidatorTest.nullTx | not applicable | `add_transaction(&[u8])` takes a value, not a nullable reference; undecodable bytes are `PoolError::RlpDecode` (`test_undecodable_transactions_still_count_as_offered`, txpool.rs:1297) | |
| TxValidatorNotNullValidatorTest.tx | not applicable | same | |
| TxValidatorNotRemascTxValidatorTest.remascTx | covered | `test_remasc_tx_rejected` (txpool.rs:1585 -> `IsRemascTransaction`). Note rustock identifies REMASC structurally (to == REMASC addr && zero price/limit/value, txpool.rs:859-867) where rskj uses `instanceof RemascTransaction` | |
| TxValidatorNotRemascTxValidatorTest.commonTx | covered | every admitted tx, e.g. `test_add_pending_transaction` (txpool.rs:1335) | |
| EthereumImplTest.getGasPrice_returns_GasPriceTrackerValue_when_feeMarketWorking_is_true | covered | `test_eth_gas_price_uses_the_tracker` (crates/rpc/src/tests.rs:3546); impl `eth_gas_price` crates/rpc/src/eth.rs:95-110 | |
| EthereumImplTest.getGasPrice_returns_correctedBestBlockValue_when_feeMarketWorking_is_false | covered | `test_eth_gas_price_returns_corrected_best_block_value_when_fee_market_is_not_working` (tests.rs:3561) plus `corrected_minimum_gas_price_truncates_like_rskj` (:3575); multiplier 1.1 const at eth.rs:114 (rskj test uses 1.2 via config; rustock hard-codes rskj's default, not configurable) | |
