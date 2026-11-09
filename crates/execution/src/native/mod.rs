//! rskj's native contracts: HDWalletUtils (0x01000009), BlockHeader
//! (0x01000010) and Environment (0x01000011).
//!
//! rskj writes each one as a `NativeContract`: a list of methods, each a
//! `CallTransaction.Function` with its own gas and its own `execute`. A call
//! goes through three steps, and the rules of each are consensus:
//!
//! 1. `parseData` picks the method by its selector and decodes its arguments
//!    ([`crate::abi`]). A payload of one to three bytes, an empty one (none of
//!    these contracts has a default method), a selector no method has, a
//!    method that is not enabled yet and arguments that do not decode all
//!    leave no call.
//! 2. `getGasForData` is the method's gas, or 0 when there is no call. The
//!    caller charges it before anything runs, and a call that cannot pay it is
//!    out of gas.
//! 3. `execute` runs the method and ABI-encodes its result. It throws when
//!    there is no call, and wherever the method refuses its arguments.
//!
//! What a throw costs depends on who made the call, a transaction or a
//! contract, and on RSKIP197: `RskPrecompileProvider` settles it.

pub(crate) mod block_header;
pub(crate) mod environment;
pub(crate) mod hd_wallet;

use alloy_primitives::Bytes;

/// How a call to a precompile ended, in rskj's terms.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// `execute` returned `output`, and the call cost `gas`: its
    /// `getGasForData`.
    Returned { gas: u64, output: Bytes },
    /// `getGasForData` asked for more gas than the call carries, so nothing
    /// ran.
    OutOfGas,
    /// `execute` threw, and the call cost `gas`: its `getGasForData`, which is
    /// 0 when no method was called.
    Threw { gas: u64, reason: String },
    /// The call has no answer, and its block fails: the node could not read
    /// what the call needs, or rskj can't process the block.
    Fatal(String),
}

/// Why a method did not return.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// rskj's method throws.
    Threw(String),
    /// The node could not read what rskj's method reads.
    Fatal(String),
}

impl Failure {
    pub(crate) fn threw(reason: impl Into<String>) -> Self {
        Failure::Threw(reason.into())
    }
}

/// One of rskj's native contracts.
pub(crate) trait NativeContract {
    /// A method with its arguments decoded.
    type Call;

    /// `parseData` for a payload that has a selector: the method `selector`
    /// names, with `args` decoded, or `None` where rskj finds no call.
    fn parse(&self, selector: [u8; 4], args: &[u8]) -> Option<Self::Call>;

    /// The method's `getGas`. `input` is the whole payload, selector included.
    fn gas(&self, call: &Self::Call, input: &[u8]) -> u64;

    /// The method's `execute`, its result ABI-encoded.
    fn execute(&self, call: Self::Call) -> Result<Vec<u8>, Failure>;
}

/// Calls `contract` with `input` and `gas_limit` as rskj does: parse, charge,
/// execute.
pub(crate) fn call<C: NativeContract>(contract: &C, input: &[u8], gas_limit: u64) -> Outcome {
    // A selector takes four bytes, and none of these contracts has a default
    // method for a payload without one.
    let call = input
        .split_first_chunk::<4>()
        .and_then(|(selector, args)| contract.parse(*selector, args));
    let Some(call) = call else {
        return Outcome::Threw {
            gas: 0,
            reason: "the payload names no method".into(),
        };
    };
    let gas = contract.gas(&call, input);
    if gas > gas_limit {
        return Outcome::OutOfGas;
    }
    match contract.execute(call) {
        Ok(output) => Outcome::Returned {
            gas,
            output: output.into(),
        },
        Err(Failure::Threw(reason)) => Outcome::Threw { gas, reason },
        Err(Failure::Fatal(reason)) => Outcome::Fatal(reason),
    }
}

/// The method `selector` names among a contract's `methods`, each given by
/// its signature.
fn method<M: Copy>(methods: &[(&str, M)], selector: [u8; 4]) -> Option<M> {
    methods
        .iter()
        .find(|(signature, _)| crate::abi::selector(signature) == selector)
        .map(|(_, method)| *method)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A contract whose one method, `f(int256)`, costs its argument and
    /// throws when that is 7.
    struct Probe;

    impl NativeContract for Probe {
        type Call = u64;

        fn parse(&self, selector: [u8; 4], args: &[u8]) -> Option<u64> {
            method(&[("f(int256)", ())], selector)?;
            crate::abi::Args::new(args)
                .int(0)?
                .long_value_exact()?
                .try_into()
                .ok()
        }

        fn gas(&self, call: &u64, _: &[u8]) -> u64 {
            *call
        }

        fn execute(&self, call: u64) -> Result<Vec<u8>, Failure> {
            match call {
                7 => Err(Failure::threw("seven")),
                _ => Ok(vec![1]),
            }
        }
    }

    fn input(n: u64) -> Vec<u8> {
        let mut input = crate::abi::selector("f(int256)").to_vec();
        input.extend_from_slice(&alloy_primitives::U256::from(n).to_be_bytes::<32>());
        input
    }

    #[test]
    fn a_payload_without_a_whole_selector_calls_nothing_and_costs_nothing() {
        for payload in [&[][..], &[1], &[1, 2, 3]] {
            assert!(matches!(
                call(&Probe, payload, 100),
                Outcome::Threw { gas: 0, .. }
            ));
        }
        let unknown = [0xFF; 36];
        assert!(matches!(
            call(&Probe, &unknown, 100),
            Outcome::Threw { gas: 0, .. }
        ));
    }

    #[test]
    fn the_gas_is_charged_before_anything_runs() {
        assert_eq!(call(&Probe, &input(50), 49), Outcome::OutOfGas);
        assert_eq!(
            call(&Probe, &input(50), 50),
            Outcome::Returned {
                gas: 50,
                output: vec![1].into()
            }
        );
    }

    #[test]
    fn a_method_that_throws_still_costs_its_gas() {
        assert_eq!(
            call(&Probe, &input(7), 100),
            Outcome::Threw {
                gas: 7,
                reason: "seven".into()
            }
        );
        // An argument that does not decode is no call at all.
        let seven = input(7);
        assert!(matches!(
            call(&Probe, &seven[..20], 100),
            Outcome::Threw { gas: 0, .. }
        ));
    }
}
