//! Environment (0x01000011, RSKIP203): rskj's `co.rsk.pcc.environment`.

use alloy_primitives::U256;

use super::{Failure, NativeContract};

/// The contract, told how deep in the call stack its caller is.
pub(crate) struct Environment {
    /// The caller's `ProgramInvoke.getCallDeep()`: 0 for the contract a
    /// transaction calls, 1 for a contract that contract calls, and so on.
    /// `None` when a transaction calls Environment itself: rskj then runs it
    /// with no `ProgramInvoke` at all.
    pub(crate) caller_depth: Option<u32>,
}

/// Environment's one method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    /// `getCallStackDepth() returns (uint32)`
    GetCallStackDepth,
}

impl NativeContract for Environment {
    type Call = Call;

    /// The method takes no arguments, so whatever follows its selector
    /// decodes.
    fn parse(&self, selector: [u8; 4], _args: &[u8]) -> Option<Call> {
        super::method(
            &[("getCallStackDepth()", Call::GetCallStackDepth)],
            selector,
        )
    }

    /// `GetCallStackDepth.getGas`: nothing.
    fn gas(&self, _call: &Call, _input: &[u8]) -> u64 {
        0
    }

    /// `GetCallStackDepth.execute`: one more than the caller's depth, or 1
    /// when there is no caller.
    fn execute(&self, call: Call) -> Result<Vec<u8>, Failure> {
        let Call::GetCallStackDepth = call;
        let depth = self.caller_depth.map_or(1, |depth| depth.saturating_add(1));
        Ok(U256::from(depth).to_be_bytes::<32>().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::{call, Outcome};

    fn depth(caller_depth: Option<u32>, input: &[u8]) -> Outcome {
        call(&Environment { caller_depth }, input, 0)
    }

    fn word(n: u64) -> alloy_primitives::Bytes {
        U256::from(n).to_be_bytes::<32>().to_vec().into()
    }

    /// rskj's `NestedCallsStackDepthTest`: a contract the transaction calls
    /// gets 1, and the third contract down a chain gets 3.
    #[test]
    fn the_depth_is_the_callers_plus_one() {
        let selector = crate::abi::selector("getCallStackDepth()");
        for (caller, expected) in [(None, 1), (Some(0), 1), (Some(2), 3)] {
            assert_eq!(
                depth(caller, &selector),
                Outcome::Returned {
                    gas: 0,
                    output: word(expected)
                }
            );
        }
        let mut extra = selector.to_vec();
        extra.extend_from_slice(&[0xFF; 40]);
        assert!(matches!(depth(Some(0), &extra), Outcome::Returned { .. }));
    }

    #[test]
    fn a_payload_that_names_no_method_throws_for_nothing() {
        for payload in [&[][..], &[0xe8, 0xce, 0x22], &[0xDE, 0xAD, 0xBE, 0xEF]] {
            assert!(matches!(
                depth(Some(0), payload),
                Outcome::Threw { gas: 0, .. }
            ));
        }
    }
}
