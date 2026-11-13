//! A raw transaction as rskj's `eth_sendRawTransaction` reads it before its
//! pool sees it, for what rskj answers where it refuses one there
//! (`EthModuleTransactionBase.sendRawTransaction`).
//!
//! rskj makes a `Transaction` of the bytes, asks whether it has a gas limit,
//! and asks whether its signature is one this network takes. Of everything
//! that can go wrong on the way it catches one thing, its decoder's
//! `RLPException`, which it answers -32602 "Invalid input: " and the
//! exception's words. An address of the wrong length is answered by its error
//! resolver, in words made for another method; and whatever else is thrown is
//! an internal error, -32603.
//!
//! What gets through is the pool's to judge, and a transaction the pool
//! refuses is rskj's `transactionError`, -32010, with the pool's reason.

use alloy_primitives::U256;
use rustock_core::rskj_rlp::{decode2, Element, RlpError};

use crate::params::{uncaught, Refusal};
use crate::types::INVALID_PARAMS;

fn invalid(message: String) -> Refusal {
    (INVALID_PARAMS, message)
}

/// What the method answers where its decoder throws: an `RLPException` is
/// caught and reported, anything else is not.
fn unread(error: RlpError) -> Refusal {
    match error.message() {
        Some(message) => invalid(format!("Invalid input: {message}")),
        None => uncaught(),
    }
}

/// The chain a signature's `v` names (`Transaction.extractChainIdFromV`), in
/// the Java `byte` rskj keeps it in: none for 27 and 28, and otherwise
/// `(v - 35) / 2`, which is below zero for a `v` under 34.
fn chain_named(v: u8) -> i8 {
    match v {
        27 | 28 => 0,
        v => ((i32::from(v) - 35) / 2) as i8,
    }
}

/// A signature's r or s as rskj reads it, `new BigInteger(1, bytes)`, where
/// it fits 256 bits. One that doesn't is past the curve's order.
fn component(bytes: &[u8]) -> Option<U256> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let significant = &bytes[first..];
    (significant.len() <= 32).then(|| U256::from_be_slice(significant))
}

/// `Err` with rskj's answer where it refuses `raw` before its pool sees it.
///
/// `written` is the parameter as the request wrote it, which the answer to a
/// misshapen address counts the characters of. `chain` is this network's
/// chain, or none where the node doesn't know it, and then any chain passes
/// here and the pool decides.
///
/// In rskj's order: the bytes are one RLP list (`RLP.decodeList`) of nine
/// elements; the receiver is no bytes or 20; `v` is absent, for no
/// signature, or one byte, and then r and s are there; the gas limit is
/// there; and the signature is one the network takes
/// (`acceptTransactionSignature`): r from 1 to below the curve's order, s
/// from 1 to below half of it, for no chain or for this one. A signature
/// that isn't is answered "Invalid chainId" and the chain it names, whatever
/// was wrong with it, as a missing one is.
pub fn refused(raw: &[u8], written: &str, chain: Option<u64>) -> Result<(), Refusal> {
    let elements = decode2(raw).map_err(unread)?;
    let [list @ Element::List { .. }] = elements.as_slice() else {
        return Err(uncaught());
    };
    let fields = list.elements().map_err(unread)?;
    let [_nonce, _gas_price, gas_limit, to, _value, _data, v, r, s] = fields.as_slice() else {
        return Err(uncaught());
    };

    // `new RskAddress(bytes)` throws `InvalidRskAddressException`, which
    // `RskErrorResolver` answers for every method alike, by the length of
    // the request's first parameter less every "0x" in it.
    if to.data().is_some_and(|to| to.len() != 20) {
        let length = written.replace("0x", "").encode_utf16().count();
        return Err(invalid(format!(
            "invalid argument 0: hex string has length {length}, want 40 for RSK address"
        )));
    }

    let signature = match v.data() {
        None => None,
        // `ECDSASignature.fromComponents` makes numbers of r and s, and of
        // a missing one a `NullPointerException`.
        Some(&[v]) => match (r.data(), s.data()) {
            (Some(r), Some(s)) => Some((v, r, s)),
            _ => return Err(uncaught()),
        },
        // `TransactionException`, "Signature V is invalid".
        Some(_) => return Err(uncaught()),
    };

    if gas_limit.data().is_none() {
        return Err(invalid(
            "Missing parameter, gasPrice, gas or value".to_string(),
        ));
    }

    let named = match signature {
        None => 0,
        Some((v, r, s)) => {
            let named = chain_named(v);
            let order = U256::from_be_bytes(secp256k1::constants::CURVE_ORDER);
            let in_range = |number: Option<U256>, below: U256| {
                number.is_some_and(|number| !number.is_zero() && number < below)
            };
            let ours = named == 0 || chain.is_none_or(|chain| u64::try_from(named) == Ok(chain));
            if ours && in_range(component(r), order) && in_range(component(s), order >> 1) {
                return Ok(());
            }
            named
        }
    };
    Err(invalid(format!("Invalid chainId: {named}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The chain a `v` names, in Java's arithmetic: its division rounds
    /// toward zero, so 34 to 36 name none, and what is under 34 names a chain
    /// below zero.
    #[test]
    fn a_v_names_its_chain_as_java_reckons_it() {
        for (v, chain) in [
            (27, 0),
            (28, 0),
            (0, -17),
            (26, -4),
            (33, -1),
            (34, 0),
            (36, 0),
            (37, 1),
            (95, 30),
            (101, 33),
            (102, 33),
            (255, 110),
        ] {
            assert_eq!(chain_named(v), chain, "v {v}");
        }
    }
}
