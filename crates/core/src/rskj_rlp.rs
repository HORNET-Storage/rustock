//! RLP as rskj's `org.ethereum.util.RLP` reads it.
//!
//! rskj's decoder is more lenient than canonical RLP. A long-form length
//! prefix may carry a short length, or leading zeros; a single byte below
//! 0x80 may come as a one-byte string; and a long-form length is built in a
//! Java `int`, so one of more than four bytes wraps instead of failing. A
//! consensus rule that reads bytes as rskj does has to accept what it accepts
//! and refuse what it refuses, so this ports `RLP.decode2`, `decodeElement`
//! and `bytesToLength`, with `RLPItem` and `RLPList`, rather than decoding
//! canonically.

/// Where rskj's decoder throws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlpError;

/// One element, as `RLP.decodeElement` cuts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Element<'a> {
    /// An `RLPItem`: its payload.
    Item(&'a [u8]),
    /// An `RLPList`: its whole encoding, prefix included, and where its
    /// payload starts in it.
    List { encoding: &'a [u8], offset: usize },
}

impl<'a> Element<'a> {
    /// `getRLPData`: none for an empty item, and a list's whole encoding,
    /// which is never empty.
    pub fn data(&self) -> Option<&'a [u8]> {
        let bytes = match *self {
            Element::Item(payload) => payload,
            Element::List { encoding, .. } => encoding,
        };
        (!bytes.is_empty()).then_some(bytes)
    }

    /// A list's elements, decoded as `RLPList.checkElements` decodes them.
    /// An item is refused, where rskj's cast to `RLPList` throws.
    pub fn elements(&self) -> Result<Vec<Element<'a>>, RlpError> {
        match *self {
            Element::List { encoding, offset } => decode2(&encoding[offset..]),
            Element::Item(_) => Err(RlpError),
        }
    }
}

/// `RLP.decode2`: every element from the start of `data` to its end.
pub fn decode2(data: &[u8]) -> Result<Vec<Element<'_>>, RlpError> {
    let mut elements = Vec::new();
    let mut position = 0;
    while position < data.len() {
        let (element, next) = decode_element(data, position)?;
        elements.push(element);
        position = next;
    }
    Ok(elements)
}

/// The first element `RLP.decode2` reads from `data`, and where the next one
/// starts.
pub fn first_element(data: &[u8]) -> Result<(Element<'_>, usize), RlpError> {
    if data.is_empty() {
        return Err(RlpError);
    }
    decode_element(data, 0)
}

/// `RLP.decodeElement`, with its lengths in Java `int`s.
fn decode_element(data: &[u8], position: usize) -> Result<(Element<'_>, usize), RlpError> {
    let b0 = data[position];
    if b0 >= 0xc0 {
        // A list's length counts its prefix too.
        let (length, offset) = if b0 <= 0xf7 {
            (i32::from(b0) - 0xc0 + 1, 1)
        } else {
            let nbytes = usize::from(b0 - 0xf7);
            let offset = 1 + nbytes as i32;
            let payload = bytes_to_length(data, position + 1, nbytes)?;
            (offset.checked_add(payload).ok_or(RlpError)?, offset)
        };
        let ending = (position as i32).checked_add(length).ok_or(RlpError)? as usize;
        if ending > data.len() {
            return Err(RlpError);
        }
        let encoding = &data[position..ending];
        return Ok((
            Element::List {
                encoding,
                offset: offset as usize,
            },
            ending,
        ));
    }
    if b0 == 0x80 {
        return Ok((Element::Item(&[]), position + 1));
    }
    if b0 < 0x80 {
        return Ok((Element::Item(&data[position..=position]), position + 1));
    }
    let (length, offset) = if b0 > 0xb7 {
        let offset = usize::from(b0 - 0xb7) + 1;
        (bytes_to_length(data, position + 1, offset - 1)?, offset)
    } else {
        (i32::from(b0 & 0x7f), 1)
    };
    // The length is never negative here, and rskj's `int` sum overflows only
    // to a negative it refuses: in either case the item runs past the end.
    let from = position + offset;
    let to = from + length as usize;
    if to > data.len() {
        return Err(RlpError);
    }
    Ok((Element::Item(&data[from..to]), to))
}

/// `RLP.bytesToLength`: big-endian in a Java `int`, so a length of more than
/// four bytes keeps only its low 32 bits, and a negative one is refused.
fn bytes_to_length(data: &[u8], position: usize, size: usize) -> Result<i32, RlpError> {
    if position + size > data.len() {
        return Err(RlpError);
    }
    let mut length = 0i32;
    for byte in &data[position..position + size] {
        length = length.wrapping_shl(8).wrapping_add(i32::from(*byte));
    }
    if length < 0 {
        return Err(RlpError);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(data: &[u8]) -> Result<Vec<Option<Vec<u8>>>, RlpError> {
        Ok(decode2(data)?
            .iter()
            .map(|e| e.data().map(<[u8]>::to_vec))
            .collect())
    }

    /// What canonical RLP writes, rskj reads.
    #[test]
    fn canonical_items_and_lists_read_as_written() {
        assert_eq!(items(&[]), Ok(vec![]));
        assert_eq!(items(&[0x05]), Ok(vec![Some(vec![0x05])]));
        assert_eq!(items(&[0x80]), Ok(vec![None]), "an empty item has no data");
        assert_eq!(items(&[0x82, 0xaa, 0xbb]), Ok(vec![Some(vec![0xaa, 0xbb])]));
        assert_eq!(items(&[0x01, 0x02]), Ok(vec![Some(vec![1]), Some(vec![2])]));

        let list = [0xc3, 0x1b, 0x81, 0x80];
        let decoded = decode2(&list).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].data(),
            Some(&list[..]),
            "a list's data is its encoding"
        );
        let inner = decoded[0].elements().unwrap();
        assert_eq!(inner, vec![Element::Item(&[0x1b]), Element::Item(&[0x80])]);
        assert_eq!(inner[0].elements(), Err(RlpError), "an item is no list");
    }

    /// rskj takes what canonical RLP refuses: a byte below 0x80 as a string,
    /// a long-form prefix on a short payload, and a length with leading zeros.
    #[test]
    fn rskj_reads_non_canonical_lengths() {
        assert_eq!(items(&[0x81, 0x05]), Ok(vec![Some(vec![0x05])]));
        assert_eq!(
            items(&[0xb8, 0x02, 0xaa, 0xbb]),
            Ok(vec![Some(vec![0xaa, 0xbb])])
        );
        assert_eq!(
            items(&[0xb9, 0x00, 0x02, 0xaa, 0xbb]),
            Ok(vec![Some(vec![0xaa, 0xbb])])
        );
        let list = [0xf8, 0x02, 0x01, 0x02];
        let decoded = decode2(&list).unwrap();
        assert_eq!(decoded[0].elements().unwrap().len(), 2);
    }

    /// A length is built in a Java `int`: five bytes keep their low four, and
    /// one with the sign bit set is refused.
    #[test]
    fn a_long_length_wraps_and_a_negative_one_is_refused() {
        let wrapped = [0xbc, 0x01, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb];
        assert_eq!(items(&wrapped), Ok(vec![Some(vec![0xaa, 0xbb])]));
        assert_eq!(items(&[0xbb, 0x80, 0x00, 0x00, 0x00]), Err(RlpError));
        assert_eq!(items(&[0xfb, 0x80, 0x00, 0x00, 0x00]), Err(RlpError));
        // A list's length counts its prefix, so a length of -1 would net the
        // five-byte prefix a list of four bytes, and reading would go on to
        // the well-formed list after it. rskj refuses it before that.
        let minus_one = [0xfb, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(items(&minus_one), Err(RlpError));
    }

    /// Anything that runs past the end is refused, an item's length bytes too.
    #[test]
    fn an_overrun_is_refused() {
        assert_eq!(items(&[0x83, 0x01]), Err(RlpError));
        assert_eq!(items(&[0xb9, 0x01]), Err(RlpError));
        assert_eq!(items(&[0xc3, 0x01]), Err(RlpError));
        assert_eq!(items(&[0xf9, 0x00]), Err(RlpError));
        assert_eq!(items(&[0x01, 0x82, 0xaa]), Err(RlpError));
    }

    /// No variation on nested lists makes reading them, at any depth, panic:
    /// rskj's decoder reads a fallback-mined header's signature from bytes
    /// its miner wrote.
    #[test]
    fn no_variation_on_rlp_panics() {
        fn walk(element: &Element<'_>) {
            let _ = element.data();
            if let Ok(inner) = element.elements() {
                inner.iter().for_each(walk);
            }
        }
        let signature = [
            &[0xf8, 0x43, 0x1b, 0xa0][..],
            &[0x7c; 32],
            &[0xa0],
            &[0x5c; 32],
        ]
        .concat();
        let long = [
            &[0xf9, 0x01, 0x06, 0xb9, 0x01, 0x00][..],
            &[0xab; 256],
            &[0xc2, 0x80, 0x01],
        ]
        .concat();
        let seeds = [
            signature,
            long,
            vec![0xc3, 0x1b, 0x81, 0x80],
            vec![0xc5, 0xc4, 0xc3, 0xc2, 0xc1, 0xc0],
        ];
        for (i, seed) in seeds.iter().enumerate() {
            assert!(decode2(seed).is_ok());
            for bytes in crate::mutate::mutants(seed, 3_000, 700 + i as u64) {
                if let Ok(elements) = decode2(&bytes) {
                    elements.iter().for_each(walk);
                }
            }
        }
    }
}
