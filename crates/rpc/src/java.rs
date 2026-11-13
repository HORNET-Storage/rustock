//! Java's arithmetic where rskj's answer depends on it.
//!
//! `eth_gasPrice`, when the fee market isn't working, is the head's minimum
//! gas price times 1.1 in doubles, read back through `Double.toString`
//! (`EthereumImpl.getGasPrice`):
//!
//! ```java
//! double estimatedGasPrice = minimumGasPrice.asBigInteger().doubleValue() * minGasPriceMultiplier;
//! return new Coin(BigDecimal.valueOf(estimatedGasPrice).toBigInteger());
//! ```
//!
//! `BigDecimal.valueOf(double)` is `new BigDecimal(Double.toString(d))`, and the
//! digits `Double.toString` prints changed in JDK 19. rskj compiles for Java 17
//! (`rskj-core/build.gradle`, `sourceCompatibility = JavaVersion.VERSION_17`)
//! and its Dockerfile builds and runs it on Temurin 17, so the digits here are
//! JDK 17's: a port of `jdk.internal.math.FloatingDecimal` as OpenJDK 17 has
//! it (`getBinaryToASCIIConverter(double, true)`, `BinaryToASCIIBuffer.dtoa`,
//! `developLongDigits`, `roundup`, `estimateDecExp`).
//!
//! A parameter written as a JSON number with a fraction or an exponent goes
//! through `Double.toString` as well: Jackson holds it as a double and gives
//! the parameter's reader that double's text (`params::text`).

use alloy_primitives::{U256, U512};

const EXP_SHIFT: i32 = 52;
const FRACT_HOB: i64 = 1 << EXP_SHIFT;
const EXP_ONE: i64 = 1023 << EXP_SHIFT;
const SIGNIF_BIT_MASK: i64 = FRACT_HOB - 1;
const EXP_BIT_MASK: i64 = 0x7FF << EXP_SHIFT;
const SIGN_BIT_MASK: i64 = i64::MIN;
const MAX_SMALL_BIN_EXP: i32 = 62;
const MIN_SMALL_BIN_EXP: i32 = -(63 / 3);

/// `FDBigInteger.LONG_5_POW.length`: 5^0 to 5^26.
const LONG_5_POW_LEN: i32 = 27;

/// `FloatingDecimal.N_5_BITS`: about ceil(log2(5^i)).
const N_5_BITS: [i32; 27] = [
    0, 3, 5, 7, 10, 12, 14, 17, 19, 21, 24, 26, 28, 31, 33, 35, 38, 40, 42, 45, 47, 49, 52, 54, 56,
    59, 61,
];

/// `FloatingDecimal.insignificantDigitsNumber`.
#[rustfmt::skip]
const INSIGNIFICANT_DIGITS_NUMBER: [i32; 64] = [
    0, 0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7,
    8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 14, 14, 14,
    15, 15, 15, 15, 16, 16, 16, 17, 17, 17,
    18, 18, 18, 19,
];

/// `BigInteger.doubleValue()`: the double nearest `x`, ties to even.
pub fn big_integer_double_value(x: &U256) -> f64 {
    let bits = x.bit_len();
    if bits <= 64 {
        // Rust's integer-to-float cast rounds to nearest, ties to even.
        return x.to::<u64>() as f64;
    }
    let shift = bits - 64;
    // The top 64 bits, the lowest of them set when anything below them is,
    // so that a tie at the 53rd bit with more under it rounds up.
    let below = *x & ((U256::from(1u8) << shift) - U256::from(1u8));
    let top = (*x >> shift).to::<u64>() | u64::from(!below.is_zero());
    top as f64 * f64::from_bits((1023 + shift as u64) << EXP_SHIFT)
}

/// `BigDecimal.valueOf(d).toBigInteger()` on Java 17: the value of the digits
/// `Double.toString(d)` prints, its fraction dropped.
///
/// `None` where Java throws -- `Double.toString` of an infinity or a NaN
/// isn't a number to `BigDecimal` -- and where this doesn't reach: a
/// negative `d`, or one from 2^400 up.
pub fn big_decimal_value_of_to_big_integer(d: f64) -> Option<U512> {
    if !d.is_finite() || d < 0.0 || d >= f64::from_bits((1023 + 400) << EXP_SHIFT) {
        return None;
    }
    if d == 0.0 {
        return Some(U512::ZERO);
    }
    let (digits, dec_exponent) = double_to_string_digits(d);
    // The value is 0.d1 d2 ... dn x 10^dec_exponent; keep its integer part.
    let mut value = U512::ZERO;
    for i in 0..dec_exponent.max(0) as usize {
        let digit = digits.get(i).copied().unwrap_or(0);
        value = value * U512::from(10u8) + U512::from(digit);
    }
    Some(value)
}

/// Java 17's `Double.toString(d)` (`BinaryToASCIIBuffer.getChars`): from
/// 10^-3 to below 10^7 the digits around a point, and outside that one digit,
/// a point, the rest and an `E` with the exponent. A digit always follows the
/// point.
pub fn double_to_string(d: f64) -> String {
    if d.is_nan() {
        return "NaN".to_string();
    }
    let sign = if d.is_sign_negative() { "-" } else { "" };
    if d.is_infinite() {
        return format!("{sign}Infinity");
    }
    if d == 0.0 {
        return format!("{sign}0.0");
    }
    let (digits, dec_exponent) = double_to_string_digits(d.abs());
    let digits: String = digits
        .iter()
        .map(|digit| char::from(b'0' + digit))
        .collect();
    let count = digits.len() as i32;
    if (1..8).contains(&dec_exponent) {
        let whole = count.min(dec_exponent) as usize;
        let zeros = "0".repeat((dec_exponent - count).max(0) as usize);
        let fraction = match &digits[whole..] {
            "" => "0",
            fraction => fraction,
        };
        format!("{sign}{}{zeros}.{fraction}", &digits[..whole])
    } else if (-2..=0).contains(&dec_exponent) {
        let zeros = "0".repeat(-dec_exponent as usize);
        format!("{sign}0.{zeros}{digits}")
    } else {
        let fraction = match &digits[1..] {
            "" => "0",
            fraction => fraction,
        };
        format!("{sign}{}.{fraction}E{}", &digits[..1], dec_exponent - 1)
    }
}

/// The digits of Java 17's `Double.toString(d)` for a positive finite `d`,
/// and its decimal exponent: `d` prints as 0.d1 d2 ... dn x 10^exponent.
/// `FloatingDecimal.getBinaryToASCIIConverter(d, true)`.
fn double_to_string_digits(d: f64) -> (Vec<u8>, i32) {
    let d_bits = d.to_bits() as i64;
    let mut fract_bits = d_bits & SIGNIF_BIT_MASK;
    let mut bin_exp = ((d_bits & EXP_BIT_MASK) >> EXP_SHIFT) as i32;
    let n_significant_bits;
    if bin_exp == 0 {
        // A subnormal: normalize it.
        let leading_zeros = fract_bits.leading_zeros() as i32;
        let shift = leading_zeros - (63 - EXP_SHIFT);
        fract_bits <<= shift;
        bin_exp = 1 - shift;
        n_significant_bits = 64 - leading_zeros;
    } else {
        fract_bits |= FRACT_HOB;
        n_significant_bits = EXP_SHIFT + 1;
    }
    bin_exp -= 1023;
    dtoa(bin_exp, fract_bits, n_significant_bits)
}

/// `BinaryToASCIIBuffer.dtoa` with `isCompatibleFormat` true, Java's `int`
/// and `long` arithmetic wrapping where Java's does.
fn dtoa(bin_exp: i32, mut fract_bits: i64, n_significant_bits: i32) -> (Vec<u8>, i32) {
    let tail_zeros = fract_bits.trailing_zeros() as i32;
    let n_fract_bits = EXP_SHIFT + 1 - tail_zeros;
    let n_tiny_bits = (n_fract_bits - bin_exp - 1).max(0);
    if (MIN_SMALL_BIN_EXP..=MAX_SMALL_BIN_EXP).contains(&bin_exp)
        && n_tiny_bits < LONG_5_POW_LEN
        && n_fract_bits + N_5_BITS[n_tiny_bits as usize] < 64
        && n_tiny_bits == 0
    {
        // The easy case: an integer that fits a long, less the digits below
        // its precision.
        let insignificant = if bin_exp > n_significant_bits {
            insignificant_digits_for_pow2(bin_exp - n_significant_bits - 1)
        } else {
            0
        };
        if bin_exp >= EXP_SHIFT {
            fract_bits <<= bin_exp - EXP_SHIFT;
        } else {
            fract_bits = ((fract_bits as u64) >> (EXP_SHIFT - bin_exp)) as i64;
        }
        return develop_long_digits(0, fract_bits, insignificant);
    }

    // The hard case: d = B / S * 10^dec_exp with 1 <= B / S < 10, and M half
    // an ulp of d scaled as B is.
    let mut dec_exp = estimate_dec_exp(fract_bits, bin_exp);
    let b5 = (-dec_exp).max(0);
    let mut b2 = b5 + n_tiny_bits + bin_exp;
    let s5 = dec_exp.max(0);
    let mut s2 = s5 + n_tiny_bits;
    let m5 = b5;
    let mut m2 = b2 - n_significant_bits;
    fract_bits = ((fract_bits as u64) >> tail_zeros) as i64;
    b2 -= n_fract_bits - 1;
    let common2factor = b2.min(s2);
    b2 -= common2factor;
    s2 -= common2factor;
    m2 -= common2factor;
    if n_fract_bits == 1 {
        m2 -= 1;
    }
    if m2 < 0 {
        b2 -= m2;
        s2 -= m2;
        m2 = 0;
    }
    let bits_of_5 = |p5: i32| N_5_BITS.get(p5 as usize).copied().unwrap_or(p5 * 3);
    let b_bits = n_fract_bits + b2 + bits_of_5(b5);
    let ten_s_bits = s2 + 1 + bits_of_5(s5 + 1);

    let mut digits = Vec::with_capacity(20);
    let (low, high, low_digit_difference);
    if b_bits < 64 && ten_s_bits < 64 {
        if b_bits < 32 && ten_s_bits < 32 {
            // All ints.
            let mut b = (fract_bits as i32)
                .wrapping_mul(5i32.pow(b5 as u32))
                .wrapping_shl(b2 as u32);
            let s = 5i32.pow(s5 as u32).wrapping_shl(s2 as u32);
            let mut m = 5i32.pow(m5 as u32).wrapping_shl(m2 as u32);
            let tens = s.wrapping_mul(10);
            let mut q = b / s;
            b = (b % s).wrapping_mul(10);
            m = m.wrapping_mul(10);
            let mut lo = b < m;
            let mut hi = b.wrapping_add(m) > tens;
            if q == 0 && !hi {
                // The estimate was one too high: drop the leading zero.
                dec_exp -= 1;
            } else {
                digits.push(q as u8);
            }
            // E-form prints at least one digit after the point.
            if !(-3..8).contains(&dec_exp) {
                hi = false;
                lo = false;
            }
            while !lo && !hi {
                q = b / s;
                b = (b % s).wrapping_mul(10);
                m = m.wrapping_mul(10);
                if m > 0 {
                    lo = b < m;
                    hi = b.wrapping_add(m) > tens;
                } else {
                    // m overflowed: Java takes both as reached.
                    lo = true;
                    hi = true;
                }
                digits.push(q as u8);
            }
            low_digit_difference = i64::from(b.wrapping_shl(1).wrapping_sub(tens));
            (low, high) = (lo, hi);
        } else {
            // All longs.
            let mut b = fract_bits
                .wrapping_mul(5i64.pow(b5 as u32))
                .wrapping_shl(b2 as u32);
            let s = 5i64.pow(s5 as u32).wrapping_shl(s2 as u32);
            let mut m = 5i64.pow(m5 as u32).wrapping_shl(m2 as u32);
            let tens = s.wrapping_mul(10);
            let mut q = b / s;
            b = (b % s).wrapping_mul(10);
            m = m.wrapping_mul(10);
            let mut lo = b < m;
            let mut hi = b.wrapping_add(m) > tens;
            if q == 0 && !hi {
                dec_exp -= 1;
            } else {
                digits.push(q as u8);
            }
            if !(-3..8).contains(&dec_exp) {
                hi = false;
                lo = false;
            }
            while !lo && !hi {
                q = b / s;
                b = (b % s).wrapping_mul(10);
                m = m.wrapping_mul(10);
                if m > 0 {
                    lo = b < m;
                    hi = b.wrapping_add(m) > tens;
                } else {
                    lo = true;
                    hi = true;
                }
                digits.push(q as u8);
            }
            low_digit_difference = b.wrapping_shl(1).wrapping_sub(tens);
            (low, high) = (lo, hi);
        }
    } else {
        // FDBigInteger, exactly. Its normalizing shift scales B, S, M and 10S
        // alike, which no quotient or comparison below can see; and here the
        // test for reaching 10S is `>=`, where the int and long paths use `>`.
        //
        // 1024 bits hold it for every double: the least and the greatest keep
        // B, S, M and 10S below 2^830.
        type Wide = alloy_primitives::Uint<1024, 16>;
        let pow52 = |p5: i32, p2: i32| Wide::from(5u8).pow(Wide::from(p5)) << (p2 as usize);
        let s = pow52(s5, s2);
        let mut b = Wide::from(fract_bits as u64) * pow52(b5, b2);
        let mut m = pow52(m5 + 1, m2 + 1);
        let ten_s = pow52(s5 + 1, s2 + 1);
        let ten = Wide::from(10u8);
        // `quoRemIteration`: the quotient, and B becomes 10 * (B mod S).
        let mut q = (b / s).to::<u8>();
        b = (b % s) * ten;
        let mut lo = b < m;
        let mut hi = ten_s <= b + m;
        if q == 0 && !hi {
            dec_exp -= 1;
        } else {
            digits.push(q);
        }
        if !(-3..8).contains(&dec_exp) {
            hi = false;
            lo = false;
        }
        while !lo && !hi {
            q = (b / s).to::<u8>();
            b = (b % s) * ten;
            m *= ten;
            lo = b < m;
            hi = ten_s <= b + m;
            digits.push(q);
        }
        low_digit_difference = if hi && lo {
            match (b << 1usize).cmp(&ten_s) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            }
        } else {
            0
        };
        (low, high) = (lo, hi);
    }

    // The last digit is rounded by how the loop stopped.
    let mut dec_exponent = dec_exp + 1;
    if high {
        if low {
            if low_digit_difference == 0 {
                // A tie: round to an even last digit.
                if digits.last().is_some_and(|digit| digit & 1 != 0) {
                    roundup(&mut digits, &mut dec_exponent);
                }
            } else if low_digit_difference > 0 {
                roundup(&mut digits, &mut dec_exponent);
            }
        } else {
            roundup(&mut digits, &mut dec_exponent);
        }
    }
    (digits, dec_exponent)
}

/// `BinaryToASCIIBuffer.developLongDigits`: the digits of `lvalue`, less
/// `insignificant_digits` low ones rounded half up, trailing zeros dropped.
fn develop_long_digits(
    mut dec_exponent: i32,
    mut lvalue: i64,
    insignificant_digits: i32,
) -> (Vec<u8>, i32) {
    if insignificant_digits != 0 {
        let pow10 = 5i64.pow(insignificant_digits as u32) << insignificant_digits;
        let residue = lvalue % pow10;
        lvalue /= pow10;
        dec_exponent += insignificant_digits;
        if residue >= pow10 >> 1 {
            lvalue += 1;
        }
    }
    let mut reversed = Vec::with_capacity(20);
    let mut c = lvalue % 10;
    lvalue /= 10;
    // Java asserts lvalue > 0; the guard only keeps a zero from looping.
    while c == 0 && lvalue != 0 {
        dec_exponent += 1;
        c = lvalue % 10;
        lvalue /= 10;
    }
    while lvalue != 0 {
        reversed.push(c as u8);
        dec_exponent += 1;
        c = lvalue % 10;
        lvalue /= 10;
    }
    reversed.push(c as u8);
    reversed.reverse();
    (reversed, dec_exponent + 1)
}

/// `BinaryToASCIIBuffer.roundup`: add one to the last digit, carrying.
fn roundup(digits: &mut [u8], dec_exponent: &mut i32) {
    let Some(mut i) = digits.len().checked_sub(1) else {
        return;
    };
    let mut q = digits[i];
    if q == 9 {
        while q == 9 && i > 0 {
            digits[i] = 0;
            i -= 1;
            q = digits[i];
        }
        if q == 9 {
            // Carried out: a 1 and zeros, one place up.
            *dec_exponent += 1;
            digits[0] = 1;
            return;
        }
    }
    digits[i] = q + 1;
}

/// `BinaryToASCIIBuffer.estimateDecExp`: about floor(log10(d)).
///
/// `0.301029995663981` is Java's literal, a different double from
/// `f64::consts::LOG10_2`, and the estimate has to round as Java's does.
#[allow(clippy::approx_constant)]
fn estimate_dec_exp(fract_bits: i64, bin_exp: i32) -> i32 {
    let d2 = f64::from_bits((EXP_ONE | (fract_bits & SIGNIF_BIT_MASK)) as u64);
    let d = (d2 - 1.5) * 0.289529654 + 0.176091259 + f64::from(bin_exp) * 0.301029995663981;
    let d_bits = d.to_bits() as i64;
    let exponent = ((d_bits & EXP_BIT_MASK) >> EXP_SHIFT) as i32 - 1023;
    let is_negative = (d_bits & SIGN_BIT_MASK) != 0;
    if (0..52).contains(&exponent) {
        let mask = SIGNIF_BIT_MASK >> exponent;
        let r = (((d_bits & SIGNIF_BIT_MASK) | FRACT_HOB) >> (EXP_SHIFT - exponent)) as i32;
        if !is_negative {
            r
        } else if mask & d_bits == 0 {
            -r
        } else {
            -r - 1
        }
    } else if exponent < 0 {
        if d_bits & !SIGN_BIT_MASK == 0 || !is_negative {
            0
        } else {
            -1
        }
    } else {
        d as i32
    }
}

/// `BinaryToASCIIBuffer.insignificantDigitsForPow2`.
fn insignificant_digits_for_pow2(p2: i32) -> i32 {
    if p2 > 1 && (p2 as usize) < INSIGNIFICANT_DIGITS_NUMBER.len() {
        INSIGNIFICANT_DIGITS_NUMBER[p2 as usize]
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_big_integer(d: f64) -> u128 {
        big_decimal_value_of_to_big_integer(d).unwrap().to::<u128>()
    }

    /// The digits as `Double.toString` would print them, read back.
    fn read_back(d: f64) -> f64 {
        let (digits, exponent) = double_to_string_digits(d);
        let digits: String = digits
            .iter()
            .map(|digit| char::from(b'0' + digit))
            .collect();
        format!("0.{digits}e{exponent}").parse().unwrap()
    }

    /// `BigInteger.doubleValue` rounds to nearest, ties to even, below 2^64
    /// and above it.
    #[test]
    fn a_big_integer_becomes_the_nearest_double() {
        let two_64 = U256::from(1u8) << 64;
        assert_eq!(
            big_integer_double_value(&U256::from(59_240_000u64)),
            59_240_000.0
        );
        assert_eq!(
            big_integer_double_value(&U256::from(u64::MAX)),
            18446744073709551616.0
        );
        // A tie between 2^64 and 2^64 + 4096 goes to the even one ...
        let tie = two_64 + U256::from(2048u64);
        assert_eq!(big_integer_double_value(&tie), 18446744073709551616.0);
        // ... and one past it, to the nearer.
        let past = tie + U256::from(1u8);
        assert_eq!(big_integer_double_value(&past), 18446744073709555712.0);
        let below = tie - U256::from(1u8);
        assert_eq!(big_integer_double_value(&below), 18446744073709551616.0);
        assert_eq!(big_integer_double_value(&U256::MAX), 2f64.powi(256));
    }

    /// Java 17's digits: an integer below 2^58 prints whole (where JDK 19's
    /// shortest digits would round it: 2.82879384806159008E17 is JDK 17's
    /// output, 2.82879384806159E17 JDK 19's); from 2^58 one digit, from 2^61
    /// two, are dropped rounding half up (`insignificantDigitsForPow2`).
    #[test]
    fn an_integer_double_keeps_java_17s_digits() {
        assert_eq!(to_big_integer(2.82879384806159e17), 282_879_384_806_159_008);
        assert_eq!(
            to_big_integer(143194535060849088.0),
            143_194_535_060_849_088
        );
        assert_eq!(
            to_big_integer(410705390902863872.0),
            410_705_390_902_863_870
        );
        assert_eq!(
            to_big_integer(2269733182554162688.0),
            2_269_733_182_554_162_690
        );
        assert_eq!(
            to_big_integer(8218640729469351936.0),
            8_218_640_729_469_351_900
        );
        assert_eq!(double_to_string_digits(1.0e7), (vec![1], 8));
        assert_eq!(to_big_integer(65164000.0), 65_164_000);
        // Past a long, the hard case's digits as JDK 17 prints them -- the
        // outputs JDK-4511638 (fixed in JDK 19) gives for these, where the
        // shortest digits are 8.41E21, 2.0E23 and 1.0E23.
        let printed = |d: f64| {
            let (digits, exponent) = double_to_string_digits(d);
            let digits: String = digits
                .iter()
                .map(|digit| char::from(b'0' + digit))
                .collect();
            format!("{}.{}E{}", &digits[..1], &digits[1..], exponent - 1)
        };
        assert_eq!(printed(8.41e21), "8.409999999999999E21");
        assert_eq!(printed(2.0e23), "1.9999999999999998E23");
        assert_eq!(printed(1.0e23), "9.999999999999999E22");
        assert_eq!(to_big_integer(8.41e21), 8_409_999_999_999_999_000_000);
    }

    /// `Double.toString` as Java 17 lays a double out, whatever its size.
    /// Each line is Java's own output: Java 11, which prints a double as 17
    /// does, printed these. The three past 10^21 are ones JDK 19 prints
    /// shorter.
    #[test]
    fn a_double_prints_as_java_17_prints_it() {
        for (d, printed) in [
            (0.0, "0.0"),
            (0.1, "0.1"),
            (5.5, "5.5"),
            (5.0, "5.0"),
            (123.456, "123.456"),
            (100000.0, "100000.0"),
            (9999999.999, "9999999.999"),
            (1.0e7, "1.0E7"),
            (12345678.9, "1.23456789E7"),
            (0.001, "0.001"),
            (0.00123, "0.00123"),
            (0.0001, "1.0E-4"),
            (1.5e-7, "1.5E-7"),
            (1.0e30, "1.0E30"),
            (8.41e21, "8.409999999999999E21"),
            (1.0e23, "9.999999999999999E22"),
            (2.0e23, "1.9999999999999998E23"),
            (f64::MAX, "1.7976931348623157E308"),
            (f64::MIN_POSITIVE, "2.2250738585072014E-308"),
            (5e-324, "4.9E-324"),
            (f64::INFINITY, "Infinity"),
        ] {
            assert_eq!(double_to_string(d), printed);
            assert_eq!(double_to_string(-d), format!("-{printed}"));
        }
        assert_eq!(double_to_string(f64::NAN), "NaN");
        // And whatever the double, the least of them included, what is
        // printed reads back as it.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            for d in [f64::from_bits(x), f64::from_bits(x >> 12)] {
                if d.is_finite() {
                    assert_eq!(double_to_string(d).parse(), Ok(d), "{d:e}");
                }
            }
        }
    }

    /// A fraction is dropped, and the digits round-trip: what Java 17 prints
    /// for a double reads back as that double.
    #[test]
    fn a_doubles_digits_read_back_as_it() {
        assert_eq!(to_big_integer(59_240_000.0 * 1.1), 65_164_000);
        assert_eq!(to_big_integer(0.5), 0);
        assert_eq!(to_big_integer(0.0), 0);
        assert_eq!(to_big_integer(-0.0), 0);
        assert_eq!(big_decimal_value_of_to_big_integer(f64::INFINITY), None);
        assert_eq!(big_decimal_value_of_to_big_integer(f64::NAN), None);
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..20_000 {
            // xorshift: minimums spread over every size to 2^256.
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let minimum = U256::from(x) << (x % 200) as usize;
            let d = big_integer_double_value(&minimum) * 1.1;
            assert_eq!(read_back(d), d, "{d:e}");
            if d < 2f64.powi(53) {
                assert_eq!(to_big_integer(d), d.trunc() as u128, "{d:e}");
            }
            let small = (x >> 11) as f64 * 1.1;
            assert_eq!(read_back(small), small, "{small:e}");
            assert_eq!(to_big_integer(small), small.trunc() as u128, "{small:e}");
        }
    }
}
