use rayon::prelude::*;
use tfhe::boolean::prelude::{BinaryBooleanGates, Ciphertext, ServerKey};

/* This module implements additions and related functions using parallel processing techniques.
The main implementations are a parallel prefix adder using the Ladner Fischer algorithm for carry
propagation (which allows for variable input size, as long as it's a power of 2), a carry save
adder for fast sequential additions and the two's complement computation.
*/

pub fn csa(
    pp: &[Ciphertext],
    sum: &[Ciphertext],
    carry: &[Ciphertext],
    shifted: usize,
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Vec<Ciphertext>) {

    // Sum and carry vecs are sign extended so we can skip doing AND/XOR on the "shifted" MSBs
    let (mut sc_xor, mut sc_and) = rayon::join(
        || xor(&sum[shifted..], &carry[shifted..], sk),
        || and(&sum[shifted..], &carry[shifted..], sk),
    );

    (0..shifted).for_each(|i| sc_xor.insert(0, sc_xor[i].clone()));
    (0..shifted).for_each(|i| sc_and.insert(0, sc_and[i].clone()));

    let (new_sum, mut new_carry) = rayon::join(
        || xor(pp, &sc_xor, sk),
        || xor(&sc_and[1..], &and(&pp[1..], &sc_xor[1..], sk), sk),
    );

    // Carry-out has been discarded and carry-in is set to 0
    new_carry.push(sk.trivial_encrypt(false));

    (new_sum, new_carry)
}

// Accepts either 257 bits or 130
pub fn twos_complement(bits: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    let n = bits.len();
    assert!(n == 257 || n == 130);

    // Bitwise NOT
    let negated = not(bits, sk);

    // Add 1 to the result
    let mut one = vec![sk.trivial_encrypt(false); n - 1];
    one.push(sk.trivial_encrypt(true));

    let (complement, _) = if n == 257 {
        add_257(&negated, &one, sk)
    } else {
        add_130(&negated, &one, sk)
    };

    complement
}

pub fn add(
    a: &[Ciphertext],
    b: &[Ciphertext],
    power_of_two: usize,
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Ciphertext) {
    assert_eq!(a.len(), 1 << power_of_two);
    assert_eq!(b.len(), 1 << power_of_two);

    let (propagate, generate) = rayon::join(
        || xor(a, b, sk),
        || and(a, b, sk),
    );

    let (carry, carry_out) = ladner_fischer(&propagate, &generate, power_of_two, sk);

    let sum = xor(&propagate, &carry, sk);

    (sum, carry_out)
}

pub fn add_257(
    a: &[Ciphertext],
    b: &[Ciphertext],
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Ciphertext) {
    assert_eq!(a.len(), 257);
    assert_eq!(b.len(), 257);

    // Add the 256 LSB using a parallel prefix adder while doing AND and XOR on the 257th bit (MSB)
    let ((mut result, carry), (ab_xor, ab_and)) = rayon::join(
        || add(&a[1..], &b[1..], 8, sk),
        || rayon::join(
            || sk.xor(&a[0], &b[0]),
            || sk.and(&a[0], &b[0]),
        ),
    );

    // Full adder to handle the 257th bit (MSB)
    let (carry_out, sum) = rayon::join(
        || sk.xor(&sk.and(&carry, &ab_xor), &ab_and),
        || sk.xor(&carry, &ab_xor),
    );

    result.insert(0, sum);
    (result, carry_out)
}

pub fn add_258(
    a: &[Ciphertext],
    b: &[Ciphertext],
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Ciphertext) {
    assert_eq!(a.len(), 258);
    assert_eq!(b.len(), 258);

    let ((mut result, carry), (ab_xor, ab_and)) = rayon::join(
        || add_257(&a[1..], &b[1..], sk),
        || rayon::join(
            || sk.xor(&a[0], &b[0]),
            || sk.and(&a[0], &b[0]),
        ),
    );

    let (carry_out, sum) = rayon::join(
        || sk.xor(&sk.and(&carry, &ab_xor), &ab_and),
        || sk.xor(&carry, &ab_xor),
    );

    result.insert(0, sum);
    (result, carry_out)
}

pub fn add_130(
    a: &[Ciphertext],
    b: &[Ciphertext],
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Ciphertext) {
    assert_eq!(a.len(), 130);
    assert_eq!(b.len(), 130);

    // Add the 128 LSB while computing AND/XOR on the 2 MSB
    let ((result, carry), (ab_xor, ab_and)) = rayon::join(
        || add(&a[2..], &b[2..], 7, sk),
        || rayon::join(
            || xor(&a[..2], &b[..2], sk),
            || and(&a[..2], &b[..2], sk),
        ),
    );

    // Full adders to handle the 2 MSB
    let (carry, sum_1) = rayon::join(
        || sk.xor(&sk.and(&carry, &ab_xor[1]), &ab_and[1]),
        || sk.xor(&carry, &ab_xor[1]),
    );
    let (carry, sum_0) = rayon::join(
        || sk.xor(&sk.and(&carry, &ab_xor[0]), &ab_and[0]),
        || sk.xor(&carry, &ab_xor[0]),
    );

    ([vec![sum_0], vec![sum_1], result].concat(), carry)
}

// We chain a 256-bit addition, a 128-bit addition and a full adder (256 + 128 + 1 = 385)
pub fn add_385(
    a: &[Ciphertext],
    b: &[Ciphertext],
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Ciphertext) {
    assert_eq!(a.len(), 385);
    assert_eq!(b.len(), 385);

    // Add the 256 LSB while computing the propagate and generate signals of the next 128 bits
    let ((sum_lsb, carry), (propagate, mut generate)) = rayon::join(
        || add(&a[129..], &b[129..], 8, sk),
        || rayon::join(
            || xor(&a[1..129], &b[1..129], sk),
            || and(&a[1..129], &b[1..129], sk),
        ),
    );

    // Change the last generate bit to take into account the carry from the previous addition
    generate[127] = sk.or(&generate[127], &sk.and(&propagate[127], &carry));

    // Perform the 128-bit addition and XOR/AND the MSB
    let ((carry_signals, carry), (ab_xor, ab_and)) = rayon::join(
        || {
            let (mut carry_signals, carry_out) =
                ladner_fischer(&propagate, &generate, 7, sk);

            // The last carry signals bit is the carry-in
            carry_signals[127] = carry;
            (carry_signals, carry_out)
        },
        || rayon::join(
            || sk.xor(&a[0], &b[0]),
            || sk.and(&a[0], &b[0]),
        ),
    );

    let sum = xor(&carry_signals, &propagate, sk);

    // Full adder to handle the MSB
    let (carry_out, sum_msb) = rayon::join(
        || sk.xor(&sk.and(&carry, &ab_xor), &ab_and),
        || sk.xor(&carry, &ab_xor),
    );

    ([vec![sum_msb], sum, sum_lsb].concat(), carry_out)
}

pub fn add_385_with_256(
    a: &[Ciphertext],
    b: &[Ciphertext],
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Ciphertext) {
    assert_eq!(a.len(), 385);
    assert_eq!(b.len(), 256);

    // Add the 256 LSB
    let (sum_lsb, carry) = add(&a[129..], b, 8, sk);

    let propagate = &a[1..129];
    let mut generate: Vec<Ciphertext> = (0..128).map(|_| sk.trivial_encrypt(false)).collect();
    generate[127] = sk.and(&propagate[127], &carry);

    // Next 128-bit addition
    let (mut carry_signals, carry_out) =
        ladner_fischer(propagate, &generate, 7, sk);

    // The last carry signals bit is the carry-in
    carry_signals[127] = carry;
    let sum = xor(&carry_signals, propagate, sk);

    // Full adder to handle the MSB
    let (carry_out, sum_msb) = rayon::join(
        || sk.and(&carry_out, &a[0]),
        || sk.xor(&carry_out, &a[0]),
    );

    ([vec![sum_msb], sum, sum_lsb].concat(), carry_out)
}

fn ladner_fischer(
    propagate: &[Ciphertext],
    generate: &[Ciphertext],
    stages: usize,
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Ciphertext) {
    let mut propagate = propagate.to_vec();
    let mut generate = generate.to_vec();

    let bits = 1 << stages;

    for d in 0..stages {
        let stride = 1 << d;

        let indices: Vec<(usize, usize)> = (0..bits - stride)
            .rev()
            .step_by(2 * stride)
            .flat_map(|i| (0..stride).map(move |count| (i, count)))
            .collect();

        let updates: Vec<(usize, Ciphertext, Ciphertext)> = indices
            .into_par_iter()
            .map(|(i, count)| {
                let index = i - count; // current column

                let p = propagate[i + 1].clone(); // propagate from a previous column
                let g = generate[i + 1].clone(); // generate from a previous column
                let new_p;
                let new_g;

                if index < bits - (2 * stride) { // black cell
                    new_p = sk.and(&propagate[index], &p);
                    new_g = sk.or(&generate[index], &sk.and(&g, &propagate[index]));

                } else { // grey cell
                    new_p = propagate[index].clone();
                    new_g = sk.or(&generate[index], &sk.and(&g, &propagate[index]));
                }
                (index, new_p, new_g)
            })
            .collect();

        for (index, new_p, new_g) in updates {
            propagate[index] = new_p;
            generate[index] = new_g;
        }
    }

    let mut carry: Vec<Ciphertext> = (0..bits).map(|_| sk.trivial_encrypt(false)).collect();
    carry[..(bits - 1)].clone_from_slice(&generate[1..bits]);

    let carry_out = generate[0].clone();

    (carry, carry_out)
}

// Bitwise homomorphic operations
pub fn xor(a: &[Ciphertext], b: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    let n = a.len();

    (0..n)
        .into_par_iter()
        .map(|i| sk.xor(&a[i], &b[i]))
        .collect()
}

pub fn and(a: &[Ciphertext], b: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    let n = a.len();

    (0..n)
        .into_par_iter()
        .map(|i| sk.and(&a[i], &b[i]))
        .collect()
}

fn not(a: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    let n = a.len();

    (0..n)
        .into_par_iter()
        .map(|i| sk.not(&a[i]))
        .collect()
}

pub fn mux(
    condition: &Ciphertext,
    then: &[Ciphertext],
    otherwise: &[Ciphertext],
    sk: &ServerKey
) -> Vec<Ciphertext> {
    let n = then.len();

    (0..n)
        .into_par_iter()
        .map(|i| sk.mux(condition, &then[i], &otherwise[i]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U512;
    use tfhe::boolean::prelude::*;
    use crate::conversion::{bools_to_u512, u512_to_bools};
    use crate::{decrypt_bools, encrypt_bools};

    fn to_bools_and_encrypt(n: &str, bits_len: usize, ck: &ClientKey) -> Vec<Ciphertext> {
        let mut v = u512_to_bools(U512::from_dec_str(n).unwrap());
        encrypt_bools(&v.split_off(512 - bits_len), ck)
    }

    #[test]
    fn test_add_257() {
        let (ck, sk) = gen_keys();

        let x = to_bools_and_encrypt("117461139922381523541187616497497412477236974156110393889151351364158879534932", 257, &ck);
        let y = to_bools_and_encrypt("149635844840778202076357383943823829963152350627394395922389037899805267124497", 257, &ck);

        // Add and insert carry value
        let (mut result, carry) = add_257(&x, &y, &sk);
        result.insert(0, carry);

        let decrypted = decrypt_bools(&result, &ck);
        let int = bools_to_u512(decrypted);

        let should_be = U512::from_dec_str("267096984763159725617545000441321242440389324783504789811540389263964146659429").unwrap();

        assert_eq!(int, should_be);
    }

    // add_385 is internally adding 256 bits, so we are testing both
    #[test]
    fn test_add_385() {
        let (ck, sk) = gen_keys();

        // Test max 385-bit values
        let max = vec![true; 385];
        let encrypted = encrypt_bools(&max, &ck);

        let (mut result_enc, carry) = add_385(&encrypted, &encrypted, &sk);
        result_enc.insert(0, carry);

        let result_clear = decrypt_bools(&result_enc, &ck);

        let result = bools_to_u512(result_clear);
        let max = bools_to_u512(max);
        assert_eq!(result, max + max);

        // Test min 385-bit values
        let min = vec![false; 385];
        let encrypted = encrypt_bools(&min, &ck);

        let (mut result_enc, carry) = add_385(&encrypted, &encrypted, &sk);
        result_enc.insert(0, carry);

        let result_clear = decrypt_bools(&result_enc, &ck);

        let result = bools_to_u512(result_clear);
        let min = bools_to_u512(min);
        assert_eq!(result, min + min);

        // Test normal case
        let x = to_bools_and_encrypt("47025062602514006042727509475978745000638010917821275502568093707838353316384434056336283145249999537604249106769469", 385, &ck);
        let y = to_bools_and_encrypt("67815384912303466065544815297240550038024383379717173427803252354458990812799388813460358985039646741378368819296071", 385, &ck);

        let (mut result, carry) = add_385(&x, &y, &sk);
        result.insert(0, carry);

        let decrypted = decrypt_bools(&result, &ck);
        let int = bools_to_u512(decrypted);

        // 386-bit number
        let should_be = U512::from_dec_str("114840447514817472108272324773219295038662394297538448930371346062297344129183822869796642130289646278982617926065540").unwrap();

        assert_eq!(int, should_be);
    }
}