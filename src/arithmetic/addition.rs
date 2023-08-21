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
    (0..shifted-1).for_each(|i| sc_and.insert(0, sc_and[i].clone()));

    let (new_sum, mut new_carry) = rayon::join(
        || xor(&pp, &sc_xor, sk),
        || xor(&sc_and, &and(&pp[1..], &sc_xor[1..], sk), sk),
    );

    // Carry-out has been discarded and carry-in is set to 0
    new_carry.push(sk.trivial_encrypt(false));

    (new_sum, new_carry)
}

// Accepts either 257 bits or 130
pub fn twos_complement(bits: &Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    let n = bits.len();
    assert!(n == 257 || n == 130);

    // Bitwise NOT
    let complement = not(bits, sk);

    // Add 1 to the result
    let mut one = Vec::new();
    for _ in 0..n-1 {
        one.push(sk.trivial_encrypt(false));
    }
    one.push(sk.trivial_encrypt(true));

    let (complement, _) = if n == 257 {
        add_257(&complement, &one, sk)
    } else {
        add_130(&complement, &one, sk)
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
    let (sum_lsb, carry) = add(&a[129..], &b[..], 8, sk);

    let propagate = &a[1..129];
    let mut generate: Vec<Ciphertext> = (0..128).map(|_| sk.trivial_encrypt(false)).collect();
    generate[127] = sk.and(&propagate[127], &carry);

    // Next 128-bit addition
    let (mut carry_signals, carry_out) =
        ladner_fischer(&propagate, &generate, 7, sk);

    // The last carry signals bit is the carry-in
    carry_signals[127] = carry;
    let sum = xor(&carry_signals, &propagate, sk);

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
    for bit in 0..bits - 1 {
        carry[bit] = generate[bit + 1].clone();
    }

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
    use primitive_types::{U256, U512};
    use rand::{Rng, thread_rng};
    use tfhe::boolean::prelude::*;
    use crate::conversion::{bool_vec_to_u512, bools_to_bytes_large, u256_to_bool_vec, u512_to_bool_vec};
    use crate::{decrypt_bools, encrypt_bools};


    #[test]
    fn test_add_257() {
        let (ck, sk) = gen_keys();

        let mut x = u512_to_bool_vec(
            U512::from_dec_str(
                "117461139922381523541187616497497412477236974156110393889151351364158879534932")
                .unwrap()
        );
        let mut y = u512_to_bool_vec(
            U512::from_dec_str(
                "149635844840778202076357383943823829963152350627394395922389037899805267124497")
                .unwrap()
        );

        let a = encrypt_bools(&x.split_off(255), &ck);
        let b = encrypt_bools(&y.split_off(255), &ck);

        assert_eq!(a.len(), 257);
        assert_eq!(b.len(), 257);

        // Add and insert carry value
        let (mut result, carry) = add_257(&a, &b, &sk);
        result.insert(0, carry);

        let decrypted = decrypt_bools(&result, &ck);

        let int = U512::from_big_endian(
            &bools_to_bytes_large(decrypted)
        );

        let should_be = U512::from_dec_str(
            "267096984763159725617545000441321242440389324783504789811540389263964146659429")
            .unwrap();

        assert_eq!(int, should_be);
    }

    #[test]
    fn test_add_256() {
        let (ck, sk) = gen_keys();

        let x = u256_to_bool_vec(
            U256::from_dec_str(
            "32180499282295368862936175210653153969476856747234275168272302057610963853214")
            .unwrap()
        );
        let y = u256_to_bool_vec(
            U256::from_dec_str(
            "73482104862469435698329704986464035699288519680142175016745041282392618033695")
            .unwrap()
        );

        let a = encrypt_bools(&x, &ck);
        let b = encrypt_bools(&y, &ck);

        let (mut result, carry) = add(&a, &b, 8, &sk);
        result.insert(0, carry);

        let decrypted = decrypt_bools(&result, &ck);

        let int = U512::from_big_endian(
            &bools_to_bytes_large(decrypted)
        );

        let should_be = U512::from_dec_str(
            "105662604144764804561265880197117189668765376427376450185017343340003581886909")
            .unwrap();

        assert_eq!(int, should_be);
    }

    #[test]
    fn test_add_385() {
        let (ck, sk) = gen_keys();
        let mut random = thread_rng();

        // Generate two 385 bit vectors
        let mut vec: Vec<bool> = Vec::new();
        let mut vec_2: Vec<bool> = Vec::new();
        for _ in 0..385 {
            vec.push(random.gen());
            vec_2.push(random.gen());
        }

        // Encrypt the vectors
        let encrypted_vec = encrypt_bools(&vec, &ck);
        let encrypted_vec_2 = encrypt_bools(&vec_2, &ck);

        // Addition
        let (mut result_enc, carry) = add_385(&encrypted_vec, &encrypted_vec_2, &sk);
        result_enc.insert(0, carry);

        // Decryption
        let result_clear = decrypt_bools(&result_enc, &ck);

        let result = bool_vec_to_u512(result_clear);
        let num = bool_vec_to_u512(vec);
        let num_2 = bool_vec_to_u512(vec_2);

        let expected = num + num_2;

        assert_eq!(result, expected);
    }
}