use std::array;
use primitive_types::U512;
use tfhe::boolean::prelude::{Ciphertext, ServerKey};
use crate::arithmetic::addition::{add_257, add_258, add_385, add_385_with_256, mux, twos_complement};
use crate::arithmetic::multiplication::{add_partial_products};
use crate::conversion::u512_to_bool_vec;

/* This module implements reduction modulo N, the 256-bit prime number used in secp256k1 signing,
for 512 bit numbers (the result of 256 bit multiplication) and 257 bit numbers (result of addition).
The 512 bit reduction requires multiplying the higher bits by c = 2^256 - N and adding the result
with the lower 256 bits. After performing this twice we get a number close to the desired range.
Finally we conditionally subtract N from the result and complete the reduction.

Specifically N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
and c = 432420386565659656852420866394968145599 (a 129-bit number).
*/

fn multiply_by_c(a: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    let n = a.len();
    assert!(n == 257 || n == 130);
    println!("Multiplying by c");

    let complement = twos_complement(a, sk);
    let false_ct = vec![sk.trivial_encrypt(false)];

    // Multiples of the multiplicand (+A, -A, +2A, -2A)
    let pos = &[vec![a[0].clone(); 2], a.to_vec()].concat();
    let neg = &[vec![complement[0].clone(); 2], complement.clone()].concat();
    let pos2 = &[vec![a[0].clone()], a.to_vec(), false_ct.clone()].concat();
    let neg2 = &[vec![complement[0].clone()], complement.clone(), false_ct.clone()].concat();

    // Pre-computed partial products
    let partial_products: Vec<&[Ciphertext]> = vec![
        neg, neg, neg, neg, pos2, neg2, pos, neg, neg, pos, neg, pos, neg, pos2, pos, neg2, 
        neg, pos2, neg, neg, pos, pos, pos, neg, pos2, pos, neg, pos2, neg, neg, pos, pos, 
        pos, pos, neg2, pos2, neg, pos, neg2, pos, pos, pos, pos, pos, pos, pos, pos,
    ];

    // Pre-computed shift values
    let index_diff =
        vec![6, 2, 6, 2, 2, 2, 2, 6, 2, 2, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 8, 4, 4, 6, 
             2, 2, 2, 2, 2, 2, 4, 2, 2, 2, 2, 4, 2, 2, 2, 2, 4, 2, 2, 2, 4, 2, 0];

    // Multiplicand length without sign (256 or 129) + multiplier length (129)
    let result_len = if n == 257 {
        385
    } else {
        258
    };

    let (sum, carry) = add_partial_products(
        index_diff, partial_products,
        n + 2, 128, result_len, sk,
    );

    let (result, _) = if n == 257 {
        add_385(&sum, &carry, sk)
    } else {
        add_258(&sum, &carry, sk)
    };

    result
}

fn first_reduction(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 512);

    let low = &num[256..];
    let high = &num[..256];
    let trivial_false = [sk.trivial_encrypt(false)];

    let product = multiply_by_c(&[&trivial_false, high].concat(), sk);

    let (result, _) = add_385_with_256(&product, low, sk);

    result
}

fn second_reduction(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 385);

    // 385 - 129 = 256
    let low = &num[129..];
    let high = &num[..129];
    let trivial_false = [sk.trivial_encrypt(false), sk.trivial_encrypt(false)];

    let product = multiply_by_c(&[&trivial_false[..1], high].concat(), sk);

    let (result, _) = add_258(&[&trivial_false, low].concat(), &product, sk);

    result
}

// Perform 2 conditional subtractions homomorphically: if sign is set, num < prime, so it's
// within range, else return num - prime (since num >= prime).
fn third_reduction(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 258);

    let compl_n: Vec<_> = complement_n().into_iter()
        .map(|bool| sk.trivial_encrypt(bool))
        .collect();

    let (mut subtracted, _) = add_258(num, &compl_n, sk);
    let mut result = mux(&subtracted[0], &num[1..], &subtracted[1..], sk);
    assert_eq!(result.len(), 257);

    (subtracted, _) = add_257(&result, &compl_n[1..], sk);
    result = mux(&subtracted[0], &result[1..], &subtracted[1..], sk);
    assert_eq!(result.len(), 256);

    result
}

fn complement_n() -> [bool; 258] {
    let prime = U512::from_dec_str(
        "115792089237316195423570985008687907852837564279074904382605163141518161494337")
        .unwrap();
    let complement = !prime + 1;

    let vec = u512_to_bool_vec(complement);

    array::from_fn(|i| vec[254 + i])
}

// Reduce 512 bits mod N
pub fn reduce_512(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 512);

    third_reduction(
        &second_reduction(
            &first_reduction(num, sk), sk), sk)
}

// Reduce 257 bits mod N
pub fn reduce_257(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 257);

    let compl_n_bools: [bool; 258] = complement_n();
    let compl_n: [Ciphertext; 257] = array::from_fn(|i| sk.trivial_encrypt(compl_n_bools[i + 1]));

    // Return num - N if num >= N (i.e. result is positive), else return num
    let (subtracted, _) = add_257(num, &compl_n, sk);
    mux(&subtracted[0], &num[1..], &subtracted[1..], sk)
}