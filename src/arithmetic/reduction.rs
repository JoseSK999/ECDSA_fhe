use std::array;
use std::time::Instant;
use primitive_types::U512;
use tfhe::boolean::prelude::{Ciphertext, ServerKey};
use crate::arithmetic::addition::{add_257, add_258, add_385, add_385_with_256, and, csa, mux, twos_complement, xor};
use crate::arithmetic::multiplication::shift;
use crate::conversion::u512_to_bool_vec;

/* This module implements reduction modulo N, the 256-bit prime number used in secp256k1 signing,
for 512 bit numbers (the result of 256 bit multiplication) and 257 bit numbers (result of addition).
The 512 bit reduction requires multiplying the higher bits by c = 2^256 - N and adding the result
with the lower 256 bits. After performing this twice we get a 260 bit number. We then conditionally
subtract N from the result to finally complete the reduction.

Specifically N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
and c = 432420386565659656852420866394968145599 (a 129-bit number).
*/

fn multiply_by_c(a: &[Ciphertext], sk: &ServerKey) -> (Vec<Ciphertext>, Vec<Ciphertext>) {
    let n = a.len();
    assert!(n == 257 || n == 130);
    println!("Multiplying by c");

    let complement = twos_complement(&a.to_vec(), sk);
    let false_ct = vec![sk.trivial_encrypt(false)];

    // Multiples of the multiplicand (+A, -A, +2A, -2A)
    let pos = &[vec![a[0].clone(); 2], a.to_vec()].concat();
    let neg = &[vec![complement[0].clone(); 2], complement.clone()].concat();
    let pos2 = &[vec![a[0].clone()], a.to_vec(), false_ct.clone()].concat();
    let neg2 = &[vec![complement[0].clone()], complement.clone(), false_ct.clone()].concat();

    // Pre-computed partial products
    let partial_products = vec![
        neg, neg, neg, neg, pos2, neg2, pos, neg, neg, pos, neg, pos, neg, pos2, pos, neg2, 
        neg, pos2, neg, neg, pos, pos, pos, neg, pos2, pos, neg, pos2, neg, neg, pos, pos, 
        pos, pos, neg2, pos2, neg, pos, neg2, pos, pos, pos, pos, pos, pos, pos, pos,
    ];

    // Pre-computed shift values
    let index_diff =
        vec![6, 2, 6, 2, 2, 2, 2, 6, 2, 2, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 8, 4, 4, 6, 
             2, 2, 2, 2, 2, 2, 4, 2, 2, 2, 2, 4, 2, 2, 2, 2, 4, 2, 2, 2, 4, 2, 0];

    let mut sum: Vec<Ciphertext> = (0..n+2).map(|_| sk.trivial_encrypt(false)).collect();
    let mut carry: Vec<Ciphertext> = (0..n+2).map(|_| sk.trivial_encrypt(false)).collect();
    let mut right_sum: Vec<Ciphertext> = (0..128).map(|_| sk.trivial_encrypt(false)).collect();
    let mut right_carry: Vec<Ciphertext> = (0..128).map(|_| sk.trivial_encrypt(false)).collect();

    // Shift and add the partial results
    let mut prev_shift = 0;
    index_diff.into_iter().enumerate().zip(partial_products).for_each(
        |((i, to_shift), partial_product)| {

            if i == 0 {
                sum = partial_product.clone();
            } else if i == 1 {
                // Discard carry-out and set carry-in to 0
                carry = and(&sum[1..], &partial_product[1..], sk);
                carry.push(sk.trivial_encrypt(false));

                sum = xor(&sum, &partial_product, sk);
            } else {
                (sum, carry) = csa(&partial_product, &sum, &carry, prev_shift, sk);
            }

            if to_shift > 0 {
                shift(&mut sum, &mut carry, &mut right_sum, &mut right_carry, to_shift);
            }
            println!("csa and shift");
            prev_shift = to_shift;
        }
    );

    sum.append(&mut right_sum);
    carry.append(&mut right_carry);

    (sum[2..].to_vec(), carry[2..].to_vec())
}

fn first_reduction(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 512);

    let low = &num[256..];
    let high = &num[..256];
    let trivial_false: [Ciphertext; 129] = array::from_fn(|_| sk.trivial_encrypt(false));

    let start = Instant::now();
    let (product_a, product_b) = multiply_by_c(&[&trivial_false[..1], &high].concat(), sk);
    let end = Instant::now();
    println!("Duration mul 256 by u129: {:?}", end.duration_since(start));

    assert_eq!(product_a.len() == 385, product_b.len() == 385);

    let (product, _) = add_385(&product_a, &product_b, sk);

    let (result, _) = add_385_with_256(&product, &low, sk);

    result
}

fn second_reduction(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 385);

    // 385 - 129 = 256
    let low = &num[129..];
    let high = &num[..129];
    let trivial_false: [Ciphertext; 2] = array::from_fn(|_| sk.trivial_encrypt(false));

    let start = Instant::now();
    let (product_a, product_b) = multiply_by_c(&[&trivial_false[..1], &high].concat(), sk);
    let end = Instant::now();
    println!("Duration mul 129 by u129: {:?}", end.duration_since(start));

    assert_eq!(product_a.len() == 258, product_b.len() == 258);

    let (product, _) = add_258(&product_a, &product_b, sk);

    let (result, _) = add_258(&[&trivial_false[..], &low].concat(), &product, sk);

    result
}

// Perform 2 conditional subtractions homomorphically: if sign is set, num < prime, so it's
// within range, else return num - prime (since num >= prime).
fn third_reduction(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 258);

    let complement_p_bools: [bool; 258] = complement_prime();
    let complement_p: [Ciphertext; 258] = array::from_fn(|i| sk.trivial_encrypt(complement_p_bools[i]));

    let (subtracted, _) = add_258(num, &complement_p, &sk);
    let mut vec = mux(&subtracted[0], &num[1..], &subtracted[1..], &sk);
    assert_eq!(vec.len(), 257);

    let (subtracted, _) = add_257(&vec, &complement_p[1..], &sk);
    vec = mux(&subtracted[0], &vec[1..], &subtracted[1..], &sk);
    assert_eq!(vec.len(), 256);

    vec
}

fn complement_prime() -> [bool; 258] {
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

    let array = second_reduction(&first_reduction(num, sk), sk);
    println!("third reduction");
    third_reduction(&array, sk)
}

// Reduce 257 bits mod N
pub fn reduce_257(num: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    assert_eq!(num.len(), 257);

    let complement_p_bools: [bool; 258] = complement_prime();
    let complement_p: [Ciphertext; 257] = array::from_fn(|i| sk.trivial_encrypt(complement_p_bools[i + 1]));

    // Return num - prime if num >= prime (i.e. result is positive), else return num
    let (subtracted, _) = add_257(num, &complement_p, &sk);
    mux(&subtracted[0], &num[1..], &subtracted[1..], &sk)
}