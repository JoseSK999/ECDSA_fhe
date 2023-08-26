use rayon::prelude::*;
use tfhe::boolean::prelude::*;
use crate::arithmetic::addition::{add, add_257, csa, mux, twos_complement};

/* This module implements a 256-bit multiplier using the Booth partial product generator (radix-16
and radix-4). The radix is chosen such that the amount of work performed is minimized (i.e. both
partial product additions and hard multiple computations).

Partial product additions are performed using carry save adders for better performance.
*/
type CtOpt = Option<Vec<Ciphertext>>;

pub fn multiply_by_scalar(
    a: &[Ciphertext],
    b: &[bool],
    sk: &ServerKey,
) -> Vec<Ciphertext> {
    assert_eq!(a.len(), 257);

    // 2s complement of the multiplicand A
    let compl = twos_complement(a, sk);
    println!("Got complement");

    let trivial_false = vec![sk.trivial_encrypt(false); 3];

    let pos = [&a[..1], &a[..1], &a[..1], &a[..1], a, &trivial_false]
        .concat();
    let neg = [&compl[..1], &compl[..1], &compl[..1], &compl[..1], &compl, &trivial_false]
        .concat();

    // Generate and compute the partial products (small multiples of the multiplicand)
    let (multiples, indices) = gen_multiples(b);

    let (pos_3, neg_3, pos_5, neg_5, pos_7, neg_7) = hard_multiples(&pos, &neg, &multiples, sk);

    // Get +/- 6A if needed. This is done by shifting +/- 3A, which has been computed
    let pos_6 = if multiples.contains(&6) {
        let pos3_ref = pos_3.as_ref()
            .expect("pos_3 was computed in hard_multiples");

        Some([&pos3_ref[1..], &trivial_false[..1]].concat())
    } else {
        None
    };

    let neg_6 = if multiples.contains(&-6) {
        let neg3_ref = neg_3.as_ref()
            .expect("neg_3 was computed in hard_multiples");

        Some([&neg3_ref[1..], &trivial_false[..1]].concat())
    } else {
        None
    };

    let mut partial_products = Vec::new();

    // Push references to the computed partial products. If we access a value we know it's Some()
    for multiple in multiples {
        match multiple {
            -8 => partial_products.push(&neg[3..]),
            -7 => partial_products.push(neg_7.as_ref().unwrap()),
            -6 => partial_products.push(neg_6.as_ref().unwrap()),
            -5 => partial_products.push(neg_5.as_ref().unwrap()),
            -4 => partial_products.push(&neg[2..263]),
            -3 => partial_products.push(neg_3.as_ref().unwrap()),
            -2 => partial_products.push(&neg[1..262]),
            -1 => partial_products.push(&neg[..261]),
            1 => partial_products.push(&pos[..261]),
            2 => partial_products.push(&pos[1..262]),
            3 => partial_products.push(pos_3.as_ref().unwrap()),
            4 => partial_products.push(&pos[2..263]),
            5 => partial_products.push(pos_5.as_ref().unwrap()),
            6 => partial_products.push(pos_6.as_ref().unwrap()),
            7 => partial_products.push(pos_7.as_ref().unwrap()),
            8 => partial_products.push(&pos[3..]),
            _ => panic!("Multiples are only within the [-8, 8] range, excluding 0"),
        }
    }

    // The index differences are the numbers to shift each partial product
    let shift_values: Vec<usize> = indices
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect();

    let (sum, carry) = add_partial_products(
        shift_values, partial_products,
        257 + 4, 257, 512, sk,
    );
    let (result, _) = add(&sum, &carry, 9, sk);

    result
}

// Iterates through the cleartext multiplier bits in groups of 5 and selects (but does not compute)
// the multiples of the multiplicand according to Booth radix-16 (from -8 to 8).
fn gen_multiples(multiplier: &[bool]) -> (Vec<i8>, Vec<usize>) {
    assert_eq!(multiplier.len(), 261);
    let mut indices = Vec::new();
    let mut multiples = Vec::new();

    let mut index = 0;

    /*
    After each iteration the index is incremented by 4 since we advance 4 bits (from LSB to MSB).
    The length of the multiplier is 261 (256 + 5 padding bits), so the multiplier indices will be:

    [0 ..= 4], [4 ..= 8], ..., [252 ..= 256], [256 ..= 260] <= starting here
    */

    for i in (4..multiplier.len()).rev().step_by(4) {
            match multiplier[i-4..=i] {
                // +A
                [false, false, false, false, true] | [false, false, false, true, false] => {
                    multiples.push(1);
                    indices.push(index);
                },
                // -A
                [true, true, true, false, true] | [true, true, true, true, false] => {
                    multiples.push(-1);
                    indices.push(index);
                },
                // +2A
                [false, false, false, true, true] | [false, false, true, false, false] => {
                    multiples.push(2);
                    indices.push(index);
                },
                // -2A
                [true, true, false, true, true] | [true, true, true, false, false] => {
                    multiples.push(-2);
                    indices.push(index);
                },
                // +3A
                [false, false, true, false, true] | [false, false, true, true, false] => {
                    multiples.push(3);
                    indices.push(index);
                },
                // -3A
                [true, true, false, false, true] | [true, true, false, true, false] => {
                    multiples.push(-3);
                    indices.push(index);
                },
                // +4A
                [false, false, true, true, true] | [false, true, false, false, false] => {
                    multiples.push(4);
                    indices.push(index);
                },
                // -4A
                [true, false, true, true, true] | [true, true, false, false, false] => {
                    multiples.push(-4);
                    indices.push(index);
                },
                // +5A
                [false, true, false, false, true] | [false, true, false, true, false] => {
                    multiples.push(5);
                    indices.push(index);
                },
                // -5A
                [true, false, true, false, true] | [true, false, true, true, false] => {
                    multiples.push(-5);
                    indices.push(index);
                },
                // +6A
                [false, true, false, true, true] | [false, true, true, false, false] => {
                    multiples.push(6);
                    indices.push(index);
                },
                // -6A
                [true, false, false, true, true] | [true, false, true, false, false] => {
                    multiples.push(-6);
                    indices.push(index);
                },
                // +7A
                [false, true, true, false, true] | [false, true, true, true, false] => {
                    multiples.push(7);
                    indices.push(index);
                },
                // -7A
                [true, false, false, false, true] | [true, false, false, true, false] => {
                    multiples.push(-7);
                    indices.push(index);
                },
                // +8A
                [false, true, true, true, true] => {
                    multiples.push(8);
                    indices.push(index);
                },
                // -8A
                [true, false, false, false, false] => {
                    multiples.push(-8);
                    indices.push(index);
                },
                _ => (),
            }
            index += 4;
        };

    // Last index
    indices.push(257);

    (multiples, indices)
}

// Computes the previously selected hard (i.e. odd) multiples of the encrypted multiplicand. If a
// hard multiple is missing in the list it's not computed.
fn hard_multiples(
    pos: &[Ciphertext],
    neg: &[Ciphertext],
    multiples: &[i8],
    sk: &ServerKey,
) -> (CtOpt, CtOpt, CtOpt, CtOpt, CtOpt, CtOpt) {
    let pos_1 = &pos[..261];
    let pos_2 = &pos[1..262];
    let pos_4 = &pos[2..263];

    let neg_1 = &neg[..261];
    let neg_2 = &neg[1..262];
    let neg_4 = &neg[2..263];

    let mut pos_3: CtOpt = None;
    let mut neg_3: CtOpt = None;
    let mut pos_5: CtOpt = None;
    let mut neg_5: CtOpt = None;
    let mut pos_7: CtOpt = None;
    let mut neg_7: CtOpt = None;

    rayon::join(
        || rayon::join(
            || {
                if multiples.contains(&7) {
                    // Compute 3A
                    let (sum, carry) = add_257(&pos_1[3..260], &pos_2[3..260], sk);
                    pos_3 = Some([&pos[..2], &[carry], &sum, &pos_1[260..]].concat());
                    println!("3A");

                    // Add 3A to 4A
                    let pos3_ref = pos_3.as_ref().unwrap();
                    let (sum, carry) = add_257(&pos3_ref[2..259], &pos_4[2..259], sk);

                    pos_7 = Some([&pos[..1], &[carry], &sum, &pos3_ref[259..]].concat());
                    println!("7A");
                }
            },
            || {
                if multiples.contains(&-7) {
                    // Compute -3A
                    let (sum, carry) = add_257(&neg_1[3..260], &neg_2[3..260], sk);
                    neg_3 = Some([&neg[..2], &[carry], &sum, &neg_1[260..]].concat());
                    println!("-3A");

                    // Add -3A to -4A
                    let neg3_ref = neg_3.as_ref().unwrap();
                    let (sum, carry) = add_257(&neg3_ref[2..259], &neg_4[2..259], sk);

                    neg_7 = Some([&neg[..1], &[carry], &sum, &neg3_ref[259..]].concat());
                    println!("-7A");
                }
            },
        ),
        || rayon::join(
            || {
                if multiples.contains(&5) {
                    let (sum, carry) = add_257(&pos_1[2..259], &pos_4[2..259], sk);

                    pos_5 = Some([&pos[..1], &[carry], &sum, &pos_1[259..]].concat());
                    println!("5A");
                }
            },
            || {
                if multiples.contains(&-5) {
                    let (sum, carry) = add_257(&neg_1[2..259], &neg_4[2..259], sk);

                    neg_5 = Some([&neg[..1], &[carry], &sum, &neg_1[259..]].concat());
                    println!("-5A");
                }
            },
        ),
    );

    rayon::join(
        || {
            if (multiples.contains(&6) || multiples.contains(&3)) && pos_3.is_none() {
                let (sum, carry) = add_257(&pos_1[3..260], &pos_2[3..260], sk);

                pos_3 = Some([&pos[..2], &[carry], &sum, &pos_1[260..]].concat());
                println!("3A");
            }
        },
        || {
            if (multiples.contains(&-6) || multiples.contains(&-3)) && neg_3.is_none() {
                let (sum, carry) = add_257(&neg_1[3..260], &neg_2[3..260], sk);

                neg_3 = Some([&neg[..2], &[carry], &sum, &neg_1[260..]].concat());
                println!("-3A");
            }
        },
    );

    (pos_3, neg_3, pos_5, neg_5, pos_7, neg_7)
}

pub fn multiply_by_ciphertext(
    a: &[Ciphertext],
    b: &[Ciphertext],
    sk: &ServerKey,
) -> Vec<Ciphertext> {
    let n = a.len();
    assert_eq!(n, 257);

    // Compute the partial products based on the encrypted multiplier bits
    let partial_products = gen_pps_fhe(a, b, sk);
    let pps_ref = partial_products.iter().map(Vec::as_slice).collect();

    let shift_values = [vec![2; 128], vec![1]].concat();
    assert_eq!(shift_values.len(), partial_products.len());

    let (sum, carry) = add_partial_products(
        shift_values, pps_ref,
        257 + 2, 257, 512, sk,
    );
    let (result, _) = add(&sum, &carry, 9, sk);

    result
}

// We iterate through the multiplier bits in groups of 3. Since these values are encrypted, the
// process of selecting each multiple is performed homomorphically. We choose Booth radix-4
// (multiples range from -2 to 2) to reduce the cost of the homomorphic selection circuit.
fn gen_pps_fhe(
    multiplicand: &[Ciphertext],
    multiplier: &[Ciphertext],
    sk: &ServerKey,
) -> Vec<Vec<Ciphertext>> {
    assert_eq!(multiplicand.len(), 257);

    let complement = twos_complement(multiplicand, sk);

    let pos = [&multiplicand[..1], &multiplicand[..1], multiplicand].concat();
    let neg = [&complement[..1], &complement[..1], &complement].concat();

    /*
    The number of bits is 259 (256 + 3 padding bits), so the bit indices will be the following:

    [0 ..= 2], [2 ..= 4] ..., [254 ..= 256], [256 ..= 258]
    */
    let bit_indices: Vec<usize> =
        (2..multiplier.len()).rev().step_by(2)
        .collect();

    bit_indices.into_par_iter()
        .map(|i| {
            println!("Par iter for bit {i}");
            let (bit_0, bit_1, bit_2) = (&multiplier[i-2], &multiplier[i-1], &multiplier[i]);

            // If first bit is set partial product is negative, otherwise it's positive
            let pos_or_neg = mux(bit_0, &neg, &pos, sk);

            // Regardless of the sign we can double the number by performing a left shift
            let pos2_or_neg2 = [&pos_or_neg[1..], &[sk.trivial_encrypt(false)]].concat();

            // If bit_1 XOR bit_2 == true, pp is pos_or_neg, otherwise it's pos2_or_neg2
            let xor_1_2 = sk.xor(bit_1, bit_2);
            let result = mux(&xor_1_2, &pos_or_neg, &pos2_or_neg2, sk);

            // Finally we select 0A only if all three bits have the same value
            // This is the case if (bit_0 XOR bit_1) OR (bit_1 XOR bit_2) == False
            let selector = sk.or(
                &sk.xor(bit_0, bit_1),
                &xor_1_2);

            (0..result.len())
                .into_par_iter()
                .map(|i| sk.and(&result[i], &selector))
                .collect()

        }).collect()
}

// Add pairs of partial products using carry save adders and shift "shift_values" bits left for the
// next addition. Return the final sum and carry vectors that need to be added.
pub fn add_partial_products(
    shift_values: Vec<usize>,
    partial_products: Vec<&[Ciphertext]>,
    lhs_len: usize,
    rhs_len: usize,
    result_len: usize,
    sk: &ServerKey,
) -> (Vec<Ciphertext>, Vec<Ciphertext>) {

    let mut sum = vec![sk.trivial_encrypt(false); lhs_len];
    let mut carry = vec![sk.trivial_encrypt(false); lhs_len];
    let mut right_sum = vec![sk.trivial_encrypt(false); rhs_len];
    let mut right_carry = vec![sk.trivial_encrypt(false); rhs_len];

    let mut prev_shift = 0;

    shift_values.into_iter().zip(partial_products)
        .for_each(
            |(to_shift, partial_product)| {

                (sum, carry) = csa(
                    partial_product, &sum, &carry,
                    prev_shift, sk,
                );

                if to_shift > 0 {
                    shift(
                        &mut sum, &mut carry,
                        &mut right_sum, &mut right_carry,
                        to_shift,
                    );
                }
                println!("CSA and shift");
                prev_shift = to_shift;
        });

    sum.append(&mut right_sum);
    carry.append(&mut right_carry);

    let cut = sum.len() - result_len;

    (sum[cut..].to_vec(), carry[cut..].to_vec())
}

pub fn shift(
    sum: &mut Vec<Ciphertext>,
    carry: &mut Vec<Ciphertext>,
    right_sum: &mut Vec<Ciphertext>,
    right_carry: &mut Vec<Ciphertext>,
    to_shift: usize,
) {
    let left_len = sum.len();
    assert_eq!(left_len, carry.len());

    let sign_sum = sum[0].clone();
    let sign_carry = carry[0].clone();

    sum.append(right_sum);
    sum.rotate_right(to_shift);
    sum[..to_shift].fill(sign_sum); // sign extend
    *right_sum = sum.split_off(left_len);

    carry.append(right_carry);
    carry.rotate_right(to_shift);
    carry[..to_shift].fill(sign_carry); // sign extend
    *right_carry = carry.split_off(left_len);
}