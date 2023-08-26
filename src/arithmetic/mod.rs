use tfhe::boolean::prelude::*;
use crate::arithmetic::addition::add;
use crate::arithmetic::multiplication::{multiply_by_ciphertext, multiply_by_scalar};
use crate::arithmetic::reduction::{reduce_512, reduce_257};

mod addition;
mod multiplication;
mod reduction;

fn modular_mul_scalar(a: &mut Vec<Ciphertext>, b: &mut Vec<bool>, sk: &ServerKey) -> Vec<Ciphertext> {
    // Sign extend multiplicand (2s complement)
    a.insert(0, sk.trivial_encrypt(false));

    // Pad multiplier for Booth Algorithm
    b.push(false);
    b.splice(..0, vec![false; 4]);

    let result = multiply_by_scalar(a, b, sk);

    reduce_512(&result, sk)
}

fn modular_mul_ciphertext(a: &mut Vec<Ciphertext>, b: &mut Vec<Ciphertext>, sk: &ServerKey) -> Vec<Ciphertext> {
    // Sign extend multiplicand (2s complement)
    a.insert(0, sk.trivial_encrypt(false));

    // Pad multiplier for Booth Algorithm
    b.push(sk.trivial_encrypt(false));
    b.splice(..0, vec![sk.trivial_encrypt(false); 2]);

    let result = multiply_by_ciphertext(a, b, sk);

    reduce_512(&result, sk)
}

fn modular_add(a: &[Ciphertext], b: &[Ciphertext], sk: &ServerKey) -> Vec<Ciphertext> {
    let (mut result, carry) = add(a, b, 8, sk);
    result.insert(0, carry);

    reduce_257(&result, sk)
}

#[allow(dead_code)]
pub fn sign_schnorr(
    private_key: &mut Vec<Ciphertext>,
    message: &mut Vec<bool>,
    nonce: &[Ciphertext],
    sk: &ServerKey,
) -> Vec<Ciphertext> {
    // priv key * message
    let product = modular_mul_scalar(private_key, message, sk);

    // + nonce
    modular_add(&product, nonce, sk)
}

pub fn sign_ecdsa(
    private_key: &mut Vec<Ciphertext>,
    nonce_inverse: &mut Vec<Ciphertext>,
    public_nonce: &mut Vec<bool>,
    message: &[bool],
    sk: &ServerKey,
) -> Vec<Ciphertext> {
    let message_enc: Vec<_> = (0..message.len())
        .map(|i| sk.trivial_encrypt(message[i]))
        .collect();

    // priv key * public nonce (x coordinate)
    let mut result = modular_mul_scalar(private_key, public_nonce, sk);

    // + message
    result = modular_add(&result, &message_enc, sk);

    // * nonce inverse
    modular_mul_ciphertext(&mut result, nonce_inverse, sk)
}