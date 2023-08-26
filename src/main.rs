mod conversion;
mod arithmetic;

use std::array;
use primitive_types::{U256, U512};
use rand::{Rng, thread_rng};

use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use secp256k1::ecdsa::Signature;
use tfhe::boolean::prelude::*;

use crate::arithmetic::sign_ecdsa;
use crate::conversion::{bools_to_bytes, bytes_to_bools};

fn main() {
    let (ck, sk) = gen_keys();
    let secp = Secp256k1::new();

    // Generate secp256k1 secret key
    let mut random = thread_rng();
    let secret = array::from_fn::<u8, 32, _>(|_| random.gen());
    let secret_key = SecretKey::from_slice(&secret)
        .expect("32 bytes, within curve order");

    // Generate and encrypt the private ECDSA inputs
    let (mut nonce_pub, mut nonce_inv, mut prv_key) = encrypt_ecdsa_input(&secret, &ck);
    let r = bools_to_bytes(&nonce_pub);

    let message_bytes = array::from_fn::<u8, 32, _>(|_| random.gen());
    let message = bytes_to_bools(&message_bytes);

    // Signature computation
    let result = sign_ecdsa(
        &mut prv_key,
        &mut nonce_inv,
        &mut nonce_pub,
        &message, &sk);

    // Decrypt
    let s = decrypt_bools(&result, &ck);
    let raw_sig = [r, bools_to_bytes(&s)].concat();

    // Verify
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let message = Message::from_slice(&message_bytes).unwrap();
    let mut sig = Signature::from_compact(&raw_sig).unwrap();

    // The value 's' must be in the lower half of the allowable range to be valid according to the
    // libsecp256k1 library. This constraint is in place to prevent signature malleability, as
    // specified by BIP 146. Signature malleability occurs when there is more than one valid
    // signature for the same transaction. By restricting 's' to the lower half, the signature
    // becomes unique and non-malleable.
    sig.normalize_s();

    assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
    println!("Success!");
}

fn encrypt_ecdsa_input(secret_key: &[u8; 32], ck: &ClientKey) -> (Vec<bool>, Vec<Ciphertext>, Vec<Ciphertext>) {
    let secp = Secp256k1::new();
    let mut random = thread_rng();

    // Nonce pub key
    let nonce = array::from_fn::<u8, 32, _>(|_| random.gen());
    let nonce_pub = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&nonce).expect("32 bytes, within curve order"),
    ).serialize();

    // Nonce modular inverse
    let nonce_inverse = bytes_to_bools(&modular_inverse(&nonce));
    let priv_k = bytes_to_bools(secret_key);

    let d = encrypt_bools(&priv_k, ck);
    let k = encrypt_bools(&nonce_inverse, ck);
    let r = bytes_to_bools(&array::from_fn(|i| nonce_pub[i+1]));

    (r, k, d)
}

fn modular_inverse(base: &[u8; 32]) -> [u8; 32] {
    let base = U256::from_big_endian(base);
    let p = U256::from_dec_str("115792089237316195423570985008687907852837564279074904382605163141518161494337").unwrap();

    let mut res = U512::one();
    let mut x = U512::from(base % p);
    let mut y = p - U256::from(2);

    while y > U256::zero() {
        if y % U256::from(2) != U256::zero() {
            res = (res * x) % p;
        }
        y /= U256::from(2);
        x = (x * x) % p;
    }

    let mut bytes = [0u8; 64];
    res.to_big_endian(&mut bytes);

    array::from_fn(|i| bytes[i+32])
}

pub fn encrypt_bools(bools: &[bool], ck: &ClientKey) -> Vec<Ciphertext> {
    bools.iter()
        .map(|bool| ck.encrypt(*bool))
        .collect()
}

pub fn decrypt_bools(ciphertext: &[Ciphertext], ck: &ClientKey) -> Vec<bool> {
    ciphertext.iter()
        .map(|cipher| ck.decrypt(cipher))
        .collect()
}