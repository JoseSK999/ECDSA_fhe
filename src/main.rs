mod conversion;
mod arithmetic;

use std::array;
use std::time::Instant;
use primitive_types::{U256, U512};
use rand::{Rng, thread_rng};

use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use secp256k1::ecdsa::Signature;
use tfhe::boolean::prelude::*;

use crate::arithmetic::{sign_ecdsa, sign_schnorr};
use crate::conversion::{bools_to_bytes, bytes_to_bools};

fn main() {
    let (ck, sk) = gen_keys();
    let secp = Secp256k1::new();

    // Generate secp256k1 secret key
    let mut random = thread_rng();
    let secret = array::from_fn::<u8, 32, _>(|_| random.gen());
    let secret_key = SecretKey::from_slice(&secret)
        .expect("32 bytes, within curve order");

    // Encrypt ECDSA inputs
    let (mut r, mut k, mut d) = encrypt_ecdsa_input(&secret, &ck);
    let nonce_pub_x = bools_to_bytes(&r);

    let message_bytes = array::from_fn::<u8, 32, _>(|_| random.gen());
    let mut m = bytes_to_bools(&message_bytes);

    // Signature computation
    let start = Instant::now();
    let result = sign_ecdsa(&mut d, &mut k, &mut m, &mut r, &sk);
    let end = Instant::now();
    println!("{:?}", end.duration_since(start));

    // Decrypt
    let decrypted = decrypt_bools(&result, &ck);
    let s = bools_to_bytes(&decrypted);

    // Verify
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let message = Message::from_slice(&message_bytes).unwrap();
    let mut sig = Signature::from_compact(&[nonce_pub_x, s].concat()).unwrap();

    // s needs to lie in the lower half of the range in order for libsecp256k1 to accept the
    // signature. This is to prevent malleability (BIP 146).
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
    let priv_k = bytes_to_bools(&secret_key);

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
        y = y / U256::from(2);
        x = (x * x) % p;
    }

    let mut bytes = [0u8; 64];
    res.to_big_endian(&mut bytes);

    array::from_fn(|i| bytes[i+32])
}

pub fn encrypt_bools(bools: &Vec<bool>, ck: &ClientKey) -> Vec<Ciphertext> {
    let mut ciphertext = vec![];

    for bool in bools {
        ciphertext.push(ck.encrypt(*bool));
    }
    ciphertext
}

pub fn decrypt_bools(ciphertext: &Vec<Ciphertext>, ck: &ClientKey) -> Vec<bool> {
    let mut bools = vec![];

    for cipher in ciphertext {
        bools.push(ck.decrypt(&cipher));
    }
    bools
}