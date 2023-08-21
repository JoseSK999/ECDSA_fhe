use primitive_types::{U256, U512};

pub fn u256_to_bool_vec(num: U256) -> Vec<bool> {
    let mut vec = Vec::new();

    // convert U256 to an array of bytes in big-endian order
    let mut bytes: [u8; 32] = [0; 32];

    num.to_big_endian(&mut bytes);

    // convert each byte into its binary representation
    for byte in &bytes {
        for i in 0..8 {
            let bit = (byte >> (7 - i)) & 0x01;
            vec.push(bit == 1);
        }
    }

    vec
}

pub fn u512_to_bool_vec(num: U512) -> Vec<bool> {
    let mut vec = Vec::new();

    // convert U256 to an array of bytes in big-endian order
    let mut bytes: [u8; 64] = [0; 64];

    num.to_big_endian(&mut bytes);

    // convert each byte into its binary representation
    for byte in &bytes {
        for i in 0..8 {
            let bit = (byte >> (7 - i)) & 0x01;
            vec.push(bit == 1);
        }
    }

    vec
}

// Panics if input.len() > 512
pub fn bool_vec_to_u512(input: Vec<bool>) -> U512 {
    let bytes = bools_to_bytes_large(input);
    U512::from_big_endian(&bytes)
}

pub fn bools_to_bytes_large(bits: Vec<bool>) -> Vec<u8> {
    let mut padded_bits = bits;
    let padding = 8 - (padded_bits.len() % 8);

    // pad with false values (0 bits)
    if padding < 8 {
        for _ in 0..padding {
            padded_bits.insert(0, false);
        }
    }

    let mut bytes = vec![];

    for chunk in padded_bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1u8 << (7 - i);
            }
        }
        bytes.push(byte);
    }

    bytes
}

pub fn bools_to_bytes(bools: &Vec<bool>) -> [u8; 32] {
    assert_eq!(bools.len(), 256);

    let mut bytes = [0u8; 32];
    for (i, &b) in bools.iter().enumerate() {
        if b {
            let byte_index = i / 8;
            let bit_index = i % 8;
            bytes[byte_index] |= 1 << (7 - bit_index);
        }
    }
    bytes
}

pub fn bytes_to_bools(bytes: &[u8; 32]) -> Vec<bool> {
    let mut bools = Vec::with_capacity(256);
    for &byte in bytes.iter() {
        for i in 0..8 {
            bools.push((byte >> (7 - i) & 1) != 0);
        }
    }
    bools
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::{U256, U512};

    #[test]
    fn test_u512() {
        let original = U512::from_dec_str(
            "67261586685705929404380284143584847341556487258585196062242163322406725709054778\
            75431052948711954663748176053196442075199363074208649460864516425000330867")
            .unwrap();

        let vec = u512_to_bool_vec(original);

        let back = bool_vec_to_u512(vec);

        assert_eq!(back, original);
    }

    #[test]
    fn test_u256() {
        let original = U256::from_dec_str(
            "3318208833893699408207012859761366950896238136434141333938889974646991869704")
            .unwrap();

        let vec = u256_to_bool_vec(original);

        let bytes = bools_to_bytes_large(vec);
        let back = U256::from_big_endian(&bytes);

        assert_eq!(back, original);
    }

    #[test]
    fn test_bytes_to_bools() {
        let original = U256::from_dec_str(
            "3318208833893699408207012859761366950896238136434141333938889974646991869704")
            .unwrap();

        let mut bytes: [u8; 32] = [0; 32];
        original.to_big_endian(&mut bytes);
        let bools = bytes_to_bools(&bytes);

        let should_be = u256_to_bool_vec(original);

        assert_eq!(bools, should_be);
    }
    #[test]
    fn test_bools_to_bytes() {
        let original = U256::from_dec_str(
            "3318208833893699408207012859761366950896238136434141333938889974646991869704")
            .unwrap();

        let bools = u256_to_bool_vec(original);
        let bytes = bools_to_bytes(&bools);

        let num = U256::from_big_endian(&bytes);

        assert_eq!(num, original);
    }
}