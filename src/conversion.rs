use primitive_types::U512;

pub fn u512_to_bools(num: U512) -> Vec<bool> {
    let mut bytes: [u8; 64] = [0; 64];

    num.to_big_endian(&mut bytes);

    let mut vec = bytes_to_bools(bytes[..32].try_into().unwrap());
    vec.extend(bytes_to_bools(bytes[32..].try_into().unwrap()));

    vec
}

#[cfg(test)]
pub fn bools_to_u512(bools: Vec<bool>) -> U512 {
    let bytes = bools_to_bytes_large(bools);
    U512::from_big_endian(&bytes)
}

#[cfg(test)]
fn bools_to_bytes_large(bools: Vec<bool>) -> [u8; 64] {
    assert!(bools.len() <= 512);

    let mut padded = [false; 512];
    let offset = 512 - bools.len();
    padded[offset..].copy_from_slice(&bools);

    let mut result = [0u8; 64];
    result[..32].copy_from_slice(&bools_to_bytes(&padded[..256]));
    result[32..].copy_from_slice(&bools_to_bytes(&padded[256..]));
    result
}

pub fn bools_to_bytes(bools: &[bool]) -> [u8; 32] {
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
    for &byte in bytes {
        for i in 0..8 {
            bools.push((byte >> (7 - i) & 1) != 0);
        }
    }
    bools
}

#[cfg(test)]
mod tests {
    use super::*;

    // All the conversion functions are involved in this test function
    #[test]
    fn test_conversions() {
        let original = U512::from_dec_str(
            "67261586685705929404380284143584847341556487258585196062242163322406725709054778\
            75431052948711954663748176053196442075199363074208649460864516425000330867")
            .unwrap();

        let bools = u512_to_bools(original);

        let result = bools_to_u512(bools);

        assert_eq!(result, original);
    }
}