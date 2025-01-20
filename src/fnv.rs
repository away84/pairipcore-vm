
pub const FNV_PRIME: u64 = 0x100000001B3;

pub fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325;
    for byte in data {
        hash ^= *byte as u64;
        hash *= FNV_PRIME;
    }
    hash
}
