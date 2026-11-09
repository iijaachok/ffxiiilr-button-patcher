//! Filelist encryption for FINAL FANTASY XIII-2 / Lightning Returns.
//!
//! Reimplementation of the cipher from `WhiteCryptTool` (GPL-3.0, Surihix).

use anyhow::{Result, ensure};

/// Multiplicative/additive constant used by the per-block "special key".
const SPECIAL_KEY: u32 = 0xA165_2347;

/// Container layout:
/// `[0..32)` plaintext preamble, `[32 .. 32+body_size)` encrypted,
/// `[32+body_size ..)` 8-byte unencrypted remainder.
pub const PREAMBLE: usize = 32;
/// Size of the unencrypted trailer after the encrypted region.
pub const REMAINDER: usize = 8;

/// Substitution table lookup: `Integers[v] == (v + 120) & 0xFF`.
#[inline]
fn integers_lookup(v: u8) -> u8 {
    v.wrapping_add(120)
}

/// Inverse substitution-table lookup (`Array.IndexOf(Integers, x)`).
#[inline]
fn integers_index_of(x: u8) -> u8 {
    x.wrapping_sub(120)
}

/// Generate the 264-byte XOR table from the 8-byte little-endian seed.
pub fn generate_xor_table(seed8: [u8; 8]) -> [u8; 264] {
    let mut rev = seed8;
    rev.reverse();
    let mut half_a = u32::from_le_bytes(rev[0..4].try_into().unwrap());
    let mut half_b = u32::from_le_bytes(rev[4..8].try_into().unwrap());
    half_a = half_a.rotate_left(8);
    half_b = half_b.rotate_left(16);

    let mut block = [0u8; 8];
    block[0..4].copy_from_slice(&half_b.to_le_bytes());
    block[4..8].copy_from_slice(&half_a.to_le_bytes());
    block[0] = block[0].wrapping_add(0x45);

    for i in 1..8 {
        let prev = block[i - 1] as u32;
        let mut tmp = (block[i] as u32).wrapping_add(0xD4).wrapping_add(prev);
        tmp ^= prev << 2;
        tmp ^= 0x45;
        block[i] = tmp as u8;
    }

    let mut table = [0u8; 264];
    table[0..8].copy_from_slice(&block);

    let mut prev = u64::from_le_bytes(block);
    for i in 1..0x21usize {
        let ha = (prev & 0xFFFF_FFFF) as u32;
        let hb = (prev >> 32) as u32;

        let mut a = prev.wrapping_mul(5);
        a ^= (hb as u64) << 32;

        let masked = ha ^ (a as u32);
        let mut shifted = (a >> 32) as u32;
        let a2 = (ha as u64) | (a & 0xFFFF_FFFF_0000_0000);

        let xha = (a2 as u32) ^ masked;
        shifted ^= hb;
        let xhb = shifted;

        block = [0u8; 8];
        block[0..4].copy_from_slice(&xha.to_le_bytes());
        block[4..8].copy_from_slice(&xhb.to_le_bytes());
        table[i * 8..(i + 1) * 8].copy_from_slice(&block);
        prev = u64::from_le_bytes(block);
    }
    table
}

/// Derive the 8-byte seed from the 16-byte plaintext preamble.
pub fn seed_from_header(data: &[u8]) -> [u8; 8] {
    let b = &data[0..16];
    let val = ((b[9] as i32) << 24) | ((b[12] as i32) << 16) | ((b[2] as i32) << 8) | (b[0] as i32);
    // C# `(ulong)(int)` sign-extends a negative value to 64 bits.
    let val = val as i64 as u64;
    val.to_le_bytes()
}

#[inline]
fn block_counter_setup(block_counter: u32) -> (usize, u32, u32) {
    let table_offset = (block_counter & 0xF8) as usize;
    let ab = (block_counter as u64) << 10;
    let cd = (block_counter as u64) << 20;
    let ef = (block_counter as u64) << 30;
    let a_val = ab as u32;
    let b_val = (ab >> 32) as u32;
    let c_val = (cd as u32) | a_val;
    let d_val = ((cd >> 32) as u32) | b_val;
    let e_val = (ef as u32) | block_counter | c_val;
    let f_val = ((ef >> 32) as u32) | d_val;
    (table_offset, e_val, f_val)
}

#[inline]
fn special_key(e_val: u32, f_val: u32) -> (u64, u64) {
    let carry = u64::from(e_val > !SPECIAL_KEY);
    let sk1 = (e_val as u64).wrapping_add(SPECIAL_KEY as u64);
    let sk2 = (f_val as u64).wrapping_add(carry);
    (sk1, sk2)
}

#[inline]
fn loop_a_byte(mut v: u8, table: &[u8; 264], off: usize) -> u8 {
    for j in 0..8 {
        v = integers_lookup(v).wrapping_sub(table[off + j]);
    }
    v
}

#[inline]
fn loop_a_byte_reverse(mut v: u8, table: &[u8; 264], off: usize) -> u8 {
    for j in (0..8).rev() {
        v = integers_index_of(v.wrapping_add(table[off + j]));
    }
    v
}

/// Decrypt one 8-byte block. `block_counter == block_index * 8`.
pub fn decrypt_block(c: &[u8], block_counter: u32, table: &[u8; 264]) -> [u8; 8] {
    let cur_id = block_counter >> 3;
    let (off, e_val, f_val) = block_counter_setup(block_counter);
    let (sk1, sk2) = special_key(e_val, f_val);

    let mut d = [0u8; 8];
    d[0] = loop_a_byte(((cur_id ^ 0x45) as u8) ^ c[0], table, off);
    for k in 1..8 {
        d[k] = loop_a_byte(c[k - 1] ^ c[k], table, off);
    }

    let mut higher = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
    let mut lower = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let xor_lower = u32::from_le_bytes(table[off..off + 4].try_into().unwrap());
    let xor_higher = u32::from_le_bytes(table[off + 4..off + 8].try_into().unwrap());

    let borrow = u32::from(lower < xor_lower);
    lower = lower.wrapping_sub(xor_lower);
    higher = higher.wrapping_sub(xor_higher).wrapping_sub(borrow);
    lower ^= sk1 as u32;
    higher ^= sk2 as u32;
    lower ^= xor_lower;
    higher ^= xor_higher;

    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&higher.to_le_bytes());
    out[4..8].copy_from_slice(&lower.to_le_bytes());
    out
}

/// Encrypt one 8-byte block. `block_counter == block_index * 8`.
pub fn encrypt_block(c: &[u8], block_counter: u32, table: &[u8; 264]) -> [u8; 8] {
    let cur_id = block_counter >> 3;
    let (off, e_val, f_val) = block_counter_setup(block_counter);
    let (sk1, sk2) = special_key(e_val, f_val);
    let xor_lower = u32::from_le_bytes(table[off..off + 4].try_into().unwrap());
    let xor_higher = u32::from_le_bytes(table[off + 4..off + 8].try_into().unwrap());

    let mut low = u32::from_le_bytes(c[4..8].try_into().unwrap());
    let mut high = u32::from_le_bytes(c[0..4].try_into().unwrap());

    low ^= xor_lower;
    high ^= xor_higher;
    low ^= sk1 as u32;
    high ^= sk2 as u32;
    low = low.wrapping_add(xor_lower);
    high = high.wrapping_add(xor_higher);
    let carry = u32::from(low < xor_lower);
    high = high.wrapping_add(carry);

    let mut computed = [0u8; 8];
    computed[0..4].copy_from_slice(&low.to_le_bytes());
    computed[4..8].copy_from_slice(&high.to_le_bytes());

    let mut out = [0u8; 8];
    let mut prev = (cur_id ^ 0x45) as u8;
    for k in 0..8 {
        let v = loop_a_byte_reverse(computed[k], table, off) ^ prev;
        out[k] = v;
        prev = v;
    }
    out
}

/// Read the BE `dataSize` field at offset 16 and return `body_size = dataSize + 8`.
pub fn body_size(data: &[u8]) -> Result<usize> {
    ensure!(data.len() >= PREAMBLE + REMAINDER, "file too small");
    let data_size = u32::from_be_bytes(data[16..20].try_into().unwrap()) as usize;
    Ok(data_size + 8)
}

/// Sum of every 4th byte over `nblocks` samples starting at `start`.
fn compute_checksum(data: &[u8], start: usize, nblocks: usize) -> u32 {
    let mut total: u32 = 0;
    for i in 0..nblocks {
        total = total.wrapping_add(data[start + 4 * i] as u32);
    }
    total
}

/// Decrypt a whole filelist (the `body_size` region from offset 32).
pub fn decrypt_filelist(data: &[u8]) -> Result<Vec<u8>> {
    let bs = body_size(data)?;
    ensure!(bs % 8 == 0, "encrypted body size not a multiple of 8");
    ensure!(data.len() >= PREAMBLE + bs, "truncated filelist");
    let table = generate_xor_table(seed_from_header(data));

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..PREAMBLE]);
    for i in 0..bs / 8 {
        let p = PREAMBLE + i * 8;
        out.extend_from_slice(&decrypt_block(&data[p..p + 8], (i as u32) * 8, &table));
    }
    out.extend_from_slice(&data[PREAMBLE + bs..]);
    Ok(out)
}

/// Encrypt a whole (decrypted) filelist: writes the checksum then encrypts.
pub fn encrypt_filelist(data: &[u8]) -> Result<Vec<u8>> {
    let bs = body_size(data)?;
    ensure!(bs % 8 == 0, "encrypted body size not a multiple of 8");
    ensure!(data.len() >= PREAMBLE + bs, "truncated filelist");

    let nblocks = (bs - 8) / 4;
    let checksum = compute_checksum(data, PREAMBLE, nblocks);

    let mut body = data[PREAMBLE..PREAMBLE + bs].to_vec();
    body[bs - 4..bs].copy_from_slice(&checksum.to_le_bytes());

    let table = generate_xor_table(seed_from_header(data));
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..PREAMBLE]);
    for i in 0..bs / 8 {
        let p = i * 8;
        out.extend_from_slice(&encrypt_block(&body[p..p + 8], (i as u32) * 8, &table));
    }
    out.extend_from_slice(&data[PREAMBLE + bs..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_table_matches_oracle_first_block() {
        // seed = b4 6b ea 85 ff ff ff ff -> oracle block 0 = B0BDA7BC3AA0B614
        let t = generate_xor_table([0xb4, 0x6b, 0xea, 0x85, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(&t[0..8], &[0xB0, 0xBD, 0xA7, 0xBC, 0x3A, 0xA0, 0xB6, 0x14]);
        // file seed 85 ea 6b b4 ff ff ff ff -> oracle block 0 = 2F717812E85E0CAA
        let t2 = generate_xor_table([0x85, 0xea, 0x6b, 0xb4, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(&t2[0..8], &[0x2F, 0x71, 0x78, 0x12, 0xE8, 0x5E, 0x0C, 0xAA]);
    }

    #[test]
    fn block_roundtrip() {
        let table = generate_xor_table([0x85, 0xea, 0x6b, 0xb4, 0xff, 0xff, 0xff, 0xff]);
        let plain = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        for bc in [0u32, 8, 64, 1024] {
            let enc = encrypt_block(&plain, bc, &table);
            let dec = decrypt_block(&enc, bc, &table);
            assert_eq!(dec, plain, "roundtrip at bc={bc}");
        }
    }
}
