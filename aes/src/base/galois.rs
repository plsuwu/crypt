const fn gf_mult(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a_tmp: u8 = a;
    let mut b_tmp: u8 = b;

    let mut i: u8 = 0;
    while i < 8 {
        if b_tmp & 1 == 1 {
            result ^= a_tmp;
        }

        let msb = a_tmp & 0x80;
        a_tmp <<= 1;

        if msb != 0 {
            a_tmp ^= 0x1b;
        }

        b_tmp >>= 1;
        i += 1;
    }

    result
}

pub const GF_MUL_TABLE: [[u8; 256]; 256] = {
    let mut table = [[0u8; 256]; 256];
    let mut i = 0;

    while i < 256 {
        let mut j = 0;
        while j < 256 {
            table[i][j] = gf_mult(i as u8, j as u8);
            j += 1;
        }

        i += 1;
    }

    table
};

pub fn gf_mult_fast(a: u8, b: u8) -> u8 {
    // table resolved at compile time - uses ~64kb of memory, could be optimized
    // for size as we only use specific regions of this table.
    GF_MUL_TABLE[a as usize][b as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mult() {
        let a: u8 = 0x57;
        let enc_b: u8 = 0x13;
        let dec_b = 1;

        let enc_r: u8 = gf_mult_fast(a, enc_b);
        let dec_r: u8 = gf_mult_fast(a, dec_b);

        assert_eq!(enc_r, 0xfe);
        assert_eq!(dec_r, a);
    }
}
