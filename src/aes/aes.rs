use super::constant::*;

pub type AesColumn = [u8; 4];
pub type AesBlock = [AesColumn; 4];
pub type AesKey128 = [u8; 16];

pub fn gf_mult(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a: u16 = a as u16;
    let mut b: u8 = b;

    // loop through each bit in `b`
    for _ in 0..8 {
        // if b's LSB is set (i.e, we are not multiplying out by 0 for this term)
        // xor the result with `a` (equiv. to adding polynomial terms of a)
        if b & 1 == 1 {
            result ^= a;
        }

        // track a's MSB to determine whether `a` is still within
        // the bounds of the field
        let msb = a & 0x80;
        a <<= 1; // double a

        // next bit in `b` represents multiplying a's terms by the next power
        // of 2 (equiv. to shifting `a` left) - need to modulo with irreducible
        // polynomial term if `a` left the field
        if msb != 0 {
            a ^= 0x11b;
        }

        // shift `b` right to operate on the next bit (worth twice as much
        // in the multiplication)
        b >>= 1;
    }

    return result as u8;
}

pub fn gf_word_add(a: AesColumn, b: AesColumn, dest: &mut AesColumn) {
    dest[0] = a[0] ^ b[0];
    dest[1] = a[1] ^ b[1];
    dest[2] = a[2] ^ b[2];
    dest[3] = a[3] ^ b[3];
}

pub fn key_schedule_128(key: &AesKey128, keys_out: &mut [AesBlock; NUM_ROUND_KEYS_128]) {
    // `AesBlock` and `AesKey128` are both 16-byte structures
    // [[u8; 4]; 4] -> [u8; 16]
    let key_block: &AesBlock = unsafe { std::mem::transmute(key) };
    keys_out[0] = *key_block;

    let mut col_c = keys_out[0][3];
    for i in 0..NUM_ROUND_KEYS_128 - 1 {
        rot_word(&mut col_c);
        sub_word(&mut col_c, &SBOX_ENCRYPT);
        gf_word_add(col_c, RCON[i], &mut col_c);

        // compute the next key round
        gf_word_add(col_c, keys_out[i][0], &mut keys_out[i + 1][0]);
        gf_word_add(keys_out[i + 1][0], keys_out[i][1], &mut keys_out[i + 1][1]);
        gf_word_add(keys_out[i + 1][1], keys_out[i][2], &mut keys_out[i + 1][2]);
        gf_word_add(keys_out[i + 1][2], keys_out[i][3], &mut keys_out[i + 1][3]);

        // update last col for next round
        col_c = keys_out[i + 1][3];
    }
}

pub fn mix_columns(state: &mut AesBlock) {
    let mut tmp: AesColumn = [0, 0, 0, 0];

    for i in 0..4 {
        tmp[0] =
            gf_mult(0x02, state[i][0]) ^ gf_mult(0x03, state[i][1]) ^ state[i][2] ^ state[i][3];
        tmp[1] =
            state[i][0] ^ gf_mult(0x02, state[i][1]) ^ gf_mult(0x03, state[i][2]) ^ state[i][3];
        tmp[2] =
            state[i][0] ^ state[i][1] ^ gf_mult(0x02, state[i][2]) ^ gf_mult(0x03, state[i][3]);
        tmp[3] =
            gf_mult(0x03, state[i][0]) ^ state[i][1] ^ state[i][2] ^ gf_mult(0x02, state[i][3]);

        state[i][0] = tmp[0];
        state[i][1] = tmp[1];
        state[i][2] = tmp[2];
        state[i][3] = tmp[3];
    }
}

pub fn inv_mix_columns(state: &mut AesBlock) {
    let mut tmp: AesColumn = [0, 0, 0, 0];

    for i in 0..4 {
        tmp[0] = gf_mult(0x0e, state[i][0])
            ^ gf_mult(0x0b, state[i][1])
            ^ gf_mult(0x0d, state[i][2])
            ^ gf_mult(0x09, state[i][3]);

        tmp[1] = gf_mult(0x09, state[i][0])
            ^ gf_mult(0x0e, state[i][1])
            ^ gf_mult(0x0b, state[i][2])
            ^ gf_mult(0x0d, state[i][3]);

        tmp[2] = gf_mult(0x0d, state[i][0])
            ^ gf_mult(0x09, state[i][1])
            ^ gf_mult(0x0e, state[i][2])
            ^ gf_mult(0x0b, state[i][3]);

        tmp[3] = gf_mult(0x0b, state[i][0])
            ^ gf_mult(0x0d, state[i][1])
            ^ gf_mult(0x09, state[i][2])
            ^ gf_mult(0x0e, state[i][3]);

        state[i][0] = tmp[0];
        state[i][1] = tmp[1];
        state[i][2] = tmp[2];
        state[i][3] = tmp[3];
    }
}

pub fn rot_word(word: &mut AesColumn) {
    let tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

pub fn sub_bytes(state: &mut AesBlock, table: &[u8]) {
    let mut index: usize;

    for col in 0..4 {
        for row in 0..4 {
            index = state[col][row] as usize;
            state[col][row] = table[index];
        }
    }
}

pub fn sub_word(word: &mut AesColumn, table: &[u8]) {
    let mut index: usize;

    for i in 0..4 {
        index = word[i] as usize;
        word[i] = table[index];
    }
}

pub fn shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut tmp_a: u8;
    let tmp_b: u8;

    // shift row 1
    // [0] [1] [2] [3] --> [1] [2] [3] [0]
    tmp_a = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = tmp_a;

    // shift row 2
    // [0] [1] [2] [3] --> [2] [3] [0] [1]
    tmp_a = state[0][2];
    tmp_b = state[1][2];
    state[0][2] = state[2][2];
    state[1][2] = state[3][2];
    state[2][2] = tmp_a;
    state[3][2] = tmp_b;

    //shift row 3
    //[0] [1] [2] [3] --> [3] [0] [1] [2]
    tmp_a = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = state[0][3];
    state[0][3] = tmp_a;
}

pub fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut tmp_a: u8;
    let tmp_b: u8;

    // shift row 1
    // [0] [1] [2] [3] --> [3] [0] [1] [2]
    tmp_a = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = tmp_a;

    // shift row 2
    // [0] [1] [2] [3] --> [2] [3] [0] [1]
    tmp_a = state[0][2];
    tmp_b = state[1][2];
    state[0][2] = state[2][2];
    state[1][2] = state[3][2];
    state[2][2] = tmp_a;
    state[3][2] = tmp_b;

    // shift row 3
    // [0] [1] [2] [3] --> [1] [2] [3] [0]
    tmp_a = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = tmp_a;
}

pub fn add_round_key(state: &mut AesBlock, round_key: &AesBlock) {
    for col in 0..4 {
        for row in 0..4 {
            state[col][row] ^= round_key[col][row];
        }
    }
}

pub fn encrypt_block(state: &mut AesBlock, key_schedule: &[AesBlock]) {
    assert_eq!(key_schedule.len(), NUM_ROUND_KEYS_128);

    add_round_key(state, &key_schedule[0]);
    for i in 1..NUM_ROUND_KEYS_128 {
        sub_bytes(state, &SBOX_ENCRYPT);
        shift_rows(state);

        // opting out of a column mix on the last round like this
        // constitutes a timing-based side-channel risk
        if i < NUM_ROUND_KEYS_128 - 1 {
            mix_columns(state);
        }

        add_round_key(state, &key_schedule[i]);
    }
}

pub fn decrypt_block(state: &mut AesBlock, key_schedule: &[AesBlock]) {
    assert_eq!(key_schedule.len(), NUM_ROUND_KEYS_128);

    let mut rnd = NUM_ROUND_KEYS_128 - 1;
    for i in 1..NUM_ROUND_KEYS_128 {
        add_round_key(state, &key_schedule[rnd]);
        rnd = rnd.wrapping_sub(1);

        if i != 1 {
            inv_mix_columns(state);
        }

        inv_shift_rows(state);
        sub_bytes(state, &SBOX_DECRYPT);
    }

    add_round_key(state, &key_schedule[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mult() {
        let a: u8 = 0x57;
        let enc_b: u8 = 0x13;
        let dec_b = 1;
        let enc_r: u8 = gf_mult(a, enc_b);
        let dec_r: u8 = gf_mult(a, dec_b);

        assert_eq!(enc_r, 0xfe);
        assert_eq!(dec_r, a);
    }

    #[test]
    fn test_sub_bytes() {
        let mut state: AesBlock = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];

        let enc_expected = [
            [0x7c, 0x77, 0x7b, 0xf2],
            [0x6b, 0x6f, 0xc5, 0x30],
            [0x01, 0x67, 0x2b, 0xfe],
            [0xd7, 0xab, 0x76, 0xca],
        ];

        let dec_expected = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];

        sub_bytes(&mut state, &SBOX_ENCRYPT);
        assert_eq!(state, enc_expected);

        sub_bytes(&mut state, &SBOX_DECRYPT);
        assert_eq!(state, dec_expected);
    }

    #[test]
    fn test_shift_rows() {
        let mut state: AesBlock = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];

        let expected_shift: AesBlock = [
            [1, 6, 11, 16],
            [5, 10, 15, 4],
            [9, 14, 3, 8],
            [13, 2, 7, 12],
        ];

        shift_rows(&mut state);
        assert_eq!(state, expected_shift);
    }

    #[test]
    fn test_inv_shift_rows() {
        let mut state: AesBlock = [
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            [9, 10, 11, 12],
            [13, 14, 15, 16],
        ];
        let expected_shift: AesBlock = [
            [1, 14, 11, 8],
            [5, 2, 15, 12],
            [9, 6, 3, 16],
            [13, 10, 7, 4],
        ];

        inv_shift_rows(&mut state);
        assert_eq!(state, expected_shift);
    }

    #[test]
    fn test_mix_columns() {
        let mut state: AesBlock = [
            [0xd4, 0xbf, 0x5d, 0x30],
            [0xe0, 0xb4, 0x52, 0xae],
            [0xb8, 0x41, 0x11, 0xf1],
            [0x1e, 0x27, 0x98, 0xe5],
        ];

        let expected_output: AesBlock = [
            [0x04, 0x66, 0x81, 0xe5],
            [0xe0, 0xcb, 0x19, 0x9a],
            [0x48, 0xf8, 0xd3, 0x7a],
            [0x28, 0x06, 0x26, 0x4c],
        ];

        mix_columns(&mut state);
        assert_eq!(state, expected_output);
    }

    #[test]
    fn test_key_schedule() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let mut key_schedule: [AesBlock; NUM_ROUND_KEYS_128] = Default::default();
        let expected: [AesBlock; NUM_ROUND_KEYS_128] = [
            [
                [0x2b, 0x7e, 0x15, 0x16],
                [0x28, 0xae, 0xd2, 0xa6],
                [0xab, 0xf7, 0x15, 0x88],
                [0x09, 0xcf, 0x4f, 0x3c],
            ],
            [
                [0xa0, 0xfa, 0xfe, 0x17],
                [0x88, 0x54, 0x2c, 0xb1],
                [0x23, 0xa3, 0x39, 0x39],
                [0x2a, 0x6c, 0x76, 0x05],
            ],
            [
                [0xf2, 0xc2, 0x95, 0xf2],
                [0x7a, 0x96, 0xb9, 0x43],
                [0x59, 0x35, 0x80, 0x7a],
                [0x73, 0x59, 0xf6, 0x7f],
            ],
            [
                [0x3d, 0x80, 0x47, 0x7d],
                [0x47, 0x16, 0xfe, 0x3e],
                [0x1e, 0x23, 0x7e, 0x44],
                [0x6d, 0x7a, 0x88, 0x3b],
            ],
            [
                [0xef, 0x44, 0xa5, 0x41],
                [0xa8, 0x52, 0x5b, 0x7f],
                [0xb6, 0x71, 0x25, 0x3b],
                [0xdb, 0x0b, 0xad, 0x00],
            ],
            [
                [0xd4, 0xd1, 0xc6, 0xf8],
                [0x7c, 0x83, 0x9d, 0x87],
                [0xca, 0xf2, 0xb8, 0xbc],
                [0x11, 0xf9, 0x15, 0xbc],
            ],
            [
                [0x6d, 0x88, 0xa3, 0x7a],
                [0x11, 0x0b, 0x3e, 0xfd],
                [0xdb, 0xf9, 0x86, 0x41],
                [0xca, 0x00, 0x93, 0xfd],
            ],
            [
                [0x4e, 0x54, 0xf7, 0x0e],
                [0x5f, 0x5f, 0xc9, 0xf3],
                [0x84, 0xa6, 0x4f, 0xb2],
                [0x4e, 0xa6, 0xdc, 0x4f],
            ],
            [
                [0xea, 0xd2, 0x73, 0x21],
                [0xb5, 0x8d, 0xba, 0xd2],
                [0x31, 0x2b, 0xf5, 0x60],
                [0x7f, 0x8d, 0x29, 0x2f],
            ],
            [
                [0xac, 0x77, 0x66, 0xf3],
                [0x19, 0xfa, 0xdc, 0x21],
                [0x28, 0xd1, 0x29, 0x41],
                [0x57, 0x5c, 0x00, 0x6e],
            ],
            [
                [0xd0, 0x14, 0xf9, 0xa8],
                [0xc9, 0xee, 0x25, 0x89],
                [0xe1, 0x3f, 0x0c, 0xc8],
                [0xb6, 0x63, 0x0c, 0xa6],
            ],
        ];

        key_schedule_128(&key, &mut key_schedule);
        assert_eq!(key_schedule, expected);
    }

    #[test]
    fn test_block_encrypt_from_key_schedule() {
        let mut input: AesBlock = [
            [0x32, 0x43, 0xf6, 0xa8],
            [0x88, 0x5a, 0x30, 0x8d],
            [0x31, 0x31, 0x98, 0xa2],
            [0xe0, 0x37, 0x07, 0x34],
        ];

        let expected: AesBlock = [
            [0x39, 0x25, 0x84, 0x1d],
            [0x02, 0xdc, 0x09, 0xfb],
            [0xdc, 0x11, 0x85, 0x97],
            [0x19, 0x6a, 0x0b, 0x32],
        ];
        let mut round_keys: [AesBlock; NUM_ROUND_KEYS_128] = Default::default();
        let key: AesKey128 = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        key_schedule_128(&key, &mut round_keys);
        encrypt_block(&mut input, &round_keys);

        assert_eq!(input, expected);
    }

    #[test]
    fn test_block_decrypt_from_key_schedule() {
        let mut input: AesBlock = [
            [0x39, 0x25, 0x84, 0x1d],
            [0x02, 0xdc, 0x09, 0xfb],
            [0xdc, 0x11, 0x85, 0x97],
            [0x19, 0x6a, 0x0b, 0x32],
        ];

        let expected: AesBlock = [
            [0x32, 0x43, 0xf6, 0xa8],
            [0x88, 0x5a, 0x30, 0x8d],
            [0x31, 0x31, 0x98, 0xa2],
            [0xe0, 0x37, 0x07, 0x34],
        ];

        let mut round_keys: [AesBlock; NUM_ROUND_KEYS_128] = Default::default();
        let key: AesKey128 = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        key_schedule_128(&key, &mut round_keys);
        decrypt_block(&mut input, &round_keys);

        assert_eq!(input, expected);
    }
}
