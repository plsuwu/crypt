use crate::{
    base::galois::gf_mult_fast,
    tables::{ROUND_KEYS_128, SBOX_DECRYPT, SBOX_ENCRYPT},
};

use super::base::Aes128;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Inverse,
}

#[derive(Debug)]
pub struct State {
    pub block: [[u8; 4]; 4],
    pub flat: [u8; 16],
    pub direction: Direction,
}

impl State {
    pub fn new(flat: &[u8; 16]) -> Self {
        let block: [[u8; 4]; 4] = unsafe { std::mem::transmute(*flat) };

        Self {
            direction: Direction::Forward,
            block,
            flat: *flat,
        }
    }

    pub fn encrypt_block(&mut self, schedule: Aes128) {
        if self.direction != Direction::Forward {
            self.direction = Direction::Forward;
        }

        self.crypt(schedule);
        self.flat = unsafe { std::mem::transmute(self.block.clone()) };
    }

    pub fn decrypt_block(&mut self, schedule: Aes128) {
        if self.direction != Direction::Inverse {
            self.direction = Direction::Inverse;
        }

        self.crypt(schedule);
        self.flat = unsafe { std::mem::transmute(self.block.clone()) };
    }

    pub fn flip_direction(&mut self) {
        self.direction = match self.direction {
            Direction::Forward => Direction::Inverse,
            Direction::Inverse => Direction::Forward,
        };
    }

    fn crypt(&mut self, schedule: Aes128) {
        self.add_round_key(&schedule.get_round_key(0));

        for i in 1..ROUND_KEYS_128 {
            self.sub_bytes();
            self.shift_rows();

            // vulnerable to timing-based side-channel attack when we opt
            // out of a final round column mix (as per below)
            if i < ROUND_KEYS_128 - 1 {
                self.mix_columns();
            }

            self.add_round_key(&schedule.get_round_key(i));
        }
    }

    pub fn sub_bytes(&mut self) {
        let mut idx;
        let sbox = match self.direction {
            Direction::Forward => SBOX_ENCRYPT,
            Direction::Inverse => SBOX_DECRYPT,
        };

        for col in 0..4 {
            for row in 0..4 {
                idx = self.block[col][row];
                self.block[col][row] = sbox[idx as usize];
            }
        }
    }

    fn shift_rows(&mut self) {
        for i in 1..4 {
            let mut row = [
                self.block[0][i],
                self.block[1][i],
                self.block[2][i],
                self.block[3][i],
            ];

            match self.direction {
                Direction::Forward => row.rotate_left(i),
                Direction::Inverse => row.rotate_right(i),
            }

            for j in 0..4 {
                self.block[j][i] = row[j];
            }
        }
    }

    fn mix_columns(&mut self) {
        const FORWARD_MATRIX: [[u8; 4]; 4] = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ];
        const INVERSE_MATRIX: [[u8; 4]; 4] = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x0b, 0x0e],
        ];

        let matrix = match self.direction {
            Direction::Forward => FORWARD_MATRIX,
            Direction::Inverse => INVERSE_MATRIX,
        };

        for i in 0..4 {
            let tmp: [u8; 4] = (0..4)
                .map(|j| {
                    (0..4)
                        .map(|k| gf_mult_fast(matrix[j][k], self.block[i][k]))
                        .fold(0, |acc, x| acc ^ x)
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            self.block[i] = tmp;
        }
    }

    fn add_round_key(&mut self, round_key: &[u8; 16]) {
        let key_block: [[u8; 4]; 4] = unsafe { std::mem::transmute(*round_key) };

        for col in 0..4 {
            for row in 0..4 {
                self.block[col][row] ^= key_block[col][row];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE_INIT: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const STATE_COLS: [u8; 16] = [
        0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98,
        0xe5,
    ];

    #[test]
    fn forward_test_sub_bytes() {
        let enc_expected = [
            [0x7c, 0x77, 0x7b, 0xf2],
            [0x6b, 0x6f, 0xc5, 0x30],
            [0x01, 0x67, 0x2b, 0xfe],
            [0xd7, 0xab, 0x76, 0xca],
        ];
        let mut output = State::new(&STATE_INIT);
        output.sub_bytes();

        assert_eq!(output.block, enc_expected);
    }

    #[test]
    fn forward_shift_rows_test() {
        let expected_shift = [
            [1, 6, 11, 16],
            [5, 10, 15, 4],
            [9, 14, 3, 8],
            [13, 2, 7, 12],
        ];
        let mut output = State::new(&STATE_INIT);
        output.shift_rows();

        assert_eq!(output.block, expected_shift);
    }

    #[test]
    fn inverse_shift_rows_test() {
        let expected_shift = [
            [1, 14, 11, 8],
            [5, 2, 15, 12],
            [9, 6, 3, 16],
            [13, 10, 7, 4],
        ];
        let mut output = State::new(&STATE_INIT);
        output.flip_direction();
        output.shift_rows();

        assert_eq!(output.block, expected_shift);
    }

    #[test]
    fn foward_mix_columns_test() {
        let mut output = State::new(&STATE_COLS);
        let expected_output = [
            [0x04, 0x66, 0x81, 0xe5],
            [0xe0, 0xcb, 0x19, 0x9a],
            [0x48, 0xf8, 0xd3, 0x7a],
            [0x28, 0x06, 0x26, 0x4c],
        ];
        output.mix_columns();

        assert_eq!(output.block, expected_output);
    }
}
