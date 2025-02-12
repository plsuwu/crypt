use rand::{rng, RngCore};

use crate::base::{base::Aes128, state::State};

#[derive(Debug)]
pub struct Aes128Cbc {
    pub aes: Aes128,
    pub iv: [u8; 16],
}

impl Aes128Cbc {
    pub fn new(key: [u8; 16]) -> Self {

        // this is probably not a secure implementation for 
        // generating IV data
        let mut iv = [0u8; 16];
        rng().fill_bytes(&mut iv[..]);

        Self {
            aes: Aes128::new(key),
            iv,
        }
    }

    fn xor_blocks(block: &mut [u8; 16], prev_block: &[u8; 16]) {
        for (curr, prev) in block.iter_mut().zip(prev_block.iter()) {
            *curr ^= prev;
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let padding = 16 - (plaintext.len() % 16);
        let padding = if padding == 0 { 16 } else { padding };

        let mut result = Vec::with_capacity(plaintext.len() + padding + 16);
        result.extend_from_slice(&self.iv);

        let mut prev_state = State::new(&self.iv);
        let mut offset = 0;
        while offset < plaintext.len() {
            let remaining_bytes = plaintext.len() - offset;
            let block_size = remaining_bytes.min(16);

            let mut chunk = [0u8; 16];
            chunk[..block_size].copy_from_slice(&plaintext[offset..offset + block_size]);

            if block_size < 16 {
                for i in block_size..16 {
                    chunk[i] = padding as u8;
                }
            }
            
            
            Self::xor_blocks(&mut chunk, &prev_state.flat);

            prev_state = State::new(&chunk);
            prev_state.encrypt_block(self.aes);
            result.extend_from_slice(&prev_state.flat);

            offset += 16;
        }

        if padding == 16 && plaintext.len() % 16 == 0 {
            let mut chunk = [padding as u8; 16];

            Self::xor_blocks(&mut chunk, &prev_state.flat);
            prev_state = State::new(&chunk);
            prev_state.encrypt_block(self.aes);
            result.extend_from_slice(&prev_state.flat);
            
        }
        
        let mut output = Vec::with_capacity(result.len() - 16);
        output.extend_from_slice(&result[16..]);

        output.to_vec()
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        // ...

        todo!();
    }
}
