use super::{aes::*, constant::NUM_ROUND_KEYS_128};
use rand::{thread_rng, Rng};

fn transmute_and_encrypt(
    state: &[u8; 16],
    output: &mut Vec<u8>,
    key_schedule: &[AesBlock; NUM_ROUND_KEYS_128],
) -> [u8; 16] {
    unsafe {
        let mut block: AesBlock = std::mem::transmute(state.to_owned());
        encrypt_block(&mut block, key_schedule);
        let encrypted: [u8; 16] = std::mem::transmute(block);
        output.extend_from_slice(&encrypted);

        //prev_state = encrypted;
        return encrypted;
    }
}

pub fn cbc_encrypt(input: &[u8], key: &AesKey128) -> Vec<u8> {
    assert_eq!(key.len(), 16);

    // not a cryptographically secure IV generation implementation
    let mut iv = [0u8; 16];
    thread_rng().fill(&mut iv[..]);

    println!("\niv:");
    for byte in iv {
        print!("{:02x?}", byte);
    }
    println!();

    let mut prev_state = iv;

    let padding = 16 - (input.len() % 16);
    let padding = if padding == 0 { 16 } else { padding };

    let output_size = input.len() + padding + 16;
    let mut output = Vec::with_capacity(output_size);
    output.extend_from_slice(&iv);

    let mut key_schedule: [AesBlock; NUM_ROUND_KEYS_128] = Default::default();
    key_schedule_128(key, &mut key_schedule);

    let mut input_offset = 0;

    while input_offset < input.len() {
        let mut state = [0u8; 16];
        let bytes_remaining = input.len() - input_offset;
        let block_size = bytes_remaining.min(16);

        // fill block from input with indexation from the current block up to a maximum block size
        // of 16 bytes
        state[..block_size].copy_from_slice(&input[input_offset..input_offset + block_size]);

        // if we are on the final block and there was not enough remaining input data, pad out the
        // remaining bytes to reach the expected block size
        if block_size < 16 {
            for i in block_size..16 {
                state[i] = padding as u8;
            }
        }

        for (curr, prev) in state.iter_mut().zip(prev_state.iter()) {
            *curr ^= prev;
        }
        //for i in 0..16 {
        //    state[i] ^= prev_state[i];
        //}

        prev_state = transmute_and_encrypt(&state, &mut output, &key_schedule);
        input_offset += 16;
    }

    if padding == 16 && input.len() % 16 == 0 {
        let mut state = [padding as u8; 16];
        for (curr, prev) in state.iter_mut().zip(prev_state.iter()) {
            *curr ^= prev;
        }

        let _prev_state = transmute_and_encrypt(&state, &mut output, &key_schedule);
    }

    return output;
}

pub fn cbc_decrypt(key: AesKey128, input: &[u8]) -> Option<Vec<u8>> {
    // retrieve iv
    let mut prev_state = &input[..16];
    let mut key_schedule: [AesBlock; NUM_ROUND_KEYS_128] = Default::default();
    key_schedule_128(&key, &mut key_schedule);

    let mut output = Vec::with_capacity(input.len() - 16);
    let mut last_byte = 0u8;
    let mut input_offset = 16;

    while input_offset < input.len() {
        let curr_block = &input[input_offset..input_offset + 16];

        unsafe {
            let mut state: AesBlock =
                std::mem::transmute(*<&[u8; 16]>::try_from(curr_block).unwrap());
            decrypt_block(&mut state, &key_schedule);

            let mut decrypted: [u8; 16] = std::mem::transmute(state);
            for (curr, prev) in decrypted.iter_mut().zip(prev_state.iter()) {
                *curr ^= prev;
            }

            // verify padding if curr_block is the last block
            if input_offset + 16 == input.len() {
                last_byte = decrypted[15];
                if last_byte == 0 || last_byte > 16 {
                    return None;
                }

                for i in 16 - last_byte..15 {
                    if decrypted[i as usize] != last_byte {
                        return None;
                    }
                }
            }

            output.extend_from_slice(&decrypted);
        }

        input_offset += 16;
        prev_state = curr_block;
    }

    output.truncate(output.len() - last_byte as usize);
    return Some(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbc_padding_needed() {
        let key: AesKey128 = [0x61; 16];
        let input: [u8; 9] = [0x41; 9];

        let enc = cbc_encrypt(&input, &key);
        let enc_clone = enc.clone();

        let dec = cbc_decrypt(key, &enc_clone);

        assert!(dec.is_some());
        assert_eq!(dec.unwrap(), input);
    }

    #[test]
    fn test_cbc_full_block() {
        let key: AesKey128 = [0x61; 16];
        let input: [u8; 16] = [0x41; 16];

        let enc = cbc_encrypt(&input, &key);
        let enc_clone = enc.clone();

        let dec = cbc_decrypt(key, &enc_clone);

        assert!(dec.is_some());
        assert_eq!(dec.unwrap(), input);
    }
}
