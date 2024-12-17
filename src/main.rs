pub mod aes;

use std::io::prelude::*;
use std::{fs::File, io};

use aes::{
    aes::*,
    cbc::{cbc_decrypt, cbc_encrypt},
};

fn main() -> io::Result<()> {
    let mut input_file = File::open("src/aes/test-input")?;
    let mut key_file = File::open("src/aes/test-key")?;

    let mut input_buf: Vec<u8> = Vec::new();
    let mut key_buf: Vec<u8> = Vec::new();

    input_file.read_to_end(&mut input_buf)?;
    key_file.read_to_end(&mut key_buf)?;

    let key: AesKey128 = key_buf.try_into().unwrap();

    let enc_out = cbc_encrypt(&input_buf[..], &key);
    //println!("{:02x?}", enc_out);

    let check_decr = enc_out.clone();
    let dec_out = cbc_decrypt(key, &check_decr);

    return Ok(());
}
