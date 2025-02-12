use cbc::cbc::Aes128Cbc;

pub mod base;
pub mod cbc;
pub mod tables;

pub fn aes(crypt_type: &str, d_key: Option<Vec<u8>>) -> Aes128Cbc {
    let mut key = [0u8; 16];

    if d_key != None {
        key.copy_from_slice(&d_key.unwrap());
    } else {
        // similar to IV generation, probably not "secure" but good enough if we're just
        // encrypting shellcode for malware
        rand::fill(&mut key);
    }

    let out = match crypt_type {
        //"128cbc" => Aes128Cbc::new(key),
        _ => Aes128Cbc::new(key),
    };

    out
}
