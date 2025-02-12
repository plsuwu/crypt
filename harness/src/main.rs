use aes::aes;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    #[arg(short, long)]
    crypter: String,
    
    // this should become a filepath tbf
    #[arg(short, long)]
    data: String,
    
    // this should be implied by the precense of a key??
    #[arg(long)]
    direction: Option<String>,

    #[arg(short, long)]
    key: Option<String>,
}

fn unpack_key(key: String) -> Vec<u8> {
    let key_bytes = key.as_bytes().to_owned();
    key_bytes
}

fn main() {
    let args = Args::parse();
    let crypter = args.crypter.as_str();
    
    /* 
     *  this was kind of just lazily done, i probably wont do a full
     *  CLI thing tbh
     */
    println!("{}", crypter);

    let crypt = match crypter {
        "aes" => {
            if args.key.is_some() {
                let raw_key = args.key.unwrap();
                aes("cbc128", Some(unpack_key(raw_key)))
            } else {
                aes("cbc128", None)
            }
        },
        _ => todo!(),
    };
    
    /* =========================================================== */
    
    println!("[+] KEY:");
    for byte in crypt.aes.key {
        print!("{:02x?}", byte);    
    }
    println!();

    println!("[+] IV:");
    for byte in crypt.iv {
        print!("{:02x?}", byte);    
    }
    println!();
    
    let input_data = args.data.as_str().as_bytes();
    let output = crypt.encrypt(input_data);

    println!("[+] OUT:");
    for byte in output {
        print!("{:02x?}", byte);    
    }
    println!();
}
