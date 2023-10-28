use clap::{arg, command, value_parser, ArgAction, Command, Arg};
use sha2::{Sha256, Sha512, Digest};
#[derive(Debug)]
enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
}
fn main() {
    // Get hash and dictionary from user as args
    let args = command!()
    .about("Crack hashes using a dictionary")
    .author("Noman Nasir Minhas")
    .version("1.0.0")
        .arg_required_else_help(true)
        .arg(
            Arg::new("hash")                
                .short('c')
                .long("hash")
                .required(true)                
                .help("Hash to crack"),
        )
        .arg(
            Arg::new("dict")
                .short('d')
                .long("dict")                
                .required(true)                
                .help("Dictionary file to use"),
        )
        .arg(
            Arg::new("index")
                .short('i')
                .long("index")                
                .action(ArgAction::SetTrue)
                .help("Maintain index of checked hashes"),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")                                
                .default_value("1")
                .help("Number of threads to use"),
                
        )
        .get_matches();
        
    let hash = args.get_one::<String>("hash").unwrap().to_owned();
    let dict = args.get_one::<String>("dict").unwrap();
    let index = args.get_flag("index");
    let threads = args.get_one::<String>("threads").unwrap();
    let hash_type = get_hash_type(hash.as_ref());    

    // Maximum number of threads
    if threads.parse::<usize>().unwrap() > 10 {
        panic!("Maximum number of threads is 10");
    }
    println!("Detected Hash Type: {:?}", hash_type);
    
    let input_hash_fn = match hash_type {
        HashType::MD5 => get_md5_hash,
        HashType::SHA1 => get_sha1_hash,
        HashType::SHA256 => get_sha256_hash,
        HashType::SHA512 => get_sha512_hash,
    };
    
    // Read dictionary file
    let mut dict = std::fs::read_to_string(dict).expect("Error reading dictionary file");    
    dict = dict.replace("\r", "");
    let mut dict: Vec<&str> = dict.split("\n").collect();

    // Loop through dictionary and check if hash matches
    let mut found = false;

    // Start timer
    let now = std::time::Instant::now();
    for (i, word) in dict.iter().enumerate() {
        let word = word.trim();
        let word_hash = input_hash_fn(word);
        if word_hash == hash {
            println!("Found match: {}", word);
            found = true;
            break;
        }
        if index {
            println!("{}: {}", i, word);
        }
    }
    let elapsed = now.elapsed();
    if !found {
        println!("No match found");
    }
    println!("Time elapsed: {:?}", elapsed);


}

fn get_hash_type(hash: &str) -> HashType {
    match hash.len() {
        32 => HashType::MD5,
        40 => HashType::SHA1,
        64 => HashType::SHA256,
        128 => HashType::SHA512,
        _ => panic!("Not a valid hash. Hash must be MD5, SHA1, SHA256, or SHA512"),
    }
}

fn get_sha1_hash(word: &str) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(word);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn get_sha256_hash(word: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(word);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn get_sha512_hash(word: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(word);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn get_md5_hash(word: &str) -> String {    
    let result = md5::compute(word);
    format!("{:x}", result)
}
