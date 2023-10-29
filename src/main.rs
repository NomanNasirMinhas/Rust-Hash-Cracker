use clap::{arg, command, value_parser, ArgAction, Command, Arg};
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    };
use std::sync::{Arc, Mutex, Condvar};
use std::sync::mpsc;
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
    if threads.parse::<usize>().unwrap() > 100 {
        panic!("Maximum number of threads is 100");
    }

    if threads.parse::<usize>().unwrap() < 1 {
        panic!("Minimum number of threads is 1");
    }
    println!("Detected Hash Type: {:?}", hash_type);
    
    let input_hash_fn = match hash_type {
        HashType::MD5 => get_md5_hash,
        HashType::SHA1 => get_sha1_hash,
        HashType::SHA256 => get_sha256_hash,
        HashType::SHA512 => get_sha512_hash,
    };
    
    // Read dictionary file
    let wordlist_file = File::open(dict).expect("Error opening dictionary file");
    let reader = BufReader::new(&wordlist_file);
    let words = reader.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
    println!("Total words in dictionary: {}", words.len());
    
    // Start timer
    let mut handles = vec![];    
    let mut chunk_size = words.len() / threads.parse::<usize>().unwrap();
    if chunk_size == 0 {
        chunk_size = 1;
    }
    let (sender, receiver) = mpsc::channel();
    let stop_signal = Arc::new((Mutex::new(false), Condvar::new()));
    let not_found_count = Arc::new((Mutex::new(0), Condvar::new()));;
    let now = std::time::Instant::now();
    let mut iterations = words.chunks(chunk_size).len();
    for chunk in words.chunks(chunk_size) {
        let sender = sender.clone();
        let stop_signal = Arc::clone(&stop_signal);
        let not_found_count = Arc::clone(&not_found_count);
        let chunk = chunk.to_vec();
        let input_hash_fn = input_hash_fn.clone();
        let hash = hash.clone();        
        let index = index.clone();
        let handle = std::thread::spawn(move || {
            let iterations = iterations.clone();
            let mut found = false;
            let hash_index: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
            for (i, word) in chunk.iter().enumerate() {
                let word = word.trim();                
                let word_hash = input_hash_fn(word);
                if index {
                    let mut hash_index = hash_index.lock().unwrap();
                    hash_index.push(format!(
                        "{}: {}",
                        word_hash,
                        word
                    ));                    
                }
                if word_hash == hash {
                    found = true;
                    // print with a banner
                    println!("\n*****************************************************");
                    println!("HASH CRACKED TO => {}", word);  
                    println!("*****************************************************\n");
                    let (lock, cvar) = &*stop_signal;
                    let mut stop = lock.lock().unwrap();
                    *stop = true;
                    cvar.notify_all();                                  
                    break;
                }                
            }
            if !found {
                // print with thread id
                let (lock, cvar) = &*not_found_count;
                let mut count = lock.lock().unwrap();
                *count += 1;
                if *count == iterations {
                    println!("\n********************NO MATCH FOUND********************\n");
                    let (lock, cvar) = &*stop_signal;
                    let mut stop = lock.lock().unwrap();
                    *stop = true;
                    cvar.notify_all();
                }
            }
            // Send thread id to main thread
            sender.send(hash_index);
            
        });
        handles.push(handle);
    }

    // Wait for any thread to signal to stop
    let (lock, cvar) = &*stop_signal;
    let mut found_sig = lock.lock().unwrap();
    while !*found_sig{
        found_sig = cvar.wait(found_sig).unwrap();
    }
    let elapsed = now.elapsed();

    println!("Stopping all threads...");
    // Close the sender to signal other threads to stop
    drop(sender);

    // Wait for all threads to finish
    let mut indexed_hashes = 0;
    for _ in 0..threads.parse::<usize>().unwrap() {
        let idx = receiver.recv();
        if idx.is_ok() && index {
            indexed_hashes += idx.unwrap().lock().unwrap().len();
        }
    }

    println!("All threads have finished.");
    println!("Indexed {} Hashes", indexed_hashes);
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
