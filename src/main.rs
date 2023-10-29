use clap::{command, Arg, ArgAction};
use sha2::{Digest, Sha256, Sha512};
use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    path,
};
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
    let hash_path = dict.replace(".txt", format!(".{:?}", hash_type).as_str());

    // Check if index file exists for this dictionary at hash_path
    if path::Path::new(&hash_path).exists() {
        println!("Index File already exists. Using it to crack the hash.");
        let hash_index_file = File::open(hash_path.clone()).expect("Error opening index file");
        let reader = BufReader::new(&hash_index_file);
        let mut hash_index: Vec<String> = Vec::new();
        for line in reader.lines() {
            if line.is_ok() {
                hash_index.push(line.unwrap());
            }
        }
        let mut found = false;
        for hash_word in hash_index.iter() {
            let hash_word = hash_word.split(":").collect::<Vec<&str>>();
            if hash_word[0] == hash {
                found = true;
                // print with a banner
                println!("\n*****************************************************");
                println!("HASH CRACKED TO => {}", hash_word[1]);
                println!("*****************************************************\n");
                return;
            }
        }
        if !found {
            println!("\n********************COULD NOT FIND IN HASH FILE********************\n");
        }
    }
    // Maximum number of threads
    if threads.parse::<usize>().unwrap() > 10 {
        println!("Maximum number of threads is 10");
        return;
    }

    if threads.parse::<usize>().unwrap() < 1 {
        println!("Minimum number of threads is 1");
        return;
    }

    if index {
        println!(
            "Running in index mode. This may take considerable space and longer to crack the hash. But can be useful later on."
        )
    }
    println!("Detected Hash Type: {:?}", hash_type);

    let input_hash_fn = match hash_type {
        HashType::MD5 => get_md5_hash,
        HashType::SHA1 => get_sha1_hash,
        HashType::SHA256 => get_sha256_hash,
        HashType::SHA512 => get_sha512_hash,
    };

    // Check if dictionary file exist

    // Read dictionary file
    println!("Reading dictionary file...{}", dict);
    let wordlist_file = File::open(dict).expect("Error opening dictionary file");
    let reader = BufReader::new(&wordlist_file);
    let mut words: Vec<String> = Vec::new();
    let mut error_count = 0;
    for line in reader.lines() {
        if line.is_ok() {
            words.push(line.unwrap());
        } else {
            error_count += 1;
        }
    }
    println!("Total words in dictionary: {}", words.len());
    println!(
        "Total ignored words in dictionary due to read errors: {}",
        error_count
    );

    let mut handles = vec![];
    let mut chunk_size = words.len() / (threads.parse::<usize>().unwrap() + 1);
    if chunk_size == 0 {
        chunk_size = 1;
    }
    let (sender, receiver) = mpsc::channel();
    let stop_signal = Arc::new((Mutex::new(false), Condvar::new()));
    let not_found_count = Arc::new((Mutex::new(0), Condvar::new()));
    let now = std::time::Instant::now();
    let iterations = words.chunks(chunk_size).len();
    println!("Starting Hash Crack. Hold on tight...");
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
            for word in chunk.iter() {
                let word = word.trim();
                let word_hash = input_hash_fn(word);
                if index {
                    let mut hash_index = hash_index.lock().unwrap();
                    hash_index.push(format!("{}: {}", word_hash, word));
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
                let (lock, _) = &*not_found_count;
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
            let _ = sender.send(hash_index);
        });
        handles.push(handle);
    }

    // Wait for any thread to signal to stop
    let (lock, cvar) = &*stop_signal;
    let mut found_sig = lock.lock().unwrap();
    while !*found_sig {
        found_sig = cvar.wait(found_sig).unwrap();
    }
    let elapsed = now.elapsed();
    println!("Hash Cracked in: {:?}", elapsed);
    println!("Cleaning Up... Please wait.");
    // Close the sender to signal other threads to stop
    drop(sender);

    let indexed_hashes = Arc::new(Mutex::new(Vec::new()));
    if index {
        println!("Reading threads for indexed hashes...");
        // Wait for all threads to finish
        for _ in 0..threads.parse::<usize>().unwrap() {
            let idx = receiver.recv();
            if idx.is_ok() && index {
                let mut indexed_hashes = indexed_hashes.lock().unwrap();
                indexed_hashes.append(&mut idx.unwrap().lock().unwrap());
            }
        }
    }
    println!("All threads have finished.");

    if index {
        println!(
            "Saving Indexed {} Hashes at {}.",
            indexed_hashes.lock().unwrap().len(),
            hash_path
        );
        // Save indexed hashes to file. If already exists, overwrite
        if path::Path::new(&hash_path).exists() {
            println!("Index File already exists. Overwriting...");
            std::fs::remove_file(&hash_path).unwrap();
        }
        // Set file as hidden
        let mut file = File::create(hash_path.clone()).unwrap();        
        for hash in indexed_hashes.lock().unwrap().iter() {
            file.write_all(hash.as_ref()).unwrap();
            file.write_all("\n".as_ref()).unwrap();
        }
    }
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
