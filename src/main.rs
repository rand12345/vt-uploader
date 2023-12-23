//! Basic VirusTotal CLI tool
//!
//!

use base64::decode;
use structopt::StructOpt;
use vt3::*;

const BASE_URL: &str = "https://www.virustotal.com/gui/search/";

#[derive(StructOpt)]
struct CommandLineArgs {
    /// Choose the action to perform (file, hash, rescan)
    action: String,

    /// The file or hash to operate on
    file_or_hash: String,
}

type LazyResult = Result<(), Box<dyn std::error::Error>>;

fn main() -> LazyResult {
    let args = CommandLineArgs::from_args();
    let api_key = std::env::var("api_key").expect("Export the VirusTotal api key to [env] api_key");
    let vt = VtClient::new(&api_key).user_agent("Chrome");

    match args.action.as_str() {
        "file" => file_upload(&vt, &args.file_or_hash)?,
        "hash" => hash(&vt, &args.file_or_hash)?,
        "rescan" => rescan(&vt, &args.file_or_hash)?,
        _ => println!("Usage: <file/hash/rescan> <file/hash>"),
    };
    Ok(())
}

fn file_upload(vt: &VtClient, file: &str) -> LazyResult {
    let res = vt.file_scan(file)?;
    let base_64 = decode(&res.data.id)?;
    let decoder = std::str::from_utf8(&base_64)?;

    if let Some(decoder) = decoder.split(':').next() {
        println!("{}{}", BASE_URL, decoder);
        Ok(())
    } else {
        Err("Error decoding base64".into())
    }
}

fn hash(vt: &VtClient, hash: &str) -> LazyResult {
    let res = vt.file_info(hash)?;
    println!("{:?}", &res.data);
    Ok(())
}

fn rescan(vt: &VtClient, hash: &str) -> LazyResult {
    let res = vt.file_rescan(hash)?;
    println!("{:?}", &res.data);
    Ok(())
}
