//! Basic VirusTotal CLI tool
//!
//!
use base64::decode;
use chksum_md5 as md5;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use structopt::StructOpt;
use vt3::*;

const BASE_URL: &str = "https://www.virustotal.com/gui/search/";
const FILE_OUTPUT: &str = "manifest.txt";

#[derive(StructOpt)]
struct CommandLineArgs {
    /// Choose the action to perform (file, hash, rescan)
    action: Actions,

    /// The file, glob, or hash to operate on
    file_or_hash: Vec<String>,
}

#[derive(StructOpt)]
#[structopt(rename_all = "lowercase")]
enum Actions {
    File,
    Hash,
    Rescan,
}
impl std::str::FromStr for Actions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file" => Ok(Actions::File),
            "hash" => Ok(Actions::Hash),
            "rescan" => Ok(Actions::Rescan),
            _ => Err(format!("Invalid action: {}", s)),
        }
    }
}

type LazyResult<T> = Result<T, Box<dyn std::error::Error>>;
type VtResult = Result<VtData, Box<dyn std::error::Error>>;

fn main() -> LazyResult<()> {
    let args = CommandLineArgs::from_args();
    let api_key = std::env::var("api_key").expect("Export the VirusTotal api key to [env] api_key");
    let vt = VtClient::new(&api_key).user_agent("Chrome");

    match args.action {
        Actions::File => file_proc(&vt, args.file_or_hash)?,
        Actions::Hash => hash(&vt, args.file_or_hash.first())?,
        Actions::Rescan => rescan(&vt, args.file_or_hash.first())?,
    };
    Ok(())
}

fn file_proc(vt: &VtClient, files: Vec<String>) -> LazyResult<()> {
    let mut data: Vec<VtData> = vec![];
    for file in files {
        data.push(file_upload(vt, &file)?)
    }
    let len = data.len();
    let manifest = Manifest {
        manifest: data,
        num_files: len,
    };
    let json = serde_json::to_string_pretty(&manifest)?;
    println!("{}", json);

    let mut file = File::create(FILE_OUTPUT)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

fn file_upload(vt: &VtClient, file: &str) -> VtResult {
    // Attempt to scan the file with VirusTotal
    let res = vt.file_scan(file)?;

    // Decode the base64-encoded VT hash
    let base_64 = decode(&res.data.id)?;
    let vt_hash = std::str::from_utf8(&base_64)?;

    // Compute the SHA256 hash of the file
    let md5 = md5_enc(file)?;

    // Split the VT hash into hash and epoch
    let (vt_hash, epoch_str) = vt_hash.split_once(':').expect("Bad VT hash");
    // Construct the URL for the scanned file
    let url = format!("{}{}", BASE_URL, vt_hash);
    // Parse the epoch to i64
    let epoch = epoch_str.parse::<i64>().expect("Bad epoch");
    // Check source hash and VT hash match
    let validated = vt_hash == md5;
    // Create a data object with the file information
    let data = VtData {
        file: file.to_string(),
        md5,
        validated,
        url,
        epoch,
    };
    Ok(data)
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
struct Manifest {
    manifest: Vec<VtData>,
    num_files: usize,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
struct VtData {
    file: String,
    md5: String,
    url: String,
    validated: bool,
    epoch: i64,
}

fn md5_enc(file_path: &str) -> LazyResult<String> {
    let file = File::open(file_path)?;
    let digest = md5::chksum(file)?;

    Ok(digest.to_hex_lowercase())
}

fn hash(vt: &VtClient, hash: Option<&String>) -> LazyResult<()> {
    let res = vt.file_info(hash.unwrap())?;
    println!("{:?}", &res.data);
    Ok(())
}

fn rescan(vt: &VtClient, hash: Option<&String>) -> LazyResult<()> {
    let res = vt.file_rescan(hash.unwrap())?;
    println!("{:?}", &res.data);
    Ok(())
}
