use crate::{
    models::{Manifest, VtData},
    LazyResult, BASE_URL, FILE_OUTPUT,
};
use base64::decode;
use chksum_md5 as md5;
use std::{fs::File, io::Write};
use vt3::VtClient;

type VtResult = Result<VtData, Box<dyn std::error::Error>>;

pub fn file_proc(vt: &VtClient, files: Vec<String>) -> LazyResult<()> {
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
    let base_64 = decode(res.data.id)?;
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

fn md5_enc(file_path: &str) -> LazyResult<String> {
    let file = File::open(file_path)?;
    let digest = md5::chksum(file)?;

    Ok(digest.to_hex_lowercase())
}
