use crate::{
    models::{CsvWithFileName, Manifest, VtData},
    LazyResult, BASE_URL, FILE_OUTPUT,
};
use base64::decode;
use chksum_md5 as md5;
use std::{fs::File, io::Write};
use vt3::VtClient;

type VtResult = Result<VtData, Box<dyn std::error::Error>>;

/// Processes files using VirusTotal API and generates a manifest in JSON format.
///
/// This function takes a reference to a `VtClient` instance and a vector of file paths as input.
/// It iterates over each file path in the vector, uploads the file to VirusTotal for analysis,
/// and collects the resulting data into a vector of `VtData` structs.
///
/// Once all files have been processed, it constructs a `Manifest` struct containing the collected
/// data and the total number of files processed. It then serializes the `Manifest` struct into
/// a JSON string and prints it to the standard output.
///
/// Additionally, it writes the serialized JSON string to a file specified by the `FILE_OUTPUT`
/// constant.
///
/// # Arguments
///
/// * `vt` - A reference to a `VtClient` instance used for processing files with VirusTotal.
/// * `files` - A vector of strings containing the paths to the files to be processed.
///
/// # Errors
///
/// This function may return an error if:
///
/// * Uploading a file to VirusTotal fails.
/// * Serializing the `Manifest` struct into JSON fails.
/// * Creating or writing to the output file fails.
///
pub fn file_proc(vt: &VtClient, files: Vec<String>) -> LazyResult<()> {
    // Create an empty vector to store processed file data
    let mut data: Vec<VtData> = vec![];

    // Iterate over each file path in the input vector
    for file in files {
        // Upload the file to VirusTotal and collect the resulting data
        data.push(file_upload(vt, &file)?)
    }

    let len = data.len();

    // Construct a manifest containing the processed file data and total number of files
    let manifest = Manifest {
        manifest: data,
        num_files: len,
    };

    // Serialize the manifest into a JSON string
    let json = serde_json::to_string_pretty(&manifest)?;

    // Create or overwrite the output file and write the JSON string to it
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

/// Converts a file manifest into CSV malware detection data.
///
/// This function takes a reference to a `VtClient` instance and the path to a file manifest as input.
/// The file manifest is expected to be in JSON format. It reads the manifest file, deserializes
/// its JSON content into a `Manifest` struct, and then iterates over each entry in the manifest.
///
/// For each entry in the manifest, it queries VirusTotal for file information based on the MD5 hash,
/// extracts relevant attributes such as detection statistics, and constructs a CSV record with
/// file name, MD5 hash, and detection statistics. It then writes each CSV record to a new CSV file.
///
/// # Arguments
///
/// * `vt` - A reference to a `VtClient` instance used for querying VirusTotal.
/// * `manifest_file` - A string slice containing the path to the file manifest.
///
/// # Errors
///
/// This function may return an error if:
///
/// * The manifest file cannot be opened or read.
/// * The CSV file cannot be created or written to.
/// * Deserialization of the manifest JSON data fails.
/// * Querying VirusTotal for file information fails.
/// * Serializing the CSV record fails.
///
pub fn csv(vt: &VtClient, manifest_file: &str) -> LazyResult<()> {
    // Generate the name for the CSV file based on the manifest file name
    let manifest_csv = format!(
        "{}.csv",
        manifest_file
            // Split the manifest file name at the first '.' character,
            // if present. If not, default to ("manifest", "txt").
            .split_once('.')
            .unwrap_or(("manifest", "txt"))
            .0
    );
    // Open the manifest file for reading
    let mut file = File::open(manifest_file)?;
    // Create a new CSV file for writing
    let csv_file = File::create(manifest_csv)?;
    // Deserialize the manifest JSON data from the manifest file
    let manifest: Manifest = serde_json::from_reader(&mut file)?;
    // Create a CSV writer for writing CSV data to the CSV file
    let mut wtr = csv::Writer::from_writer(csv_file);

    // Iterate over each entry in the manifest
    for vt_data in manifest.manifest {
        // Query VirusTotal for file information based on the MD5 hash
        let res = vt.file_info(&vt_data.md5)?;
        let data = res.data.unwrap().attributes.unwrap();
        let last = data.last_analysis_stats.unwrap();
        // Create a CSV record for the current file entry
        let record = CsvWithFileName {
            file_name: vt_data.file,
            md5: vt_data.md5,
            harmless: last.harmless.unwrap_or_default(),
            malicious: last.malicious.unwrap_or_default(),
            suspicious: last.suspicious.unwrap_or_default(),
            timeout: last.timeout.unwrap_or_default(),
            type_unsupported: last.type_unsupported.unwrap_or_default(),
            undetected: last.undetected.unwrap_or_default(),
        };
        // Serialize and write the CSV record to the CSV file
        wtr.serialize(&record)?;
    }
    // Flush any remaining CSV data to the file
    wtr.flush()?;

    Ok(())
}

fn md5_enc(file_path: &str) -> LazyResult<String> {
    let file = File::open(file_path)?;
    let digest = md5::chksum(file)?;

    Ok(digest.to_hex_lowercase())
}
