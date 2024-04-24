use vt3::{VtClient, VtResult};

/// Retrieves and prints analysis results for a file hash from VirusTotal.
///
/// This function takes a reference to a `VtClient` instance and an optional reference to a string
/// containing the file hash as input. If no hash value is provided, the function will panic.
///
/// It queries VirusTotal for file information based on the provided hash value and prints
/// the analysis results to the standard output. If the file is categorized as malicious,
/// it prints the engine name and the result associated with it.
///
/// Additionally, it prints the file name(s) associated with the provided hash.
///
/// # Arguments
///
/// * `vt` - A reference to a `VtClient` instance used for querying VirusTotal.
/// * `hash` - An optional reference to a string containing the file hash.
///
/// # Errors
///
/// This function returns a `VtResult` which is an alias for `Result<(), VtError>`.
/// It may return an error if querying VirusTotal for file information fails.
///
/// # Panics
///
/// This function will panic if no hash value is provided.
pub fn hash(vt: &VtClient, hash: Option<&String>) -> VtResult<()> {
    // Retrieve file information from VirusTotal based on the provided hash value
    let res = vt.file_info(hash.expect("No hash value given"))?;
    // Extract relevant attributes from the VirusTotal response data
    let data = res.data.unwrap().attributes.unwrap();
    // Print analysis statistics for the file
    println!("{:#?}", &data.last_analysis_stats.unwrap());
    // Iterate over each analysis result and print details if the file is categorized as malicious
    for (_s, item) in data.last_analysis_results.unwrap() {
        if Some("malicious".to_string()) == item.category {
            println!("{:?} {:?}", item.engine_name, item.result);
        }
    }
    // Print the file name(s) associated with the provided hash
    println!("File name(s): {:?}", data.names.unwrap());
    Ok(())
}
