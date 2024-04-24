//!  VirusTotal CLI tool
//!
//!
//!

mod file;
mod hash;
mod models;
use file::*;
use hash::*;
use structopt::StructOpt;

use vt3::*;

const BASE_URL: &str = "https://www.virustotal.com/gui/search/";
const FILE_OUTPUT: &str = "manifest.txt";
type LazyResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Entry point of the program.
///
/// This function serves as the entry point of the program. It parses command-line arguments
/// using the `CommandLineArgs::from_args()` function provided by `structopt`. It also retrieves
/// the VirusTotal API key from the environment variable `api_key`.
///
/// After parsing the command-line arguments and retrieving the API key, it initializes a `VtClient`
/// instance using the API key and sets the user agent to "Chrome".
///
/// Depending on the action specified in the command-line arguments, it calls one of the following
/// functions:
///
/// * `file_proc`: Processes files if the action is `Actions::File`.
/// * `hash`: Retrieves and prints analysis results for a file hash if the action is `Actions::Hash`.
/// * `csv`: Converts a file manifest into CSV malware detection data if the action is `Actions::Csv`.
///
/// # Errors
///
/// This function returns a `LazyResult` which is an alias for `Result<(), LazyError>`.
/// It may return an error if any of the called functions encounters an error.
///
/// # Panics
///
/// This function panics if the VirusTotal API key is not exported to the environment variable `api_key`.
///
fn main() -> LazyResult<()> {
    // Parse command-line arguments
    let args = CommandLineArgs::from_args();
    // Retrieve the VirusTotal API key from the environment variable
    let api_key = std::env::var("api_key").expect("Export the VirusTotal api key to [env] api_key");
    // Initialize a VtClient instance with the retrieved API key and set the user agent
    let vt = VtClient::new(&api_key).user_agent("Chrome");

    // Match the action specified in the command-line arguments and call the corresponding function
    match args.action {
        Actions::File => file_proc(&vt, args.file_or_hash)?,
        Actions::Hash => hash(&vt, args.file_or_hash.first())?,
        Actions::Csv => csv(&vt, args.file_or_hash.first().unwrap())?,
    };
    Ok(())
}

#[derive(structopt::StructOpt)]
pub struct CommandLineArgs {
    /// Choose the action to perform (file, hash, or csv)
    action: Actions,

    /// The file, glob, or hash to operate on
    file_or_hash: Vec<String>,
}

#[derive(StructOpt)]
#[structopt(rename_all = "lowercase")]
pub enum Actions {
    File,
    Hash,
    Csv,
}

impl Actions {
    fn variants() -> &'static &'static str {
        &"file <filename>, hash <hash value>, csv <manifest>, help"
    }
}

impl std::str::FromStr for Actions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file" => Ok(Actions::File),
            "hash" => Ok(Actions::Hash),
            "csv" => Ok(Actions::Csv),
            _ => Err(format!(
                "Invalid action: {}\nValid actions are: {}",
                s,
                Actions::variants()
            )),
        }
    }
}
