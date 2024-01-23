//! Basic VirusTotal CLI tool
//!
//!
//!
mod file;
// mod hash;
mod models;

use file::*;
use std::fs::File;

use structopt::StructOpt;
use vt3::*;

use crate::models::{CsvWithFileName, Manifest};

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
    Manifest,
}
impl std::str::FromStr for Actions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file" => Ok(Actions::File),
            "hash" => Ok(Actions::Hash),
            "rescan" => Ok(Actions::Rescan),
            "manifest" => Ok(Actions::Manifest),
            _ => Err(format!("Invalid action: {}", s)),
        }
    }
}

type LazyResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> LazyResult<()> {
    let args = CommandLineArgs::from_args();
    let api_key = std::env::var("api_key").expect("Export the VirusTotal api key to [env] api_key");
    let vt = VtClient::new(&api_key).user_agent("Chrome");

    match args.action {
        Actions::File => file_proc(&vt, args.file_or_hash)?,
        Actions::Hash => hash(&vt, args.file_or_hash.first())?,
        Actions::Rescan => rescan(&vt, args.file_or_hash.first())?,
        Actions::Manifest => manifest(&vt, args.file_or_hash.first().unwrap())?,
    };
    Ok(())
}

fn hash(vt: &VtClient, hash: Option<&String>) -> VtResult<()> {
    let res = vt.file_info(hash.unwrap())?;
    let data = res.data.unwrap().attributes.unwrap();
    // println!("{:#?}", data);
    let last = data.last_analysis_stats.unwrap();
    println!("{:#?}", &last);
    Ok(())
}
fn manifest(vt: &VtClient, manifest_file: &str) -> LazyResult<()> {
    let manifest_csv = format!(
        "{}.csv",
        manifest_file
            .split_once('.')
            .unwrap_or(("manifest", "txt"))
            .0
    );
    let mut file = File::open(manifest_file)?;
    let csv_file = File::create(manifest_csv)?;
    let manifest: Manifest = serde_json::from_reader(&mut file)?;

    let mut wtr = csv::Writer::from_writer(csv_file);
    for vt_data in manifest.manifest {
        let res = vt.file_info(&vt_data.md5)?;
        let data = res.data.unwrap().attributes.unwrap();
        let last = data.last_analysis_stats.unwrap();
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
        wtr.serialize(&record)?;
    }
    wtr.flush()?;

    Ok(())
}

fn rescan(vt: &VtClient, hash: Option<&String>) -> LazyResult<()> {
    let res = vt.file_rescan(hash.unwrap())?;
    println!("{:?}", &res.data);
    Ok(())
}
