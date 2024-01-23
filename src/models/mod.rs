use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Manifest {
    pub manifest: Vec<VtData>,
    pub num_files: usize,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct VtData {
    pub file: String,
    pub md5: String,
    pub url: String,
    pub validated: bool,
    pub epoch: i64,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct CsvWithFileName {
    pub file_name: String,
    pub md5: String,
    pub harmless: i64,
    pub malicious: i64,
    pub suspicious: i64,
    pub timeout: i64,
    pub type_unsupported: i64,
    pub undetected: i64,
}
