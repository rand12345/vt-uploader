---

# 🦀 Rust VirusTotal Uploader 

This Rust application is a command-line tool designed to interact with the VirusTotal API, allowing users to perform operations related to file scanning, hash lookups, and CSV file processing. It leverages the power of Rust for high-performance and reliability.

## 🚀 Features

- **File Processing:** Process files for virus scanning using VirusTotal.
- **Hash Lookup:** Perform hash lookups to check file safety.
- **CSV Conversion:** Transform manifest json files to comma seperated variable files.

## 🛠️ Prerequisites

Before you begin, ensure you have the following prerequisites installed:
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)
- An API key from VirusTotal, which needs to be set as an environment variable.

## ⚙️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/rand12345/vt-uploader.git
   cd vt-uploader
   ```

2. **Set up the VirusTotal API Key:**
   You need to export your VirusTotal API key as an environment variable. Replace `your_api_key_here` with your actual API key.

   - **macOS & Linux:**
     ```bash
     export api_key="your_virustotal_api_key_here"
     ```
   - **Windows:**
     ```cmd
     set api_key="your_virustotal_api_key_here"
     ```

## 🛠️ Building the Application

- **macOS & Linux:**
  ```bash
  cargo build --release
  ```
- **Windows:**
  ```cmd
  cargo build --release
  ```

## 🚀 Usage

Run the application using the following syntax:
```bash
cargo run [ACTION] [FILE_OR_HASH]
```
- `[ACTION]`: The action to perform (`file`, `hash`, or `csv`).
- `[FILE_OR_HASH]`: The file path, glob pattern, or hash value depending on the action.

### Examples:
- **File Scan:**
  ```bash
  cargo run file ./path/to/sample_file
  ```
- **Hash Lookup:**
  ```bash
  cargo run hash 123abc456def
  ```
- **CSV conversion of generated manifest**
  ```bash
  cargo run csv ./path/to/manifest.txt
  ```

