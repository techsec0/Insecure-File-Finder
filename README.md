# Insecure File Finder (IFF)

A simple Python tool to scan local directories for potentially insecure or sensitive files, such as passwords, API keys, and misconfigured files.

## Features
- Detects suspicious filenames such as `.env`, `secrets.txt`, `id_rsa`, etc.
- Scans file contents for keywords like `password`, `API_KEY`, `token`, etc.
- Flags files with insecure permissions (world-readable/writable)
- Saves a detailed report in both console output and an optional JSON file.

## Usage

To run the tool:

```bash
python insecure_file_finder.py --path <your-directory-path to testing files> --json <output-report.json>
