import os
import stat
import argparse
import json

# Keywords we look for in files
DEFAULT_KEYWORDS = ["password", "secret", "api_key", "PRIVATE KEY", "token", "jwt"]

# Common file names that are suspicious
SUSPICIOUS_FILES = [
    ".env", "secrets.txt", "id_rsa", "id_dsa", "config.json", "credentials.csv", "passwords.txt"
]

def scan_directory(path, keywords, output_json=None):
    results = []
    print(f"\n🔍 Scanning directory: {path}\n")

    # Loop through every file in the directory
    for root, dirs, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)

            try:
                # Get file metadata like permissions
                st = os.stat(filepath)
                permissions = stat.filemode(st.st_mode)

                # Check for bad permissions (world-readable or writable)
                insecure_perms = permissions[-3:] in ['rwx', 'rw-', 'r--']

                # Check if file name is suspicious
                if any(suspicious_file in file.lower() for suspicious_file in SUSPICIOUS_FILES):
                    print(f"[!] Suspicious filename: {filepath} ({permissions})")
                    results.append({"file": filepath, "issue": "Suspicious filename", "permissions": permissions})

                # Check if file has bad permissions
                if insecure_perms:
                    print(f"[!] Insecure permissions: {filepath} ({permissions})")
                    results.append({"file": filepath, "issue": "Insecure permissions", "permissions": permissions})

                # Open the file and look for keywords
                with open(filepath, "r", errors="ignore") as f:
                    for i, line in enumerate(f.readlines()):
                        for keyword in keywords:
                            if keyword.lower() in line.lower():
                                print(f"[!] Keyword '{keyword}' found in: {filepath} (line {i+1})")
                                results.append({"file": filepath, "issue": f"Keyword '{keyword}'", "line": i+1})

            except Exception as e:
                # If there's an error reading the file
                print(f"[x] Error reading {filepath}: {e}")

    # If an output file was given, write the results there
    if output_json:
        with open(output_json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n📄 Report saved to {output_json}")

    print(f"\n✅ Scan complete. Found {len(results)} issues.\n")

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Insecure File Finder - Find sensitive or misconfigured files.")
    parser.add_argument("--path", required=True, help="Directory to scan")
    parser.add_argument("--json", help="Output JSON report")
    parser.add_argument("--keywords", help="File with extra keywords to look for")

    args = parser.parse_args()
    scan_path = args.path

    # Load user keywords if provided
    if args.keywords and os.path.isfile(args.keywords):
        with open(args.keywords, "r") as f:
            user_keywords = [line.strip() for line in f if line.strip()]
            keywords = DEFAULT_KEYWORDS + user_keywords
    else:
        keywords = DEFAULT_KEYWORDS

    # Start scanning the directory
    scan_directory(scan_path, keywords, output_json=args.json)
