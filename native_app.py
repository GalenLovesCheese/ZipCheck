import struct
import sys
import json
import hashlib
import requests
import os
import wget
import shutil
import zipfile
import platform
from dotenv import load_dotenv

load_dotenv()

def send_message(message):
    """Send a message to the Chrome extension."""
    encoded_message = json.dumps(message).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('I', len(encoded_message)))  # 4-byte length prefix
    sys.stdout.buffer.write(encoded_message)
    sys.stdout.buffer.flush()

'''
def receive_message():
    """Receive a message from the Chrome extension."""
    message = sys.stdin.readline().strip()
    return json.loads(message)
'''

def receive_message():
    """Read a message from stdin and parse it."""
    # Read the 4-byte length header
    raw_length = sys.stdin.read(4)
    if not raw_length:
        sys.exit(0)

    # Unpack the length and read the message
    message_length = struct.unpack('I', raw_length.encode('utf-8'))[0]
    message = sys.stdin.read(message_length)
    return json.loads(message)


def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def scan_file_with_virustotal(file_hash):
    """Send the file hash to VirusTotal and get the scan report."""
    VIRUSTOTAL_API_KEY = "5cf0f36e4eaa12ad2dcb24b069b30dcf34445264b6a73791dc8058c1d9c9da88"
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'accept': 'application/json',
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result['data']['attributes']['last_analysis_stats']
    else:
        return None

def handle_zip_file(filepath):
    """Extract a zip file and return the list of extracted file paths."""
    if platform.system() == "Windows":
        user = os.getlogin()
        extract_point = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\.scan_zip_tmp_folder\\extract_point"

    if not os.path.exists(extract_point):
        os.mkdir(extract_point)

    extracted_files = []
    with zipfile.ZipFile(filepath, 'r') as zf:
        for zinfo in zf.infolist():
            is_encrypted = zinfo.flag_bits & 0x1
            if is_encrypted:
                print(f"Encrypted file detected: {zinfo.filename}")
                # Add handling for encrypted files here if needed
                continue
            else:
                extracted_path = zf.extract(zinfo, extract_point)
                extracted_files.append((False,extracted_path))

    return extracted_files

def download_file(url, destination_path):
    """Download the file to the specified destination."""
    downloaded_file = wget.download(url, out=destination_path)
    if zipfile.is_zipfile(downloaded_file):
        return handle_zip_file(downloaded_file)
    else:
        return [downloaded_file]

def process_and_scan_files(file_paths):
    """Process each file: calculate its hash, scan with VirusTotal, and return results."""
    results = []
    for path in file_paths:
        print(f"Processing file: {path}")
        file_hash = calculate_file_hash(path)
        scan_results = scan_file_with_virustotal(file_hash)
        if scan_results:
            num_flags = sum(scan_results.values())
            results.append({'file': path, 'hash': file_hash, 'flags': num_flags})
        else:
            results.append({'file': path, 'hash': file_hash, 'flags': None, 'error': 'Error contacting VirusTotal API'})
    return results
if platform.system() == "Windows":
    user = os.getlogin()
    temp_folder = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\.scan_zip_tmp_folder"
temp_file = os.path.join(temp_folder, '.scan_zip_tmp_file')

# Create temporary folders if they do not exist
if not os.path.exists(temp_folder):
    os.mkdir(temp_folder)

while True:
# Simulated message for testing
    message = receive_message()

    action = message.get('action')
    url = message.get('url')
    
    #message = {'action': 'download_and_scan', 'url': "https://www.sample-videos.com/zip/10mb.zip"}
    if action == 'download_and_scan':
        # Step 1: Download the file
        file_paths = download_file(url, temp_file)

        # Step 2: Process and scan each file (individual or extracted)
        results = process_and_scan_files(file_paths)
        for result in results:
            response = {
                "status": "success",
                "flags": result['flags'],  # Pretend VirusTotal detected 3 flags
            }
            #send_message({'status': 'success', 'file': result['file'], 'hash': result['hash'], 'flags': result['flags']})
            send_message(response)

        # Clean up temporary folder
        if os.path.isdir(temp_folder):
            shutil.rmtree(temp_folder)
        break
