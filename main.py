import requests
import time
import hashlib
import os
import json
from cryptography.fernet import Fernet
from termcolor import colored
import base64

API_KEY = "1b65377db6fc7106e8267a15e560484a58bd18ec7df637c095bd9bc92892a342"
VT_URL = "https://www.virustotal.com/api/v3/files/"
DEFAULT_DIR = "/etc/init.d"
LOG_PATH = "/var/log/scan_log.json"
ENC_FILE = "hashes.enc"

def generate_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode())

def decrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data).decode()

def save_hashes(hashes, key):
    encrypted_data = encrypt_data(json.dumps(hashes), key)
    with open(ENC_FILE, "wb") as f:
        f.write(encrypted_data)

def load_hashes(key):
    if os.path.exists(ENC_FILE):
        with open(ENC_FILE, "rb") as f:
            encrypted_data = f.read()
        return json.loads(decrypt_data(encrypted_data, key))
    return {}

def send_file(filename, key, known_hashes):
    if os.path.exists(filename):
        with open(filename, "rb") as file:
            file_data = file.read()
            file_hash = hashlib.md5(file_data).hexdigest()

        if filename in known_hashes and known_hashes[filename] == file_hash:
            print(colored(f"{filename} previously scanned and unchanged. Skipping...", "yellow"))
            return known_hashes
        
        headers = {"x-apikey": API_KEY}
        url = f"{VT_URL}{file_hash}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                print(colored(f"{filename} Malicious File Found!", "red"))
            else:
                print(colored(f"{filename} Clean File: www.virustotal.com/gui/file/{file_hash}", "green"))
            known_hashes[filename] = file_hash
        elif response.status_code == 404:
            print(colored(f"{filename} Not yet scanned on Virustotal", "blue"))
            known_hashes[filename] = file_hash
        else:
            print(colored(f"İstek Hatası: {response.status_code}", "red"))
    else:
        print(colored(f"Dosya Bulunamadı: {filename}", "red"))
    return known_hashes

def list_directory(directory):
    try:
        if os.path.exists(directory):
            return os.listdir(directory)
        else:
            return -1
    except Exception as error:
        print(colored(f"Error: {error}", "red"))

def main(key):
    files = list_directory(DEFAULT_DIR)
    known_hashes = load_hashes(key)
    
    if files != -1:
        for file in files:
            full_path = os.path.join(DEFAULT_DIR, file)
            known_hashes = send_file(full_path, key, known_hashes)
            time.sleep(1)
        save_hashes(known_hashes, key)
    else:
        print(colored(f"Directory Not Found: {DEFAULT_DIR}", "red"))

def check_changes(key):
    if not os.path.exists(ENC_FILE):
        print(colored("You must do a scan first!", "red"))
        return
    
    known_hashes = load_hashes(key)
    current_hashes = {}
    files = list_directory(DEFAULT_DIR)
    
    if files != -1:
        for file in files:
            full_path = os.path.join(DEFAULT_DIR, file)
            if os.path.exists(full_path):
                with open(full_path, "rb") as f:
                    file_data = f.read()
                    file_hash = hashlib.md5(file_data).hexdigest()
                    current_hashes[full_path] = file_hash   
                    
                    if full_path in known_hashes:   
                        if known_hashes[full_path] != file_hash:
                            print(colored(f"{full_path}: The file has changed!  ", "red"))
                        else:
                            print(colored(f"{full_path}: The file has not changed.  ", "green"))
                    else:
                        print(colored(f"{full_path}: New file, you must scan first!  \n", "yellow"))
    else:
        print(colored(f"Directory Not Found: {DEFAULT_DIR}", "red"))

print(r"""
         _nnnn_
        dGGGGMMb
       @p~qp~~qMb
       M|@||@) M|
       @,----.JM|
      JS^\__/  qKL
     dZP        qKRb
    dZP          qKKb
   fZP            SMMb
   HZM            MMMM
   FqM            MMMM
 __| ".        |\dS"qML
 |    `.       | `' \Zq
_)      \.___.,|     .'
\____   )MMMMMP|   .'
     `-'       `--
""")
#HashSentinel
option = input("1) Run scan\n2) Check previous scans\nOption: ")
if option in ["1", "2"]:
    password = input("Enter password: ")
    key = generate_key(password)
    if option == "1":
        main(key)
    elif option == "2":
        check_changes(key)
else:
    print("Bye...")
    exit
