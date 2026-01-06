#!/usr/bin/env python3

import hashlib
import os
import sys

# Version MD5 Hashes
MD5_185EAD00 = bytes.fromhex('8149654a030d813bcc02a24f39fd3ce9')
MD5_NLM_MEM  = bytes.fromhex('A9A58ADC4CEAEC337BAAB64F018FBA7F')
# TODO: Add extraction logic for version 185a6100 (MD5: 01dd6c8aa72b473ba1523c73c6527d86)

def md5(file):
    hash_md5 = hashlib.md5()
    file.seek(0)
    for chunk in iter(lambda: file.read(4096), b''):
        hash_md5.update(chunk)
    return hash_md5.digest()

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        exit(1)

    input_file_name = sys.argv[1]
    input_file = open(input_file_name, 'rb')

    file_md5 = md5(input_file)

    # Configuration based on file identity
    if file_md5 == MD5_185EAD00:
        print("Detected version: 185ead00 (Dashboard)")
        salt_off, salt_len = 0x16098, 0x75
        auth_off, auth_len = 0x16110, 0x54
        key_off = 0x92986
        is_sparse = True  # Original dashboard 1-skip-3 pattern
    elif file_md5 == MD5_NLM_MEM:
        print("Detected version: NLM.MEM (Firmware Image)")
        salt_off, salt_len = 0xBC364, 117
        auth_off, auth_len = 0xBC3DC, 84
        key_off = 0xBF520
        is_sparse = False # Contiguous read for firmware
    else:
        print(f"Incompatible file version (MD5: {file_md5.hex().upper()}), aborting...")
        input_file.close()
        exit(1)

    dir_name = 'secrets'
    if not os.path.isdir(dir_name):
        os.mkdir(dir_name)

    # Extract HMAC Salt
    input_file.seek(salt_off, 0)
    with open(os.path.join(dir_name, 'hmac_salt.bin'), 'wb') as f:
        f.write(input_file.read(salt_len))

    # Extract Auth Copyright
    input_file.seek(auth_off, 0)
    with open(os.path.join(dir_name, 'auth_copyright.bin'), 'wb') as f:
        f.write(input_file.read(auth_len))

    # Extract HMAC Key
    input_file.seek(key_off, 0)
    if is_sparse:
        hmac_key = b''
        for i in range(16):
            hmac_key += input_file.read(1)
            input_file.seek(3, 1)
    else:
        hmac_key = input_file.read(16)

    with open(os.path.join(dir_name, 'hmac_key.bin'), 'wb') as f:
        f.write(hmac_key)

    input_file.close()
    print(f"Extraction complete. Secrets saved to ./{dir_name}/")

if __name__ == "__main__":
    main()
