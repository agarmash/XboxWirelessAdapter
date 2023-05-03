#!/usr/bin/env python3

import hashlib
import os
import sys

MD5_185ead00 = bytes.fromhex('8149654a030d813bcc02a24f39fd3ce9')
# TODO: Add extraction logic for the version 185a6100 (MD5: 01dd6c8aa72b473ba1523c73c6527d86)

def md5(file):
    md5 = hashlib.md5()

    for chunk in iter(lambda: file.read(4096), b''):
        md5.update(chunk)

    return md5.digest()

def main():
    dashboard_file_name = sys.argv[1]
    dashboard_file = open(dashboard_file_name, 'rb')

    dashboard_md5 = md5(dashboard_file)
    if dashboard_md5 != MD5_185ead00:
    	print('Incompatible xonlinedash version, aborting...')
    	exit(1)

    dir_name = 'secrets'

    if not os.path.isdir(dir_name):
    	os.mkdir(dir_name)

    dashboard_file.seek(0x16098, 0)
    hmac_salt = dashboard_file.read(0x75)
    hmac_salt_file = open(dir_name + '/hmac_salt.bin', 'wb')
    hmac_salt_file.write(hmac_salt)
    hmac_salt_file.close()

    dashboard_file.seek(0x16110, 0)
    auth_copyright = dashboard_file.read(0x54)
    auth_copyright_file = open(dir_name + '/auth_copyright.bin', 'wb')
    auth_copyright_file.write(auth_copyright)
    auth_copyright_file.close()

    dashboard_file.seek(0x92986, 0)
    hmac_key = b''
    for i in range(16):
    	hmac_key += dashboard_file.read(1)
    	dashboard_file.seek(3, 1)
    hmac_key_file = open(dir_name + '/hmac_key.bin', 'wb')
    hmac_key_file.write(hmac_key)
    hmac_key_file.close()

if __name__ == "__main__":
    main()
