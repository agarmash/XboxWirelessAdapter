#!/usr/bin/env python3
"""
validate_frame.py

Validate/parse an XBOX MS-NLB-like frame hex dump.

Input:
 - A file containing a single line which is the hex dump as printed by the fuzzer/emulator:
   e.g. "ff ff ff ff ff ff 00 11 22 33 44 55 88 6f 58 58 58 58 ..."
 - Optionally provide --secrets-dir to verify handshake HMAC (expects hmac_key.bin and hmac_salt.bin).
 

Checks:
 - Ethernet ethertype == 0x886f
 - Signature == "XBOX"
 - Version == 0x01 0x01
 - Body size consistency vs frame length
 - Checksum correctness (checksum bytes must be zeroed during calculation)
 - Optional HMAC verification for handshake responses
"""
import argparse
import binascii
import hmac
import hashlib
import os
import sys

ETH_TYPE = 0x886f

def parse_hex_line(line):
    parts = line.strip().split()
    try:
        b = bytes(int(x, 16) for x in parts)
    except Exception as e:
        # Also accept colon-separated mac style: "aa:bb:cc:..."
        cleaned = line.strip().replace(":", " ").replace(",", " ")
        parts = cleaned.split()
        b = bytes(int(x, 16) for x in parts)
    return b

def ones_complement_checksum(data):
    s = 0
    # sum 16-bit words
    for i in range(0, (len(data) // 2) * 2, 2):
        s += (data[i] << 8) + data[i+1]
        if s > 0xffff:
            s = (s & 0xffff) + 1
    if len(data) % 2:
        s += data[-1] << 8
        if s > 0xffff:
            s = (s & 0xffff) + 1
    return (s ^ 0xffff) & 0xffff

def load_secrets(dirpath):
    keyp = os.path.join(dirpath, "hmac_key.bin")
    saltp = os.path.join(dirpath, "hmac_salt.bin")
    if not os.path.isfile(keyp) or not os.path.isfile(saltp):
        raise FileNotFoundError("Missing hmac_key.bin or hmac_salt.bin in %s" % dirpath)
    with open(keyp, "rb") as f: key = f.read()
    with open(saltp, "rb") as f: salt = f.read()
    return key, salt

def pretty_mac(b):
    return ":".join("%02x" % x for x in b)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="file containing space-separated hex bytes")
    ap.add_argument("--secrets-dir", help="directory containing hmac_key.bin and hmac_salt.bin", default=None)
    args = ap.parse_args()

    raw = open(args.file, "r").read().strip()
    frame = parse_hex_line(raw)
    if len(frame) < 26:
        print("Frame too short:", len(frame))
        sys.exit(2)

    dst = frame[0:6]
    src = frame[6:12]
    ethertype = (frame[12] << 8) | frame[13]
    print("Dst MAC:", pretty_mac(dst))
    print("Src MAC:", pretty_mac(src))
    print("Ethertype: 0x%04x" % ethertype)
    if ethertype != ETH_TYPE:
        print("  WARNING: unexpected ethertype (expected 0x886f)")

    # Body starts at offset 14
    if len(frame) < 14 + 12:
        print("Frame body too small")
        sys.exit(2)
    body = frame[14:]
    sig = body[0:4]
    ver = body[4:6]
    body_size = body[6]
    pkt_type = body[7]
    nonce = (body[8] << 8) | body[9]
    checksum_bytes = body[10:12]
    payload = body[12:]

    print("Signature:", sig)
    print("Version:", ver.hex())
    print("Body size (dwords): 0x%02x (%d bytes total body)" % (body_size, body_size*4))
    print("Packet type: 0x%02x" % pkt_type)
    print("Nonce: 0x%04x" % nonce)
    print("Checksum field:", checksum_bytes.hex())

    expected_body_len = body_size * 4
    if expected_body_len > len(body):
        print("  ERROR: body_size says %d bytes but packet provides %d bytes" % (expected_body_len, len(body)))
    else:
        print("Body length ok (provided %d bytes, expected %d bytes)" % (len(body), expected_body_len))

    # Calculate checksum over the first expected_body_len bytes with checksum zeroed
    calc_buf = bytearray(body[:expected_body_len])
    # zero checksum bytes (offsets 10 and 11 inside the body)
    if len(calc_buf) < 12:
        print("Body too small for checksum calculation")
        sys.exit(2)
    calc_buf[10] = 0
    calc_buf[11] = 0
    calc = ones_complement_checksum(calc_buf)
    print("Calculated checksum: 0x%04x" % calc)
    got = (checksum_bytes[0] << 8) | checksum_bytes[1]
    print("Checksum in frame : 0x%04x" % got)
    if calc == got:
        print("Checksum: OK")
    else:
        print("Checksum: MISMATCH")

    # If this is a handshake response (type 0x02) and we have secrets, verify HMAC
    if args.secrets_dir and pkt_type == 0x02:
        try:
            key, salt = load_secrets(args.secrets_dir)
        except Exception as e:
            print("Could not load secrets:", e)
            sys.exit(2)
        # HMAC input per doc: first 16 bytes of challenge message (from original request) plus responder MAC plus salt.
        # On response, the response payload layout begins with the 20-byte HMAC.
        if len(payload) < 20:
            print("Handshake response payload too short for HMAC check")
            sys.exit(2)
        sig_in_frame = payload[0:20]
        # The original 16-byte challenge is not part of the response; to verify we need the challenge
        # However common check: compute HMAC over (challenge||responder_mac||salt) where 'challenge' should be known.
        # If user has the request challenge, they can compare. We'll attempt to infer: if payload contains the 16-byte challenge at offset 20 we can try.
        # Many implementations compute: HMAC(key, msg16 || responder_mac || salt)
        possible_msg = payload[20:20+16]
        if len(possible_msg) == 16:
            data = possible_msg + src + salt
            computed = hmac.new(key, data, hashlib.sha1).digest()
            print("Comparing HMAC of (response.payload[20:36] || src_mac || salt) against response[0:20]")
            print("Computed HMAC:", computed.hex())
            print("Frame HMAC  :", sig_in_frame.hex())
            if computed == sig_in_frame:
                print("HMAC: OK (using payload[20:36] as challenge — verify this is the original 16-byte challenge)")
            else:
                print("HMAC: MISMATCH (the challenge used here may not be the original request challenge)")
        else:
            print("Cannot infer original 16-byte challenge from payload; to fully verify HMAC you must provide the original 16-byte challenge from the request.")

    # Print TLV preview if connect-to-ssid request (0x07)
    if pkt_type == 0x07:
        print("\nTLV parsing of payload:")
        pos = 0
        while pos + 2 <= len(payload):
            tag = payload[pos]; length = payload[pos+1]
            if pos + 2 + length > len(payload):
                print("  TLV truncated at pos", pos)
                break
            val = payload[pos+2:pos+2+length]
            print("  Tag 0x%02x len %d val %s" % (tag, length, val.hex()))
            pos += 2 + length

if __name__ == "__main__":
    main()
