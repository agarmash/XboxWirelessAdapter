#!/usr/bin/env python3

# Note: CAP_NET_RAW capability is required to use SOCK_RAW

import fcntl
import socket
import struct
import sys
import hmac
import hashlib

ETH_P_ALL = 3
ETH_P_MSNLB = 0x886f

PACKET_TYPE_HANDSHAKE_REQUEST = b'\x01'
PACKET_TYPE_HANDSHAKE_RESPONSE = b'\x02'
PACKET_TYPE_NETWORKS_LIST_REQUEST = b'\x03'
PACKET_TYPE_NETWORKS_LIST_RESPONSE = b'\x04'
PACKET_TYPE_ADAPTER_INFO_REQUEST = b'\x05'
PACKET_TYPE_ADAPTER_INFO_RESPONSE = b'\x06'
PACKET_TYPE_CONNECT_TO_SSID_REQUEST = b'\x07'
PACKET_TYPE_CONNECT_TO_SSID_RESPONSE = b'\x08'
PACKET_TYPE_BEACON_REQUEST = b'\x09'
PACKET_TYPE_BEACON_RESPONSE = b'\x0a'

HEADER_SIGNATURE = b'XBOX'
HEADER_VERSION = b'\x01\x01'

hmac_salt = b""
hmac_key = b""
auth_copyright = b""

class NLB_Packet:
    def __init__(self, data):
        self.destination_mac = data[0:6]
        self.source_mac = data[6:12]
        self.frame_type = data[12:14]

        self.signature = data[14:18] # always 'XBOX'
        self.version = data[18:20] # always 01 01
        self.size_in_dwords = data[20:21]
        self.packet_type = data[21:22]
        self.nonce = data[22:24]
        self.checksum = data[24:26]

        self.payload = data[26:]

    def __repr__(self):
        return "Dst mac: " + self.destination_mac.hex(":") + "\n" + \
            "Src mac: " + self.source_mac.hex(":") + "\n" + \
            "Frame type: " + repr(self.frame_type) + "\n" + \
            "Signature: " + repr(self.signature) + "\n" + \
            "Version: " + self.version.hex(":") + "\n" + \
            "Size in DWORDs: " + repr(self.size_in_dwords) + "\n" + \
            "Packet type: " + self.packet_type.hex(":") + "\n" + \
            "Nonce: " + self.nonce.hex(":") + "\n" + \
            "Checksum: " + self.checksum.hex(":") + "\n" + \
            "Payload: " + repr(self.payload) + "\n"

    def is_broadcast(self):
        return self.destination_mac == b'\xff\xff\xff\xff\xff\xff'

def load_secrets():
    global hmac_salt, hmac_key, auth_copyright

    try:
        hmac_salt_file = open('secrets/hmac_salt.bin', 'rb')
        hmac_key_file = open('secrets/hmac_key.bin', 'rb')
        auth_copyright_file = open('secrets/auth_copyright.bin', 'rb')
    except:
        print('Have you extracted the secrets from the xonlinedash?')
        print('Aborting...')
        exit(1)

    with hmac_salt_file, hmac_key_file, auth_copyright_file:
        hmac_salt = hmac_salt_file.read()
        hmac_key = hmac_key_file.read()
        auth_copyright = auth_copyright_file.read()

def start_server(ifname):
    # Open raw socket and bind it to network interface.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_MSNLB))
    s.bind((ifname, 0))

    local_mac = get_local_mac(s, ifname)

    while True:
        data = s.recv(1500)
        packet = NLB_Packet(data)
        print(packet)
        print("\n")

        if packet.is_broadcast() and (packet.packet_type == PACKET_TYPE_HANDSHAKE_REQUEST):
            respond_to_handshake(packet, s, local_mac)
        elif packet.packet_type == PACKET_TYPE_BEACON_REQUEST:
            respond_to_beacon(packet, s, local_mac)
        elif packet.packet_type == PACKET_TYPE_ADAPTER_INFO_REQUEST:
            respond_to_info_request(packet, s, local_mac)
        elif packet.packet_type == PACKET_TYPE_NETWORKS_LIST_REQUEST:
            respond_to_networks_list_request(packet, s, local_mac)
        elif packet.packet_type == PACKET_TYPE_CONNECT_TO_SSID_REQUEST:
            respond_to_connect_to_ssid_request(packet, s, local_mac)

def send_response(packet_type, nonce, payload, socket, local_mac, destination_mac):
    body_size = calculate_body_size_in_dwords_for_payload(payload)

    if len(payload) < 34: # check wherher the frame has to be padded to 64 bytes in total
        payload += bytes(34 - len(payload))

    body_wo_checksum = HEADER_SIGNATURE + \
                       HEADER_VERSION + \
                       body_size + \
                       packet_type + \
                       nonce + \
                       b'\x00\x00' + \
                       payload

    checksum = calculate_body_checksum(body_wo_checksum)

    frame = destination_mac + \
            local_mac + \
            ETH_P_MSNLB.to_bytes(2, 'big') + \
            HEADER_SIGNATURE + \
            HEADER_VERSION + \
            body_size + \
            packet_type + \
            nonce + \
            checksum + \
            payload

    print(frame.hex(":"))

    socket.send(frame)

def respond_to_handshake(packet, socket, local_mac):
    print("Trying to respond to the broadcast message...\n")

    hmac = make_signature_hmac(packet.payload[0:16], local_mac)
    response = bytes.fromhex("54 6F 74 61 6C 6C 79 20 6C 65 67 69 74 20 77 69 72 65 6C 65 73 73 20 61 64 61 70 74 65 72 00 00 44 75 64 65 20 74 72 75 73 74 20 6D 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 06 07 00 00 0F FE 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 01 A9 FE 47 79 01 02 01 0B 02 0C 31 31 31 31 31 31 31 31 31 31 31 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 00 00")

    payload = hmac + auth_copyright + response

    send_response(PACKET_TYPE_HANDSHAKE_RESPONSE, 
                  packet.nonce,
                  payload,
                  socket,
                  local_mac,
                  packet.source_mac)

def respond_to_beacon(packet, socket, local_mac):
    print("Trying to respond to the beacon...\n")

    payload = bytes.fromhex("02 80 00 00")

    send_response(PACKET_TYPE_BEACON_RESPONSE, 
                  packet.nonce,
                  payload,
                  socket,
                  local_mac,
                  packet.source_mac)

def respond_to_info_request(packet, socket, local_mac):
    print("Trying to respond to the info request...\n")

    payload = bytes.fromhex("00 09 01 04 A9 FE 47 79 02 01 01 04 01 01 05 01 0B 06 06 00 00 00 00 00 00 07 0C 31 31 31 31 31 31 31 31 31 31 31 31 08 01 02 09 01 01 11 01 02")

    send_response(PACKET_TYPE_ADAPTER_INFO_RESPONSE, 
                  packet.nonce,
                  payload,
                  socket,
                  local_mac,
                  packet.source_mac)

def respond_to_networks_list_request(packet, socket, local_mac):
    print("Trying to respond to the networks list request...\n")

    payload = bytes.fromhex("10 AA AA AA AA AA A0 01 0C 61 61 61 61 61 61 61 61 61 61 61 61 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 04 06 B1 02 04 0B 16 12 24 48 6C 0C 18 30 60 00 00 00 00 AA AA AA AA AA A1 01 05 62 62 62 62 62 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 04 06 B0 02 04 0B 16 12 24 48 6C 0C 18 30 60 00 00 00 00 AA AA AA AA AA A2 01 0B 63 63 63 63 63 63 63 63 63 63 63 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 04 06 A7 02 04 0B 16 24 30 48 6C 0C 12 18 60 00 00 00 00 AA AA AA AA AA A3 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 04 06 A7 02 04 0B 16 24 30 48 6C 0C 12 18 60 00 00 00 00 AA AA AA AA AA A4 01 11 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 04 06 A5 02 04 0B 16 24 30 48 6C 0C 12 18 60 00 00 00 00 AA AA AA AA AA A5 01 0C 65 65 65 65 65 65 65 65 65 65 65 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 0B 04 06 B5 02 04 0B 16 24 30 48 6C 0C 12 18 60 00 00 00 00 AA AA AA AA AA A6 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 0B 04 06 B4 02 04 0B 16 24 30 48 6C 0C 12 18 60 00 00 00 00 AA AA AA AA AA A7 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 0B 04 06 AC 02 04 0B 16 24 30 48 6C 0C 12 18 60 00 00 00 00 AA AA AA AA AA A8 01 0C 66 66 66 66 66 66 66 66 66 66 66 66 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 0B 04 06 AB 02 04 0B 16 24 30 48 6C 0C 12 18 60 00 00 00 00 AA AA AA AA AA A9 01 0C 67 67 67 67 67 67 67 67 67 67 67 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 03 04 06 B5 02 04 0B 16 12 24 48 6C 0C 18 30 60 00 00 00 00 AA AA AA AA AA AA 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 03 04 06 B5 02 04 0B 16 12 24 48 6C 0C 18 30 60 00 00 00 00 AA AA AA AA AA AB 01 15 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 00 00 00 00 00 00 00 00 00 00 00 02 05 04 06 B7 02 04 0B 16 0C 12 18 24 30 48 60 6C 00 00 00 00 AA AA AA AA AA AC 01 0B 69 69 69 69 69 69 69 69 69 69 69 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 05 04 06 B9 02 04 0B 16 0C 12 18 24 30 48 60 6C 00 00 00 00 AA AA AA AA AA AD 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 05 04 06 B0 02 04 0B 16 0C 12 18 24 30 48 60 6C 00 00 00 00 AA AA AA AA AA AE 01 15 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 6A 00 00 00 00 00 00 00 00 00 00 00 02 05 04 06 B1 02 04 0B 16 0C 12 18 24 30 48 60 6C 00 00 00 00 AA AA AA AA AA AF 01 0B 6B 6B 6B 6B 6B 6B 6B 6B 6B 6B 6B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 05 04 06 B1 02 04 0B 16 0C 12 18 24 30 48 60 6C 00 00 00 00 00 00 00")
    
    send_response(PACKET_TYPE_NETWORKS_LIST_RESPONSE, 
                  packet.nonce,
                  payload,
                  socket,
                  local_mac,
                  packet.source_mac)

def respond_to_connect_to_ssid_request(packet, socket, local_mac):
    print("Trying to respond to the connect to network request...\n")

    payload = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
    
    send_response(PACKET_TYPE_CONNECT_TO_SSID_RESPONSE, 
                  packet.nonce,
                  payload,
                  socket,
                  local_mac,
                  packet.source_mac)

# Untested
def align_payload_to_dword_boundary(payload):
    misalignment = len(payload) % 4

    if misalignment > 0:
        return payload + bytes(4 - misalignment)
    else:
        return payload

def calculate_body_size_in_dwords_for_payload(payload):
    packet_size = (len(payload) // 4) + 3

    if packet_size > 0xff:
        raise Exception("The payload is too big to be sent")

    return packet_size.to_bytes(1, 'big')

def get_local_mac(socket, ifname):
    info = fcntl.ioctl(socket.fileno(),
                       0x8927,
                       struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return info[18:24]

def make_signature_hmac(message, local_mac):
    data = message + local_mac + hmac_salt
    signature = hmac.new(hmac_key, data, hashlib.sha1).digest()
    return signature

def calculate_body_checksum(data):
    size = len(data)

    checksum = 0

    for i in range(0, size-1, 2):
        checksum += (data[i] << 8) + data[i+1]
        if checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1

    checksum = checksum ^ 0xffff
    return checksum.to_bytes(2, 'big')

def main():
  ifname = sys.argv[1]
  load_secrets()
  start_server(ifname)

if __name__ == "__main__":
    main()
