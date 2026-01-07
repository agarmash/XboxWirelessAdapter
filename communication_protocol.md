## Frame format

The communication protocol is weird - the console and the wireless adapter send each other ethernet frames of type `MS NLB heartbeat`. Ironically, they exchange the frames roughly every second, which indeed makes it a heartbeat. However, the similarities with `MS NLB` protocol end here.  

The actual structure of the frame is the following:
- The standard ethernet frame header:
    - 6 bytes for the source MAC address;
    - 6 bytes for the destination MAC address;
    - 2 bytes for the frame type, `0x886f` in our case;
- The body of the frame:
    - 4 bytes for the signature, always equals to `XBOX`;
    - 2 bytes for the version, always equals to `\x01\x01`;
    - 1 byte for the size of the body in DWORDs (the actual size divided by 4; the body seems to be padded with zeroes to be multiple of 4 in size);
    - 1 byte for the packet type, more on that later;
    - 2 bytes for the nonce, should be taken from the request and returned in the response;
    - 2 bytes for the checksum;
    - the payload with the size of `(body_size * 4) - 12`, where `body_size` is the field described above and the constant `12` is the size of all the body fields except the payload;
- An optional padding with zeroes to make the ethernet frame at least 64 bytes in size as the standard requires. Note: if you're capturing the traffic with the Wireshark and the frame size is 60 bytes instead of 64, this is because the last 4 bytes of the frame are a checksum, and your NIC strips it off before the frame is captured.


## Packet types

The packet type can be one of the following values:
```
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
```
Frames with any other packet types are considered invalid (TODO add offset in the dashboard)


## Requests and responses payloads

### PACKET_TYPE_HANDSHAKE_REQUEST
Body size: `0x07` DWORDs (28 bytes)
Payload size: `0x04` DWORDs (16 bytes)

- 16 bytes of auth challenge data.

### PACKET_TYPE_HANDSHAKE_RESPONSE
Body size: `0x43` DWORDs (268 bytes)
Payload size: `0x40` DWORDs (256 bytes)

- 20 bytes of auth challenge response;
- 84 bytes of auth copyright string (no zero termination, the size is fixed);
- 32 bytes of wireless adapter name string (padded with zeroes, no zero termination, the size is fixed);
- 32 bytes of wireless adapter firmware version (padded with zeroes, no zero termination, the size is fixed);
- 51 bytes of yet unknown data;
- 1 byte defining the current SSID length;
- 32 bytes of current SSID string (padded with zeroes, no zero termination, the size is fixed);
- 4 bytes of yet unknown data.

### PACKET_TYPE_BEACON_REQUEST
Body size: `0x03` DWORDs (12 bytes)
Payload size: `0x00` DWORDs (0 bytes)

The payload is absent here.

### PACKET_TYPE_BEACON_RESPONSE
Body size: `0x04` DWORDs (16 bytes)
Payload size: `0x01` DWORDs (4 bytes)

- 3 bytes of yet unknown data (probably the current status);
- 1 unused byte, filled with zero.

### PACKET_TYPE_ADAPTER_INFO_REQUEST
Body size: `0x08` DWORDs (32 bytes)
Payload size: `0x05` DWORDs (20 bytes)

- 20 (?) bytes of yet unknown data;

### PACKET_TYPE_ADAPTER_INFO_RESPONSE
_(Sizes seem to represent a particular case, please ingore this payload description for now)_
Body size: `0x0F` DWORDs (60 bytes)
Payload size: `0x0C` DWORDs (48 bytes)

- 1 byte of status (0 means OK; 1,2,3 mean errors)
- 25 bytes of yet unknown data (bytes 0-2 seems to be equal to the bytes 0-2 from the request's first chunk);
- 1 byte defining the current SSID length;
- 32 bytes of current SSID string (padded with zeroes, no zero termination, the size is fixed);

### PACKET_TYPE_CONNECT_TO_SSID_REQUEST

Payload uses TLV (Tag-Length-Value) encoding. See "Protocol Relationships" section below for details.

**Confirmed TLV Tags:**
- `0x01`: SSID (up to 32 bytes)
- `0x02`: Password/Passphrase (up to 63 bytes)
- `0x03`: Security Type (1 byte)

### PACKET_TYPE_CONNECT_TO_SSID_RESPONSE

Payload structure not yet fully documented.

---

## Protocol Relationships

### TLV Encoding (Industry Standard)
The `PACKET_TYPE_CONNECT_TO_SSID_REQUEST` payload uses standard Tag-Length-Value (TLV) encoding, commonly found in:
- Wi-Fi Protected Setup (WPS) configuration messages
- IEEE 802.16 WiMAX configuration files
- LDAP directory information trees
- Smart card EMV payment systems

**TLV Structure:**
```
Tag (1 byte) | Length (1 byte) | Value (variable)
```

**Confirmed Tags:**
- `0x01`: SSID (up to 32 bytes, per IEEE 802.11)
- `0x02`: Password/Passphrase (up to 63 bytes for WPA-PSK)
- `0x03`: Security Type (1 byte)

**Security Type Values (Tag 0x03):**

For original Xbox Wireless Adapter (2002-2005 era):
- `0x00`: Open/No Security
- `0x01`: WEP (Wired Equivalent Privacy - only common security at launch)
- `0x02`: WPA-PSK (WPA with Pre-Shared Key - available after 2003)

**Historical Note:** WPA2 was not ratified until June 2004, after the original Xbox wireless adapter was released.

This TLV format allows extensibility - new configuration parameters can be added by defining new tag values without breaking existing implementations.

### Relationship to WPS
While the Xbox protocol uses a custom transport layer (MS NLB heartbeat frames with HMAC-SHA1 authentication), the WiFi configuration payload structure closely resembles Wi-Fi Protected Setup (WPS) TLV encoding. However, unlike WPS which uses EAP (Extensible Authentication Protocol) over standard 802.11 frames, Xbox uses a proprietary Ethernet-based transport.

**Key Difference:** Standard WPS uses 16-bit attribute IDs (e.g., 0x1045 for SSID), while Xbox uses simplified 8-bit tags (0x01 for SSID), suggesting Microsoft adapted WPS concepts for their lightweight custom protocol.

**WPS to Xbox Tag Mapping:**
| Xbox Tag | WPS Attribute ID | Description |
|----------|------------------|-------------|
| `0x01`   | `0x1045`         | SSID / Network Name |
| `0x02`   | `0x1027`         | Network Key / Passphrase |
| `0x03`   | `0x1003`         | Authentication Type |

---

## Appendix A: Reverse Engineering Notes (Xbox Internals - Unverified)

The following information is derived from Ghidra analysis of the xonlinedash.xbe binary and represents **educated guesses about Xbox internal implementation**. These details are **NOT required for a working emulator** - the Python and C reference implementations work without implementing any of this logic.

### Xbox Internal State Structure (Speculative)

Analysis suggests the Xbox maintains an internal state structure (`AutoClass1`) at offset `0x1000` with the following fields:

- **Offset 0x02** - `source_mac` (6 bytes) - MAC address of wireless adapter
- **Offset 0x0c** - `response_type_enum` (1 byte) - Response type indicator (unconfirmed purpose)
- **Offset 0x0d** - `is_connected_maybe` (1 byte) - Possible connection status flag
- **Offset 0x14** - `nlb_frame_copy` (pointer) - Possible copy of last NLB frame
- **Offset 0x18** - `kernel_tick_count` (4 bytes) - System timing value
- **Offset 0x1c** - `kernel_tick_count_2` (4 bytes) - Additional timing value
- **Offset 0x20** - `delay_maybe` (4 bytes) - Possible retry delay value
- **Offset 0x24** - `attempts_count_maybe` (4 bytes) - Possible retry counter
- **Offset 0x2c** - `hmac_message` (16 bytes) - HMAC challenge data storage
- **Offset 0x40** - `error_code` (pointer) - Possible error code storage

**Note:** Field names ending in "maybe" indicate uncertainty. The structure name `AutoClass1` with comment "PlaceHolder Class Structure" indicates this is a Ghidra-generated placeholder, not a confirmed structure from debug symbols.

### Speculative Retry Behavior

Based on the presence of timing and counter fields, the Xbox *may* implement:
1. Timeout detection using `kernel_tick_count` values
2. Retry attempts tracked in `attempts_count_maybe`
3. Exponential backoff using `delay_maybe`
4. Frame retransmission from cached `nlb_frame_copy`

## Appendix B: WPS-Based Speculation (Unverified)

Based on the similarity to Wi-Fi Protected Setup (WPS) protocol, the Xbox protocol **could** support additional TLV tags beyond the confirmed 0x01-0x03.

### Potential Additional TLV Tags

Standard WPS includes these attributes that Xbox *might, could* theoretically support:

| Xbox Tag | WPS Equivalent | Name              | Max Length | Description |
|----------|----------------|-------------------|------------|-------------|
| `0x04`?  | `0x100F`       | Encryption Type   | 1 byte     | AES vs TKIP cipher specification |
| `0x05`?  | `0x1020`       | MAC Address       | 6 bytes    | Target AP BSSID/MAC address |
| `0x06`?  | `0x1026`       | Network Index     | 1 byte     | Priority/preference for multiple networks |
| `0x07`?  | `0x1028`       | Network Key Index | 1 byte     | Which WEP key to use (1-4) |

### Speculative Encryption Type Values (Tag 0x04?)

If implemented, would specify the cipher independently from authentication:

| Value  | Name  | Description | Era |
|--------|-------|-------------|-----|
| `0x00` | None  | Open network (no encryption) | All |
| `0x01` | WEP   | RC4-based encryption (insecure, deprecated) | 2001+ |
| `0x02` | TKIP  | Temporal Key Integrity Protocol (used with WPA) | 2003+ |
| `0x04` | AES   | Advanced Encryption Standard / CCMP (WPA2, post-2004) | 2005+ (Xbox 360) |

### Extended Security Type Values (Tag 0x03)

Additional values that *could* exist based on WPS specification :

| Value  | Name              | Description
|--------|-------------------|-------------
| `0x04` | WPA2-Personal     | WPA2 with PSK (post-2004)
| `0x08` | WPA-Enterprise    | 802.1X authentication with RADIUS
| `0x10` | WPA2-Enterprise   | WPA2 with 802.1X authentication
| `0x20` | WPA3-Personal     | Latest WPA3 standard (2018+)

---
