# Xbox Wireless Adapter — XPP Protocol Specification

**Document Version**: v61 (2026-05-08) — Corrections applied 2026-05-19 (Type 0x06 mandatory tag rule)

**Compatable Hardware**:
Microsoft MN-740 Wireless Bridge
Linksys WGA54G Wireless-G Game Adapter

**Protocol**: Xbox Peripheral Protocol (XPP) over NLB (EtherType 0x886f)
**Protocol spec**: protocol is based off the MN-740 with additional WGA54g specific additions.
**Status**: near complete


---

## Overview
This document purpose is to document the XPP wireless protocol as implemented on the original Xbox console and the MN-740/ WGA54g Ethernet-to-Wireless bridge. the software link is unique that is manages the wireless hardware Unlike a standard "dumb" bridge, the Xbox console is able to control and monitor the adaptors wireless radio all from the dashboard UI.

Microsoft used the existing Ethernet port and created a "Virtual Serial Bus" by wrapping management commands in Fake NLB Heartbeats. This allowed the Xbox to configure the adapter without needing a complex TCP/IP stack.

The configuration payload structure resembles Wi-Fi Protected Setup (WPS) TLV encoding but has been modified to be lightweight.

The Main problem with the wireless adapter hardware has been the lack of WPA and newer protocols, this project aims to be a stepping stone to implement an emulator or alternative hardware to enable such connections to modern wireless networks.

The currently available adaptors are actually hampered at a firmware level to WEP128 when the adapters actually support newer security standards, there is a breakdown of what is required to patch in WPA support in the MN-740 and WGA54G later on in this document.

Contrary to belief The Xbox is capable of more than it seems the adaptor uses the handshake response to tell the Xbox what security is supports and the Xbox dashboard uses this to customize the UI.
upon returning specific values new UI options are available for wireless networks.
The Xbox dash is aware of ciphers and encryption support all the way up to WPA2 enterprise with the latest dash files.
The Xbox supports PMK formatted hex and ASCII passwords up to 63 characters as per the WPA/WPA2 standard.

The adaptors and console supports a set of basic tags but extra tags and features have been implemented and features outside of what the console or adaptors support currently for future purposes that never materialised on both the Xbox and adaptor side.

---

## Table of Contents

- [Packet Transport Types](#packet-transport-types)
  - [NLB (EtherType 0x886f)](#nlb-transport-ethertype-0x886f)
  - [EAPOL (EtherType 0x888e)](#eapol-transport-etherType-0x888)
- [Type 0x00 - ECHO](#type-0x00--echo)
- [Type 0x01 - HANDSHAKE_REQUEST](#type-0x01--handshake_request)
- [Type 0x02 - HANDSHAKE_RESPONSE](#type-0x02--handshake_response)
- [Type 0x03 - NETWORKS_LIST_REQUEST](#type-0x03--networks_list_request)
- [Type 0x04 - NETWORKS_LIST_RESPONSE](#type-0x04--networks_list_response)
- [Type 0x05 - ADAPTER_INFO_REQUEST](#type-0x05--adapter_info_request)
- [Type 0x06 - ADAPTER_INFO_RESPONSE](#type-0x06--adapter_info_response)
- [Type 0x07 - CONNECT_TO_SSID_REQUEST](#type-0x07--connect_to_ssid_request)
- [Type 0x08 - CONNECT_TO_SSID_RESPONSE](#type-0x08--connect_to_ssid_response)
- [Type 0x09 - BEACON_REQUEST](#type-0x09--beacon_request)
- [Type 0x0A - BEACON_RESPONSE](#type-0x0a--beacon_response)
- [Types 0x0B, 0x0C, 0x0F — Silently Dropped](#types-0x0b-0x0c-0x0f--silently-dropped)
- [Type 0x11 - WPA_ASSOC / WPA_EXCHANGE](#type-0x11--wpa_assoc--wpa_exchange)

### Supporting Information
- [HMAC-SHA1 Authentication](#hmac-sha1-authentication)
- [Checksum Calculation](#checksum-calculation)
- [BBN Device Discovery Protocol (MN-740 only)](#bbn-device-discovery-protocol)
- [TFTP Firmware Upgrade (MN-740 only)](#tftp-firmware-upgrade)
- [Virtual File System (MN-740 only)](#Virtual-File-system)
- [MSBNUpdate Firmware Update Tool (MN-740 only)](#msbnupdate-firmware-update-tool)
- [Signal Strength Scaling](#signal-strength-scaling)
- [Error code flags](#error-code-flags)
- [MAC.DAT File Format (MN-740 only)](#mac-dat-pairing-file-format)
- [Connection Workflows](#connection-workflows)
- [Implementation Checklist](#implementation-checklist)
- [DHCP Implementation & XPP Interaction](#dhcp-implementation---xpp-interaction)
- [HTTP Web Interface (MN-740 only)](#http-web-interface-mn-740-only)
- [Factory Test Backdoor (MN-740 only)](#factory-test-backdoor-mn-740-only)
- [Packet Flow Timing Diagrams](#packet-flow-timing-diagrams)
- [WPA/WPA2 Implementation](#wpa-wpa2-implementation)
- [Ghidra Struct Definitions](#ghidra-struct-definitions)

---

## Packet Transport Types

Two distinct transports are used. The transport for each packet type is noted at the top of each section.

```
Transport      | EtherType | Used by
---------------|-----------|--------------------------------------------------
NLB (XPP)      | 0x886f    | Types 0x00–0x09, 0x0A, 0x0B, 0x0C, 0x0F
EAPOL (802.1X) | 0x888e    | Type 0x11 only (WPA authentication)
```

**protocol types**
```
EtherType | Protocol            
----------|---------------------------------------------------------------
0x0806    | ARP
0x886f    | NLB (XPP)
0x888e    | EAPOL (IEEE 802.1X)
```

### NLB Transport (EtherType 0x886f)

```
Size         | Segment           | Description
-------------|-------------------|------------------------------------------------
14 bytes     | Ethernet header   | dst MAC, src MAC, EtherType 0x886f
12 bytes     | XPP header        | Magic, version, body size, type, nonce, checksum
Variable     | Payload           | Packet-specific data
0–3 bytes    | DWORD padding     | Zeros to align to 4-byte boundary
Variable     | IEEE 802.3 padding| Zeros to reach 60-byte minimum frame size
```

#### Ethernet Header (14 bytes)

```
Offset | Size | Field           | Value
-------|------|-----------------|----------------------------------------------
0      | 6    | Destination MAC | Target MAC (FF:FF:FF:FF:FF:FF for HANDSHAKE_REQ)
6      | 6    | Source MAC      | Sender MAC
12     | 2    | EtherType       | 0x886f
```

#### XPP Header (12 bytes)

```
Offset | Size | Field              | Value
-------|------|--------------------|--------------------------------------------------
0      | 4    | Magic signature    | "XBOX" (0x58 0x42 0x4f 0x58)
4      | 1    | Version byte 1     | 0x01 (static)
5      | 1    | Version byte 2     | 0x01 (static)
6      | 1    | Body size (DWORDs) | (12 + payload + padding) / 4
7      | 1    | Packet type        | Command ID
8      | 2    | XID (nonce)        | Transaction ID — matched between request and response
10     | 2    | Checksum           | RFC 1071 (calculated with this field = 0x0000)
```

Body size counts from the start of the XPP header and covers header + payload + DWORD padding. IEEE 802.3 padding is never included.

```
Example body size calculation:
Type 0x01: 16-byte payload  → (12 + 16) / 4 =  7 DWORDs = 0x07
Type 0x02: 256-byte payload → (12 + 256) / 4 = 67 DWORDs = 0x43
Type 0x09: 0-byte payload   → (12 + 0) / 4  =  3 DWORDs = 0x03
```

**Build order:**
1. Pack payload data
2. For Type 0x02 only: prepend 20-byte HMAC at offset 0
3. Pad to 4-byte boundary with 0x00
4. Calculate body size: `(12 + padded_payload) / 4`
5. Write XPP header fields
6. Calculate RFC 1071 checksum over `body_size × 4` bytes and write to offset 10
7. Pad entire frame to 60-byte minimum with 0x00 (IEEE 802.3, not checksummed)

---

### EAPOL Transport (EtherType 0x888e)

Used exclusively by Type 0x11. **No XPP magic signature, no body size DWORD count, no RFC 1071 checksum.**

```
Size     | Field           | Value
---------|-----------------|------------------------------------------------
6 bytes  | Destination MAC | FF:FF:FF:FF:FF:FF (broadcast) or AP MAC (retry)
6 bytes  | Source MAC      | Console MAC
2 bytes  | EtherType       | 0x888e
2 bytes  | Frame type word | 0x6388 or 0x123c (WPA sub-protocol selector)
1 byte   | Type marker     | 0x11 (constant)
1 byte   | Sub-type        | Direction/state byte
2 bytes  | Reserved        | 0x0000
2 bytes  | Length          | Big-endian payload length
2 bytes  | Reserved        | 0x0000
Variable | Payload         | Sub-TLVs: [tag:1][len:1][data:len]
```

---

## Type 0x00 — ECHO

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Latency probe. The adapter has no dedicated echo handler — an incoming type 0x00 frame falls through the type switch with no handler and the firmware transmits the zero-filled response buffer. The response is therefore a 60-byte all-zeros frame, not a structured XPP reply.

### Packet Format Request

```
Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | dst=adapter MAC, src=Xbox MAC, EtherType=0x886f
12 bytes | XPP header      | type=0x00, body=0x03 DWORDs, no payload
```

### Packet Format Response

```
Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | dst=Xbox MAC, src=adapter MAC, EtherType=0x886f
46 bytes | Zeros           | Zero-filled to meet 60-byte minimum frame size
```

No XPP magic. No checksum. All bytes after the Ethernet header are 0x00. RTT typically 1–5 ms.

**Emulator note**: Respond with a 60-byte all-zeros Ethernet frame (EtherType 0x886f). Do not include XPP structure in the response.

---

## Type 0x01 — HANDSHAKE_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Initiates an authentication session with a random challenge nonce.

### Packet Format

```
Total size: 42 bytes (14 Ethernet + 12 XPP + 16 payload)
Body size:  0x07 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | dst=FF:FF:FF:FF:FF:FF (broadcast), EtherType=0x886f
12 bytes | XPP header      | type=0x01, body=0x07 DWORDs
16 bytes | Payload         | Randomly generated 128-bit challenge nonce
```

### Example

```
58 42 4f 58 01 01 07 01 ed c6 66 9a   ← XPP header (type=0x01, body=0x07)
12 34 56 78 9a bc de f0 11 22 33 44   ← 16-byte challenge nonce (bytes 0–11)
55 66 77 88                           ← 16-byte challenge nonce (bytes 12–15)
```

---

## Type 0x02 — HANDSHAKE_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Authenticates the adapter and reports current wireless status. Contains a 20-byte HMAC-SHA1 at offset 0 of the payload — the only packet type to carry an HMAC.

```
Total size: 282 bytes (14 Ethernet + 12 XPP + 252 payload + 4 trailer)
Body size:  0x43 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x02, body=0x43 DWORDs
252 bytes| Fixed payload   | See layout below
4 bytes  | Trailer         | OpMode bitmask + LinkState + 0x00 0x00
```

### Fixed Payload (252 bytes)

```
Offset | Size     | Field
-------|----------|------------------------------------------------------------------
0      | 20 bytes | HMAC-SHA1 — see HMAC Authentication section
20     | 84 bytes | "Device is Xbox Compatible. Copyright (c) Microsoft Corporation.
       |          |  All Rights Reserved." null-padded to 84 bytes
104    | 32 bytes | "Xbox Wireless Adapter (MN-740)" null-padded to 32 bytes
136    | 32 bytes | Firmware version string e.g. "1.0.2.26 Boot: 1.3.0.06" null-padded
168    | 6 bytes  | BSSID of connected AP, or 00:00:00:00:00:00 if not connected
174    | 1 byte   | Security capability byte — see WPA Capability Bytes below
175    | 1 byte   | Cipher capability byte — see WPA Capability Bytes below
176    | 4 bytes  | Ad hoc 802.11b/g channel list bitmask — hardcoded 0x00000FFE (channels 1-11), big-endian on the wire: 00 00 0f fe (capture-verified)
       |          | Rejection rule: bit 0 set OR bit >14 set → entire response rejected
180    | 28 bytes | Ad hoc 802.11a channel list bitmask (1=enabled, 0=disabled, per-bit for ch 1–200)
       |          | Stock firmware sends all zeros (all channels disabled)
       |          | Channel allow list overflow,Parsed, hard-rejected by XBE always 0x00 0x00 0x00
208    | 1 byte   | Radio mode capability bitmask — hardcoded 0x05
       |          | Bit 0=802.11b, Bit 1=802.11a, Bit 2=802.11g. High bits (0xF8) must be zero
       |          | or the dashboard rejects the packet
209    | 1 byte   | DHCP state: 0x00=no DHCP, 0x01=DHCP acquired, 0x02=static/manual (decompile reading). A real MN-740 sent 0x00 in every capture, even with an IP; the emulator sends 0x01 once it has an IP
210    | 4 bytes  | Current IP address (big-endian)
214    | 1 byte   | Radio active: 0x00=radio off, 0x01=radio on.
       |          | Guard: value must be < 2 — sending 0x02 or higher rejects the entire
       |          | handshake response. (decompile-verified: same < 2 guard as byte 216)
215    | 1 byte   | Auth status: 0x02=open/idle, 0x03=WEP association in progress.
       |          | Guard: value must be < 4 — values 0x04+ reject the entire handshake
       |          | response. (decompile-verified: `*(byte*)(iVar2+0xf1) < 4` in
       |          | xpp_process_handshake_response)
216    | 1 byte   | Radio active flag: 0x00=radio off, 0x01=radio on.
       |          | Guard: value must be < 2 — sending 0x02 or higher rejects the entire
       |          | handshake response. The 0x02 (b+g active) value is only valid in
       |          | ADAPTER_INFO_RESP Tag 0x04, never in the handshake.
217    | 1 byte   | Current channel (1–14). Returns live radio channel when authenticated,
       |          | or the saved configured channel when not authenticated.
       |          | Guard: value must be < 201 (0xc9) or the entire handshake response
       |          | is rejected. Values 15–200 pass the guard (relevant for 5 GHz
       |          | channels in the extended bitmask). (decompile-verified)
218    | 1 byte   | 802.11 authentication algorithm. Seeds AutoClass1+0xf5f (auth_algorithm)
       |          | via copy_rx_state_to_cfg, which is echoed back as CONNECT_REQ Tag 0x11.
       |          | Guard: value must be < 3 — value 0x03+ rejects the entire handshake.
       |          | 0x00=Open System auth, 0x01=Shared Key auth, 0x02=WPA/EAP auth.
       |          | Only 0x00 and 0x02 are seen on wire from stock firmware.
219    | 1 byte   | SSID length (max 32)
220    | 32 bytes | SSID string, null-padded
252    | 1 byte   | Secondary security capability — **this is the same byte as trailer
       |          | offset 0 (opmode_mask)**. The firmware writes `XPP_Get_Link_State_Bitmask()`
       |          | here (0x02=WEP disabled/idle, 0x04=WEP enabled). The dashboard also
       |          | reads this position as `sec_caps_default` via
       |          | `xpp_select_best_security_mode()`. For a WPA-patched adapter: set to
       |          | 0x16 (adds bit 0x10) to enable WPA pre-selection in the UI.
       |          | Bit 0x10 SET → WPA1/RSN capable (same as byte 174)
       |          | Bit 0x20 SET → WPA2 enterprise capable (same as byte 174)
       |          | Controls which security type is pre-selected in the UI
253    | 1 byte   | Secondary cipher capability — **this is the same byte as trailer
       |          | offset 1 (link_state)**. The firmware writes
       |          | `XPP_Tag_09_Handler_Get_Link_State()` here (0x01=no link,
       |          | 0x02=infrastructure, 0x04=ad-hoc). The dashboard also reads this
       |          | position as `cipher_caps_default` via `xpp_select_best_security_mode()`.
       |          | Bit 0x01 SET → Open security option selected by default
       |          | Bit 0x02 SET → WEP-64 selected by default
       |          | Bit 0x04 SET → WEP-128 selected by default
       |          | Controls which security mode is pre-selected in the UI
254    | 2 bytes  | Reserved (trailer bytes 2–3), always 0x00 0x00
```

### Trailer payload (4 bytes)

```
Offset | Size   | Field       | Values
-------|--------|-------------|-----------------------------------------------
0      | 1 byte | OpMode mask | 0x02=WEP disabled/link idle, 0x04=WEP enabled/link active
1      | 1 byte | Link state  | 0x01=no link, 0x02=infrastructure linked, 0x04=ad-hoc linked
2      | 1 byte | Reserved    | Always 0x00
3      | 1 byte | Reserved    | Always 0x00
```

### WPA Capability Bytes (Offsets 174–175)

These two bytes gate which security options the Xbox dashboard displays. Stock firmware sends hardcoded stubs.
 **To enable the WPA PSK menu option, byte 174 must have bit 0x10 set** (send `0x16` instead of `0x06`).

**Byte 174 — Adapter security capability:**
This byte is used to inform the Xbox what wireless security ciphers it supports
this packet is rejected if a prior security method is not supported ie:

byte174 Setting bit 0x20 without bit 0x10 → rejection

 **Note** `xpp_select_best_security_mode()` selects security in **highest-first priority order**: WEP-128 (bit 0x04) is evaluated before WEP-64 (bit 0x02), which is evaluated before Open (bit 0x01). The adapter always connects at the highest security mode the peer supports.

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
1    | 0x02 | SET         | WPA-TKIP cipher supported
2    | 0x04 | SET         | WPA-CCMP/AES cipher supported
4    | 0x10 | CLEAR       | WPA1/RSN capable — set this to unlock WPA PSK UI
5    | 0x20 | CLEAR       | WPA2 enterprise capable
```

**Byte 175 — Cipher mode capability:**
This byte is used to inform the Xbox what wireless security sub ciphers is supports
this packet is rejected if a prior security method is not supported ie:

byte175 bits 0,1,2 must ALL be set or → rejection

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
0    | 0x01 | SET         | "No Security" menu option shown
1    | 0x02 | SET         | "WEP-64" menu option shown
2    | 0x04 | SET         | "WEP-128" menu option shown
3    | 0x08 | CLEAR       | CCMP/AES cipher mode
4    | 0x10 | CLEAR       | WPA2 TKIP
5    | 0x20 | CLEAR       | WPA2 CCMP/AES
```
**Stock values**: the adaptor has a function stub indicating the cipher mode the device supports.
byte 174=`0x06`, byte 175=`0x07` → WPA PSK option never shown; No Security, WEP-64, WEP-128 all shown.

### Ad hoc 802.11b/g channel list bitmask (Bytes 176–179)
This bitfield is the channel list for the dash's Ad hoc 802.11b/g mode: it is the set of channels offered on that mode's Channel screen.

It is independent of the Ad hoc 802.11a list in bytes 180-207. Each list feeds only its own mode's Channel screen, and neither is a fallback or priority list for the other.

Dash behaviour (decompile, 2026-11-24): the dash stores this word as a channel list and rejects the handshake if bit 0 or any bit above 14 is set. The Channel screen of Ad hoc 802.11b/g lists these channels. The Channel screen of Ad hoc 802.11a lists the extended block (bytes 180-207, read back to front: channel N is bit N%8 of frame byte 233-N/8, up to channel 200) and defaults to its first entry, so that block should hold 5 GHz channels only. Infrastructure mode has no channel choice. The Ghidra name "rate_list" for the extended list is wrong.

On the MN-740 this list is created from the region code of the adaptor set with Tag 0x84:
```
For example:

FCC (default): min=1, max=11 → bits 1–11 set → 0x00000FFE
ETSI: min=1, max=13 → bits 1–13 set → 0x00003FFE
Spain: min=10, max=11 → bits 10–11 set → 0x00000C00
Japan: min=14, max=14 → bit 14 set → 0x00004000
```

Rejection rule: bit 0 set OR bit >14 set → entire HS_RESP rejected.

### Ad hoc 802.11a channel list bitmask (Bytes 180–207)

This bitfield is the channel list for the dash's Ad hoc 802.11a mode: it is the set of channels offered on that mode's Channel screen.
It does not override bytes 176-179: the two lists are separate, one per ad hoc mode.
Total of 28 bytes, Each bit represents a channel 1-200 : **1=enabled, 0=disabled**.
bit 0 has no special handling and maps to channel 0 it will not cause rejection but setting bits above 200 will cause rejection.

This list is also the channel list of the dash's **Ad hoc 802.11a** mode (shown only when byte 208 bit 1 is set); it defaults to the first entry, so keep 2.4 GHz channels out of it and put the 2.4 GHz channels in bytes 176-179. Verified on a stock Xbox 2026-11-24: an emulator list of 36, 40, 44, 48, 149, 153, 157, 161, 165 shows exactly those channels.

**Byte order on the wire (verified on a stock Xbox, 2026-11-24):** the dash reads the 28 bytes back to front. Channel N is bit `N % 8` of byte `27 - N / 8` (counting from byte 180), i.e. the bit numbering in the table below applies to the *reversed* 28-byte block. An adapter that keeps its mask as "channel N = bit N%8 of byte N/8" must reverse the block before putting it in the reply, otherwise the scan list and channel selection are wrong.

```
Bit | Channel | Notes
----|---------|------
1   | 1       | 2.4 GHz
2   | 2       | 2.4 GHz
...
11  | 11      | 2.4 GHz
12  | 12      | 2.4 GHZ (USA Banned )
13  | 13      | 2.4 GHz (USA Banned)
14  | 14      | 2.4 GHZ (Japan only)
15  | 15      | 2.4ghz Not a valid channel under current regs
...
32  | 32      | 5.0ghz 5150–5170mhz U-NII-1
...
196 | 196     | 5.9ghz 5970–5990mhz UK indoor
```

### Radio Mode Capability Bitmask (Byte 208)

Corrected 2026-11-24 from the dash decompile (Network Mode menu builder at 0x784c6): bit 1 is 802.11a, bit 2 is 802.11g, and bit 1 decides whether the Network Mode menu has three entries (Infrastructure, Ad hoc 802.11a, Ad hoc 802.11b/g) or two (Infrastructure, Ad hoc b/g). The earlier labels (bit 1 = g, bit 2 = ad-hoc) were wrong. The emulator sends 0x07 when allow_5ghz=1 and 0x05 otherwise.

**VERIFIED on a stock Xbox 2026-11-24:** with byte 208 = 0x07 the Network Mode menu shows Ad hoc 802.11a. With 0x05 it shows only Infrastructure and Ad hoc 802.11b/g. The 802.11a Channel screen listed about 8 channels from the extended block (emulator default offers 9: 36, 40, 44, 48, 149, 153, 157, 161, 165); whether the screen scrolls or drops one entry is not yet confirmed.

Emulator settings (INI/UCI): `adhoc_channels_a` = extended block / 802.11a channel list (old name `channel_mask_5g`), `adhoc_channels_bg` = bytes 176-179 (old names `chan_bitmask_2g`, `rate_bitmask`), `allow_5ghz` = also switches byte 208 between 0x05 and 0x07.

These bytes are used to inform the Xbox what radio mode standard it supports.

```
Bit | Mask | Wire value | Meaning
----|------|------------|------------------------------
0   | 0x01 | SET        | 802.11b capable
1   | 0x02 | CLEAR      | 802.11a capable - SET adds "Ad hoc 802.11a" to the dash Network Mode menu
2   | 0x04 | SET        | 802.11g capable
3-7 | 0xf8 | 0x00       | Must be zero — dashboard rejects packet if any high bit set
```
**Stock values**: the adaptor has function stubs setting constants
byte 208=`0x05` - the stock adaptor is b/g only: 802.11b + 802.11g, no 802.11a (so no "Ad hoc 802.11a" menu item)

### Byte 209 DHCP state
This byte indicates the state of the upstream DHCP DISCOVERY.
```
Result | Meaning
-------|--------
0x00   | no DHCP/searching,
0x01   | DHCP acquired,
0x02   | interface manually enabled.
```

### Byte 216 — Radio Active Flag

This bytes indicates the state of the radio in the adaptor.
The `0x02` (b+g radio active) value reported by Tag 0x04 in ADAPTER_INFO_RESP is not valid here.

```
Result | Meaning
-------|------------------------------------------------------------------
0x00   | Radio off / disabled
0x01   | Radio on
0x02+  | ENTIRE HANDSHAKE REJECTED — do not send in handshake response
```

### Byte 217 - XPP_Get_Channel_Or_Fallback()

returns live radio channel when authenticated
returns saved configured channel when not authenticated

### Byte 218 — 802.11 Authentication Algorithm

This is the **802.11 authentication algorithm** currently active on the radio — not a generic encryption flag. It is distinct from Tag 0x11 in ADAPTER_INFO_RESP, which reports live HAL encryption state.

The value seeds `XPP_FsmState+0xe2f` (`auth_algorithm_rx`), which propagates via `AutoClass1_copy_rx_state_to_cfg` to `XPP_FsmState+0xf5f` (`auth_algorithm`). That field is then echoed back to the adapter as CONNECT_REQ Tag 0x11, keeping the dash and adapter in sync on the 802.11 auth method in use.

```
Value | Meaning                    | Wire seen
------|----------------------------|-----------
0x00  | Open System authentication | Yes — open and WEP open-auth networks
0x01  | Shared Key authentication  | Not seen on wire from stock firmware
0x02  | WPA/EAP authentication     | Not seen on wire from stock firmware
0x03+ | ENTIRE HANDSHAKE REJECTED — do not send in handshake response
```

Stock firmware only produces `0x00` (Open System) since WPA is not implemented and Shared Key auth is uncommon. For a WPA-patched adapter, send `0x02` when WPA association is active.

*"This field reflects the adapter's current saved HAL state. On a fresh factory-reset adapter it will be 0x00. If the adapter has been previously connected, it may retain a non-zero value until the next CONNECT_REQ updates it. The value seen on wire may therefore differ from the active 802.11 auth method for the current session."*

### WPA Capability default selection (Offsets 252–253)

**Byte 252 — Adapter security default selection:**
This byte is used to inform the Xbox what wireless security ciphers to select or use by default.

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
1    | 0x02 | SET         | WPA-TKIP cipher supported
2    | 0x04 | SET         | WPA-CCMP/AES cipher supported
4    | 0x10 | CLEAR       | WPA1/RSN capable — set this to unlock WPA PSK UI
5    | 0x20 | CLEAR       | WPA2 enterprise capable
```

**Byte 253 — Cipher mode default selection:**
This byte is used to inform the Xbox what wireless security sub ciphers to select or use by default.

```
Bit  | Mask | Stock value | Meaning
-----|------|-------------|--------------------------------------------
0    | 0x01 | SET         | "No Security" menu option shown
1    | 0x02 | SET         | "WEP-64" menu option shown
2    | 0x04 | SET         | "WEP-128" menu option shown
3    | 0x08 | CLEAR       | CCMP/AES cipher mode
4    | 0x10 | CLEAR       | WPA2 TKIP
5    | 0x20 | CLEAR       | WPA2 CCMP/AES
```

### Example Payload

```
[0x00] HMAC-SHA1:  b9 f0 d1 96 c3 3c 1f 34 f7 b9 e9 85 1c 45 f0 77 11 85 9d a0
[0x14] Copyright: "Device is Xbox Compatible. Copyright (c) Microsoft Corporation..."
[0x68] Model:     "Xbox Wireless Adapter (MN-740)"
[0x88] Firmware:  "1.0.2.26 Boot: 1.3.0.06"
```

---

## Type 0x03 — NETWORKS_LIST_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Triggers a Wi-Fi site survey. No payload. If a scan is already in progress the request is silently dropped.

### Packet Format

```
Total size: 26 bytes (14 Ethernet + 12 XPP)
Body size:  0x03 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x03, body=0x03 DWORDs
```

Scan takes 50–900 ms depending on channel count. Response is sent when scan completes.

---

## Type 0x04 — NETWORKS_LIST_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Returns discovered networks. Maximum 16 networks (firmware limit).

**Body-size validation formula (decompile-verified)**: The dashboard validates the body_size_dwords field
with the exact formula:

```
body_size_dwords × 4 == (network_count × 0x3d + 0x10) & 0xFFFFFFFC
```

If this check fails the entire response is discarded. Emulators must compute body_size correctly using
this formula — round `(12 + 1 + network_count × 61)` up to the next 4-byte boundary then divide by 4.

**Network slot sizes**:
Each the network slots is a string of 53 bytes of sequential meaningful data with padding at
the end of each slot to make a stride of 61 bytes from the start of one slot to the next.

### Packet Format

```
Total size: Variable (14 Ethernet + 12 Header + 1 Count + N×61 Slots + Padding) = N Bytes
Body size:  Variable (12 + 1 + (Network count × 61) + padding) / 4 DWORDs

Size         | Segment         | Description
-------------|-----------------|-----------------------------------------------
14 bytes     | Ethernet header | Standard
12 bytes     | XPP header      | type=0x04, body=variable DWORDs
1 byte       | Network count   | Number of SSIDs found (max 16)
N × 61 bytes | Network slots   | Fixed-width blocks (see below)
0–3 bytes    | Padding         | Zeros to DWORD-align
```

### Payload Structure example:
```
Offset | Size  | Field
-------|-------|-------
0      | 61    | Network slot 1
61     | 61    | Network slot 2
------------------------------
info omitted  for slots 3-14
-----------------------------
854    | 61    | network slot 15
915    | 61    | network slot 16
```

### Network Slot Structure (61 bytes each)
```
Offset | Size    | Field           | Description
-------|---------|-----------------|--------------------------------------------------
0      | 6 bytes | BSSID           | AP MAC address
6      | 1 byte  | Privacy flags   | Unreliable — set on almost all networks. Use byte 42.
7      | 1 byte  | SSID length     | 0–32. Length=0 means hidden SSID.
8      | 32 bytes| SSID            | Network name, null-padded
40     | 1 byte  | Network mode    | 0x00=softAP/test, 0x02=infrastructure.
       |         |                 | Ad-hoc value unseen in captures.
41     | 1 byte  | Channel         | AP channel number
42     | 1 byte  | Security status | 0x02=Privacy bit NOT set in beacon (open/WEP-open)
       |         |                 | 0x04=Privacy bit SET in beacon (WEP/WPA/WPA2)
43     | 1 byte  | Rate indicator  | 0x01 when byte 42=0x02, 0x06 when byte 42=0x04.
       |         |                 | Correlates with rate set size
44     | 1 byte  | Signal/RSSI     | 0–255 scaled
45     | 8 bytes | Supported rates | table of supported rate codes
53     | 8 bytes | Padding         | Zeros to reach 61-byte stride
```


**Factory Reset Default Network**:
When a factory reset is performed the adapter defaults to SSID "mshome", channel 1, infrastructure mode, IP 192.168.2.252/24, rate capability 0x0B (11 Mbps), no security, with all WEP keys cleared.

**⚠ Stale cache behaviour**: If the current scan returns zero networks, the adapter falls back to the previous scan's results and returns those instead. The adapter never sends an empty network list — it always returns the last successful scan.

### Network mode field (Byte 40)
```
⚠ Wire-verified across real adapter captures. Values 0x01/0x06/0x09 do NOT appear at byte 40.

 Value | Meaning
-------|--------------------------------------------------
 0x00  | softAP / test AP (observed on software access points)
 0x02  | Infrastructure BSS (real AP)
 other | Ad-hoc — not observed in captures, expected non-zero
```
Dash validation guard: value must be ≤ 2 or the entire NETWORKS_LIST_RESPONSE is discarded (decompile-verified 2026-11-24; not just the one slot).

### Security status Bitfield (Byte 42)
```
⚠ Wire-verified across all real adapter captures:

 Value | Wire observation                       | Known networks with this value
-------|----------------------------------------|-------------------------------
 0x02  | 802.11 Privacy bit NOT set in beacon   | All open networks (OpenWrt*), WEP-open auth networks
 0x04  | 802.11 Privacy bit SET in beacon       | WPA, WPA2, WEP shared-key auth networks
```

**Important**: The adapter faithfully copies the 802.11 Privacy bit from the AP beacon into this byte.
It does NOT make a higher-level judgement about the security protocol in use.
- WEP open-auth networks may report 0x02 if the AP beacon has Privacy=0 (AP-dependent).
- OWE (Opportunistic Wireless Encryption) networks report 0x04 despite being open-auth.
- Use this byte only to determine if the AP beacon advertises encryption — not what kind.

**Privacy byte (Byte 6) is unreliable**: Wire captures show 0x01 on virtually all networks
including genuinely open ones. Do not use Byte 6 as a security indicator.

⚠️ **Privacy byte guard (decompile-verified)**: The dashboard validates `byte[6] <= 1`.
Values **> 1 cause the ENTIRE NETWORKS_LIST_RESPONSE to be discarded** (function returns 0).
Send `0x00` or `0x01` only. All wire captures confirm adapters send `0x01`, which passes this guard.

```
 Bit | Hex  | Original Ghidra Label | Description (firmware constant names are inferred)
-----|------|-----------------------|------------------------------------------------------
 0   | 0x01 | WLAN_FLAG_PRIVACY     | (unreliable — set on almost all networks including open)
 1   | 0x02 | WLAN_FLAG_OPEN        | 802.11 Privacy bit not set in beacon
 2   | 0x04 | WLAN_FLAG_TKIP        | 802.11 Privacy bit set in beacon (WEP/WPA/WPA2)
 3   | 0x08 | WLAN_FLAG_AES         | Reserved/Unused (not seen on wire)
 4-7 | ---- | WLAN_FLAG_RSVD        | Reserved/Unused bits
```

**Note**: byte 44 signal RSSI has custom scaling see [Signal strength / link quality scaling)](Signal strength / link quality scaling)

**Hidden SSID handling**: SSID length=0 indicates a hidden network. The Xbox ignores these on first scan; the user can manually enter the SSID to trigger a directed probe.

**Per-slot checks in the dash (`xpp_process_networks_list_response` @000a449e, decompile-verified 2026-11-24)**: the count byte must be ≤ 16. A slot is kept only if its SSID length is non-zero **and** its BSSID is not all zeros; otherwise it is silently skipped. Any of the following discards the **whole response**: SSID length > 32, privacy byte (6) > 1, network mode (40) > 2, channel (41) > 200, or the 16 bytes starting at offset 45 (8 rates + 8 padding) having a non-zero byte after the first zero byte. In other words the rate list must be non-zero bytes followed only by zeros. The emulator's own limit is 15 slots (`MAX_NETWORK_SLOTS`), one below the dash's 16.

### Real Example

```
[Network Slot — "Kids2.4g"] — 61 bytes total
Offset | Hex                                            | Field
-------|------------------------------------------------|-------------------
0–5    | b6 b0 24 59 b8 0a                              | BSSID
6      | 01                                             | Privacy flags (unreliable)
7      | 08                                             | SSID length (8)
8–15   | 4b 69 64 73 32 2e 34 67                        | "Kids2.4g"
16–39  | 00 × 24                                        | SSID padding
40     | 02                                             | Network mode (0x02 = infrastructure)
41     | 01                                             | Channel 1
42     | 02                                             | Security status (Privacy bit not set — open)
43     | 01                                             | Rate indicator
44     | d9                                             | Signal/RSSI (0xD9 = strong signal)
45–52  | 0c 12 18 24 30 48 60 6c                        | Supported rates: 6,9,12,18,24,36,48,54 Mbps
53–60  | 00 00 00 00 00 00 00 00                        | Padding
```

---

## Type 0x05 — ADAPTER_INFO_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Requests a set of TLV tags from the adapter. Tags are specified as `[Tag][Length Hint]` pairs.

```
Total size: Variable (14 Ethernet + XPP header + 1 tag count + tag payload + Padding)
Body size:  Variable (12 + 1 + (tag pairs) + padding) / 4 DWORDs

Size     | Segment       | Description
---------|---------------|----------------------------------------------
14 bytes | Ethernet hdr  | Standard
12 bytes | XPP header    | type=0x05, body=variable DWORDs
1 byte   | Tag count     | Number of [Tag][Length Hint] pairs
Variable | Tag pairs     | Array of [1-byte Tag][1-byte Length Hint]
0–3 bytes| Padding       | Zeros to DWORD-align
```

The length hint is advisory — the firmware ignores it and uses hardcoded response lengths.
Unknown tags cause a buffer corruption side effect (see Type 0x06) and should be avoided.

### Example: Request tags 0x01, 0x04, 0x11

```
03 01 04 04 01 11 01 00
|  ↑  ↑  ↑  ↑  ↑  ↑  ↑  
|  |  |  |  |  |  |  └─── alignment padding to next 4 Byte boundary (1 byte)
|  |  |  |  |  |  └─  third requested length hint  (1 byte)
|  |  |  |  |  └────  third requested tag 0x11 (encryption type)
|  |  |  |  └─ second requested length hint (1 byte)
|  |  |  └──── second requested tag 0x04 (wireless mode), (1 byte)
|  |  └─── first requested length hint (4 bytes)
|  └────── first requested tag 0x01 (IP address)
└────── Number of [tag] [tag hint] pairs (3)
```

See the Type 0x06 Tag Table for a full list of available tags.

---

## Type 0x06 — ADAPTER_INFO_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Response to a Type 0x05 request. Tags are returned as a TLV stream — parse as a stream, not at fixed offsets.

⚠ All requested tags are mandatory and must be present in the response exactly once. The dashboard enforces a strict bitmask: every tag listed in the Type 0x05 request must appear in the response or the entire response is silently discarded with no error. See the Mandatory Tag Rule section below the tag table for full details.
Requests a set of TLV tags from the adapter. Tags are specified as `[Tag][Length][data}`.
```
Total size: Variable (14 Ethernet + 12 XPP Header + 2 artifact + Payload + padding) = N bytes
Body size:  Variable (12 XPP header + 2 artifact + payload + padding) / 4 = N DWORDs

Size     | Segment          | Description
---------|------------------|----------------------------------------------
14 bytes | Ethernet header  | Standard
12 bytes | XPP header       | type=0x06, body=variable DWORDs
1 byte   | Status byte      | 0x00 = OK, TLVs follow. 0x01 / 0x03 = error 0x80000003, 0x02 = error 0x80000002 (TLVs ignored). Above 0x03 = response dropped
1 byte   | Tag count echo   | Echoes the count from the Type 0x05 request
Variable | TLV stream       | [Tag][Length][Value] triplets
0–3 bytes| Padding          | Zeros to DWORD-align
```


### Example: Response tags 0x01, 0x04, 0x11 — no IP assigned

This example shows a correct response when the adapter has no IP address yet.
Tag 0x01 is included with value 0.0.0.0 — it is never omitted.

```
00 03 01 04 00 00 00 00 04 01 01 11 01 01
↑  ↑  ↑  ↑  ↑───────────↑  ↑  ↑  ↑  ↑  ↑
|  |  |  |  |            |  |  |  |  |  └── Tag 0x11 data (0x01 = not associated)
|  |  |  |  |            |  |  |  |  └───── Tag 0x11 length (1 byte)
|  |  |  |  |            |  |  |  └──────── Tag 0x11
|  |  |  |  |            |  |  └─────────── Tag 0x04 data (0x01 = radio on)
|  |  |  |  |            |  └────────────── Tag 0x04 length (1 byte)
|  |  |  |  |            └───────────────── Tag 0x04
|  |  |  |  └────────────────────────────── Tag 0x01 data (0.0.0.0 — no IP yet)
|  |  |  └───────────────────────────────── Tag 0x01 length (4 bytes)
|  |  └──────────────────────────────────── Tag 0x01
|  └─────────────────────────────────────── Tag count echo (3)
└────────────────────────────────────────── Firmware artifact (always 0x00)
```

All three requested tags are present. Tag 0x01 sends 0.0.0.0 because the adapter has
no IP address yet — the tag itself is never skipped. If any of the three tags were
missing, the dashboard would silently discard the entire response.

### Tag Table (Types 0x05 / 0x06)

```
Tag  | Name               | Size | Condition       | Description
-----|--------------------|------|-----------------|---------------------------------------------------
0x01 | IP address         | 4    | Always          | Current adapter IP (big-endian).
     |                    |      |                 | Sends 0.0.0.0 when no IP assigned. Never omitted.
     |                    |      |                 | ⚠ Dashboard guard: len must == 4 or entire response rejected.
0x02 | Connection state   | 1    | Always          | 0x00=no DHCP, 0x01=DHCP acquired, 0x02=static/manual
0x03 | Admin password     | Var  | Always          | XPP admin identity password (max 16 bytes).
     |                    |      |                 | Factory default "admin". Also used as TFTP WRQ auth input.
0x04 | Radio active flag  | 1    | Always          | 0x00=radio off, 0x01=radio on (single band), 0x02=radio on (b+g)
     |                   |      |                 | ⚠ Dashboard guard: value > 1 causes entire Type 0x06 response
     |                   |      |                 | to be rejected. Send only 0x00 or 0x01 in Type 0x06.
     |                   |      |                 | 0x02 is valid inside NML.bin internally but the dashboard
     |                   |      |                 | rejects it when received on the wire.
0x05 | Radio channel      | 1    | Always          | Returns live channel when associated, or saved channel otherwise
0x06 | BSSID              | 6    | Always          | Current AP MAC. 00:00:00:00:00:00 when not connected.
     |                   |      |                 | ⚠ Tag is mandatory when requested. "If connected" refers
     |                   |      |                 | to the value, not whether the tag is present.
     |                   |      |                 | Dashboard guard: len must == 6 or entire response rejected.
0x07 | SSID               | Var  | Always          | Byte 0=length, Bytes 1..N=SSID string.
     |                   |      |                 | Length=0 when no SSID configured.
     |                   |      |                 | ⚠ Tag is mandatory when requested. "If associated" refers
     |                   |      |                 | to the value, not whether the tag is present.
     |                   |      |                 | Dashboard guard: len > 32 rejects the entire response (decompile-verified 2026-11-24).
0x08 | Auth type          | 1    | Always          | RESP: 0x02=open/no WEP, 0x04=WEP active (wire-verified).
     |                    |      |                 | REQ hint: 0x00=open/WEP, 0x10=WPA radio on, 0x20=WPA radio off.
     |                    |      |                 | See Tag 0x08 subsection for full decode.
0x09 | Enc type echo      | 1    | Always          | RESP: 0x01=open, 0x02=WEP-64, 0x04=WEP-128 (wire-verified).
     |                    |      |                 | Not a link state in this context.
     |                    |      |                 | ⚠ Dashboard guard: 0x00 rejected, 0x05+ rejected.
     |                    |      |                 | Only 0x01–0x04 accepted. Entire response discarded on violation.
     |                    |      |                 | See Tag 0x09 subsection for full decode.
0x0A | WEP key slot 0     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0B | WEP key slot 1     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0C | WEP key slot 2     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0D | WEP key slot 3     | —    | WRITE-ONLY      | ⚠ No read handler.
0x0E | Current channel    | 1    | Radio active    | Live channel via hardware (1–14)
0x0F | WEP-128 key        | —    | WRITE-ONLY      | ⚠ No read handler.
0x10 | WPA PMK            | —    | WRITE-ONLY      | ⚠ No read handler.
0x11 | Radio state        | 1    | Always          | 0x00=not associated, 0x01=not associated (alt), 0x02=associated
     |                    |      |                 | ⚠ Dashboard guard: value > 2 causes the entire response to be rejected.
     |                    |      |                 | Real adapters send 0x02 whenever associated (every capture) and the dash
     |                    |      |                 | accepts it; 0x01 = not associated. (Earlier text here claiming 0x02 is rejected was wrong.)

0x81 | Adapter MAC        | 6    | Always          | Adapter's own Ethernet MAC address
0x82 | Regulatory domain  | 1    | Always          | Domain code from hardware EEPROM (see table below)
0x83 | Net reset param    | 1    | Always          | Current reconnect mode value (read-back of Tag 0x83 write)
0x84 | channel            | 1    | Always          | Configured or saved channel
0x85 | TX rate code       | 1    | If associated   | Current PHY speed — see rate code table
0x86 | EEPROM block 0     | 512  | Radio off only  | AR5212 EEPROM bytes 0x000–0x1FF
0x87 | EEPROM block 1     | 512  | Radio off only  | AR5212 EEPROM bytes 0x200–0x3FF
0x88 | EEPROM block 2     | 512  | Radio off only  | AR5212 EEPROM bytes 0x400–0x5FF
0x89 | EEPROM block 3     | 512  | Radio off only  | AR5212 EEPROM bytes 0x600–0x7FF
```

**⚠ Write-only tags (0x0A–0x0D, 0x0F, 0x10)**: These have no read handler. Including them in a read request corrupts the response for that tag entry (a stale byte is decremented and written back). Subsequent tags in the same request are unaffected. Do not include these in ADAPTER_INFO_REQ.

**⚠ EEPROM tags (0x86–0x89)**: Never requested by the Xbox dashboard. Intended for the PC-side setup wizard. The radio must be inactive (Tag 0x04 = 0x00) or the read will return 0xFF-filled data. The TLV length byte for these tags is `0xFF` (indicating a 512-byte extended block).

### ⚠ Mandatory Tag Rule

#### The bitmask guard

Before sending Type 0x05, the dashboard sets a bitmask in `AutoClass1+0x6c` — one bit per
requested tag. The response processor `xpp_process_adapter_info_response` accumulates a
"seen" bitmask in `AutoClass1+0x70` as it parses each TLV. At the end of the first parse
pass it checks:

```c
if (seen_bitmask != expected_bitmask) {
    return 0;   // entire response discarded — "No response from adapter"
}
```

**A single missing tag, duplicate tag, or unexpected extra tag causes the entire
ADAPTER_INFO_RESPONSE to be silently discarded.**

#### The 9 fixed tags

The dashboard always sends exactly 9 tags in every Type 0x05, from a single hardcoded
code path (`xpp_build_adapter_info_request`). There is no mechanism in xonlinedash.xbe
to request a different set. Fixed payload size is always 0x2E (46) bytes.

```
Tag  | Expected bitmask bit | Notes
-----|----------------------|---------------------------------------------------
0x01 | 0x00000002           | Always include — send 0.0.0.0 if no IP assigned
0x02 | 0x00000004           | Always include
0x04 | 0x00000010           | Always include — value 0x00 or 0x01 only
0x05 | 0x00000020           | Always include — value must be ≤ 200 (201+ rejects the response)
0x06 | 0x00000040           | Always include — send 00:00:00:00:00:00 if not connected
0x07 | 0x00000080 (shifted) | Always include — length 0 if no SSID
0x08 | 0x00000100           | Always include
0x09 | 0x00000200           | Always include — value must be 0x01–0x04
0x11 | 0x00020000           | Always include — value 0x00–0x02 (0x02 = associated; 0x03+ rejects the response)
```

#### Per-tag guards (dashboard rejects entire response on any violation)

```
Tag  | Violation                        | Effect
-----|----------------------------------|---------------------------------------
0x01 | len != 4                         | Entire response discarded
0x02 | len != 1                         | Entire response discarded
     | value > 2                        | Entire response discarded
0x04 | len != 1                         | Entire response discarded
     | value > 1                        | Entire response discarded
0x05 | len != 1                         | Entire response discarded
     | value > 200                      | Entire response discarded
0x06 | len != 6                         | Entire response discarded
0x07 | len > 32                         | Entire response discarded (the clamp to 32 in the later apply pass is unreachable)
0x08 | len != 1                         | Entire response discarded
0x09 | len != 1                         | Entire response discarded
     | value == 0x00                    | Entire response discarded
     | value > 0x04                     | Entire response discarded
0x11 | len != 1                         | Entire response discarded
     | value > 2                        | Entire response discarded
0x0E | len != 1                         | Entire response discarded (never requested by the dash)
     | value == 0 or > 4                | Entire response discarded
```

#### Maximum response size for the 9-tag request

```
Tag  | Overhead | Max data | Total
-----|----------|----------|------
0x01 | 2 bytes  | 4 bytes  |  6 bytes
0x02 | 2 bytes  | 1 byte   |  3 bytes
0x04 | 2 bytes  | 1 byte   |  3 bytes
0x05 | 2 bytes  | 1 byte   |  3 bytes
0x06 | 2 bytes  | 6 bytes  |  8 bytes
0x07 | 2 bytes  | 32 bytes | 34 bytes
0x08 | 2 bytes  | 1 byte   |  3 bytes
0x09 | 2 bytes  | 1 byte   |  3 bytes
0x11 | 2 bytes  | 1 byte   |  3 bytes
     |          | Prefix*  |  2 bytes
     |          | TOTAL    | 68 bytes (worst case, max-length SSID)
```

*Prefix = 1 byte firmware artifact (0x00) + 1 byte tag count echo (0x09)

Total Ethernet frame worst case:
14 (Ethernet header) + 12 (XPP header) + 68 (payload) + 2 (DWORD pad) = **96 bytes**

This is well within the 1518-byte Ethernet MTU. Any ADAPTER_INFO_RESPONSE significantly
larger than ~100 bytes indicates the builder is including unrequested tags (e.g. EEPROM
blocks 0x86–0x89 at 512 bytes each). The dashboard never requests EEPROM tags — those
are PC-side setup wizard tags only.

#### Correct values for the 9 tags when no network is configured

```
Tag  | Wire bytes              | Meaning
-----|-------------------------|-------------------------------------------
0x01 | 01 04 00 00 00 00       | IP = 0.0.0.0 (no IP yet)
0x02 | 02 01 00                | DHCP state = no DHCP / searching
0x04 | 04 01 01                | Radio = on (single band)
0x05 | 05 01 01                | Channel = 1 (or saved channel value)
0x06 | 06 06 00 00 00 00 00 00 | BSSID = not connected
0x07 | 07 <len> <ssid bytes>   | SSID string (length byte + data)
0x08 | 08 01 02                | Auth type = open / no WEP
0x09 | 09 01 01                | Enc type = open (no cipher)
0x11 | 11 01 01                | HAL state = not associated
```

## Tag 0x02 Connection State
This byte indicates the connection state to the upstream router or network.
```
Return | Meaning
-------|----------------------------
0x00   | Interface up, no DHCP yet
0x01   | DHCP acquired (fully connected)
0x02   |  Static IP / manual mode
```

### Tag 0x08 Auth Type

Tag 0x08 has different values depending on direction. The dash sends a hint in ADAPTER_INFO_REQ; the adapter returns a status in ADAPTER_INFO_RESP. These are not the same encoding.

**ADAPTER_INFO_RESP (adapter → dash) — wire-verified across all captures:**

The value feeds `xpp_select_best_security_mode()` as `param_1`. Only bits `0x10` and `0x20` gate the WPA path; all other bits are ignored by that function.

```
Return | Meaning                          | Effect in dash
-------|----------------------------------|---------------------------------------------
0x02   | Open network / no WEP            | Downgrade path — enc_type from Tag 0x09
0x04   | WEP active (any key length)      | Downgrade path — enc_type from Tag 0x09
0x10   | WPA active, infrastructure       | WPA path — enc_type=4 (requires byte 174 bit 0x10 set in handshake)
0x20   | WPA active, open-system auth     | WPA path — enc_type=4 (requires byte 174 bit 0x10 set in handshake)
```

Note: `0x10` and `0x20` are only effective if the handshake response byte 174 had bit `0x10` set (`cap_wpa1_rsn` non-zero). Without that, the WPA bits in Tag 0x08 are silently ignored and the downgrade path fires regardless.

**ADAPTER_INFO_REQ (dash → adapter) — hint only, decompile-verified:**

The dash encodes this using `xpp_encode_tag08_auth_type(enc_type, radio_active)`. The adapter is not required to echo this value back.

```
Value | Meaning
------|-------------------------------------------
0x00  | Open/WEP (enc_type 1, 2, or 3)
0x10  | WPA active, radio on  (enc_type=4, radio_active != 0)
0x20  | WPA active, radio off (enc_type=4, radio_active == 0)
```

> **Note:** The `0x10`/`0x20` values encode **WPA mode + radio_active state**, not "Shared Key / Open System authentication" as may be implied elsewhere. Decompiled function `xpp_encode_tag08_auth_type`:
> - `enc_type != 4` (not WPA) → always returns `0x00`
> - `enc_type == 4`, `radio_active != 0` → returns `0x10`
> - `enc_type == 4`, `radio_active == 0` → returns `0x20`
> Wire-verified: `0x00` for all open/WEP captures, `0x10`/`0x20` only appear for WPA connections.

### Tag 0x09 Encryption Type Echo

**Corrected 2026-11-24:** older text said this tag means something completely different in CONNECT_REQ (a link state: `0x01=disassociate`, `0x02=infra`, `0x04=ad-hoc`). The dash decompile (`xpp_encode_tag09_link_state` @000a2a7b) and the captures show the dash builds CONNECT_REQ tag 0x09 from the same encryption type with the same mapping as this response (1 open, 2 WEP-64, 4 WEP-128, 0 WPA). It is an encryption cipher echo in both directions and never says infrastructure or ad hoc.

**ADAPTER_INFO_RESP (adapter → dash) — wire-verified across all captures:**

The value feeds `xpp_select_best_security_mode()` as `param_2`. It is only consulted when Tag 0x08 has no WPA bits set (bits `0x10`/`0x20` both clear).

```
Return | Meaning          | Guard
-------|------------------|-----------------------------------------------
0x00   | —                | REJECTED — entire ADAPTER_INFO_RESP discarded
0x01   | Open / no cipher | Pass — enc_type = 1 (Open)
0x02   | WEP-64 active    | Pass — enc_type = 2 (WEP-64)
0x03   | —                | Pass (accepted but unmatched — falls to Open)
0x04   | WEP-128 active   | Pass — enc_type = 3 (WEP-128)
0x05+  | —                | REJECTED — entire ADAPTER_INFO_RESP discarded
```

For WPA connections (Tag 0x08 = `0x10` or `0x20`): Tag 0x09 is never read by `xpp_select_best_security_mode` since the function returns enc_type=4 immediately. However the value must still pass the guard (`0x01`–`0x04`) or the response is discarded before the function is reached. Send `0x01` for WPA.

### Regulatory Domain Codes (Tag 0x82)

```
Value | Region         | Allowed channels
------|----------------|------------------
0x10  | USA/Canada     | 1–11
0x20  | Canada         | 1–11
0x30  | ETSI           | 1–13
0x31  | Spain          | 10–11
0x32  | France         | 10–13
0x40  | Japan          | 14 only
0x41  | Japan all      | 1–14
other | Unknown        | 1–11 (default)
```

### TX Rate Codes (Tag 0x85)

```
Code  | Rate     | Standard
------|----------|----------
0x00  | Auto     | —
0x02  | 1 Mbps   | 802.11b
0x04  | 2 Mbps   | 802.11b
0x0B  | 5.5 Mbps | 802.11b
0x16  | 11 Mbps  | 802.11b
0x0C  | 6 Mbps   | 802.11g
0x12  | 9 Mbps   | 802.11g
0x18  | 12 Mbps  | 802.11g
0x24  | 18 Mbps  | 802.11g
0x30  | 24 Mbps  | 802.11g
0x48  | 36 Mbps  | 802.11g
0x60  | 48 Mbps  | 802.11g
0x6C  | 54 Mbps  | 802.11g
```

### AR5212 EEPROM Dump (Tags 0x86-0x89)
These tags return the contents of the Atheros AR5212 radio chip's
onboard serial EEPROM The EEPROM is a separate 2KB
chip on the AR5001X MAC/baseband board that holds factory-calibrated radio data burned at
manufacture time.

**EEPROM contents** (2048 bytes total, four 512-byte blocks):
```
Offset       | Contents
-------------|---------------------------------------------------------------
0x000-0x07F  | AR5212 magic word (0x5aa5 at word 0x3D), board configuration,
             | regulatory domain code, factory MAC address (hardware-burned,
             | distinct from the provisioned NVRAM MAC)
0x080-0x1FF  | Per-channel TX power calibration tables (2.4GHz channels 1-14)
0x200-0x3FF  | Noise floor calibration, additional per-channel corrections
0x400-0x7FF  | Extended calibration (often sparse/zeroed on b/g-only hardware)
```

**Special notes**:
- The TLV Length Byte in the response is `0xFF` — a protocol signal indicating an
  "Extended Data Block" of 512 bytes follows, since 512 > 255 (the normal 1-byte length
  maximum).
- The radio must be inactive (tag 0x04 = 0x00) for the EEPROM read to succeed. Querying
  these tags while the radio is associated will return 0xFF-filled blocks.

### Wire Example (Open network, channel 3, WAN connected)

```
Raw payload (after XPP header):
00 09 | 01 04 c0 a8 01 96 | 02 01 00 | 04 01 01 | 05 01 03 |
06 06 c4 4b d1 00 47 4e | 07 04 6f 70 65 6e | 08 01 02 | 09 01 01 | 11 01 02

Decoded:
  Payload           | Meaning
--------------------|--------------------------------------------------
 00                 | Firmware artifact (skip)
 09                 | 9 tags follow
 01 04 c0a80196     | Tag 0x01: IP 192.168.1.150
 02 01 00           | Tag 0x02: DHCP state 0x00
 04 01 01           | Tag 0x04: Radio active
 05 01 03           | Tag 0x05: Channel 3
 06 06 c44bd100474e | Tag 0x06: BSSID c4:4b:d1:00:47:4e
 07 04 6f70656e     | Tag 0x07: SSID "open"
 08 01 02           | Tag 0x08: Auth type open (0x02=open/no WEP)
 09 01 01           | Tag 0x09: Enc type open (0x01=no cipher — DHCP state machine not at 0x52 yet)
 11 01 02           | Tag 0x11: associated 0x02 (set by prior CONNECT_REQ)
```

#### Tag 0x08 in ADAPTER_INFO_RESP — Auth Type

Reports the live 802.11 authentication state. Wire-verified across all captures. This is different from Tag 0x08 in CONNECT_REQ (Type 0x07) where it sets the requested 802.11 auth algorithm, and different from the hint value the dash sends in ADAPTER_INFO_REQ.

The value feeds `xpp_select_best_security_mode()` as `param_1` together with Tag 0x09 as `param_2`. Together they produce the internal `enc_type` (1–4) that drives all subsequent security decisions.

```
Value | Meaning                     | Source in firmware
------|-----------------------------|----------------------------------------------------
0x02  | Open network (no WEP)       | Wire-verified: all open captures
0x04  | WEP encryption active       | Wire-verified: all WEP-64 and WEP-128 captures
0x10  | WPA active, infrastructure  | Decompile only — not seen on wire from stock firmware
0x20  | WPA active, open-system     | Decompile only — not seen on wire from stock firmware
```

Tags 0x08 and 0x09 together report the **NVRAM-configured** state. Tag 0x11 separately reports the **live HAL** state. These can differ during association — for example, an adapter mid-WEP-association will report `tag08=0x04` (WEP configured) and `tag11=0x00` (HAL not yet encrypting) simultaneously.

---

## Type 0x07 — CONNECT_TO_SSID_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Configures the adapter's connection profile and triggers connection. Settings are saved to NVRAM.

### Packet Format

```
Total size: Variable (14 Ethernet + 12 Header + Payload + padding) = N bytes
Body size:  Vairable (12 XPP header + payload + padding) / 4 = N DWORDs

Size     | Segment       | Description
---------|---------------|----------------------------------------------
14 bytes | Ethernet hdr  | Standard
12 bytes | XPP header    | type=0x07, body=variable DWORDs
1 byte   | TLV count     | Number of TLV tags that follow
Variable | TLV stream    | [Tag][Length][Value] triplets
0–3 bytes| Padding       | Zeros to DWORD-align
```

**Tag ordering**: Tags do **not** follow strict ascending numerical order. The dashboard builds the TLV stream in a fixed bitmask-driven sequence (decompile-verified from `xpp_build_connect_request` in `xonlinedash_xbe.c`). The adapter parser makes a single forward pass with no backtracking — tags must appear in the order the firmware expects or later tags will be misinterpreted. Unknown tags abort the entire parse — all subsequent tags in the same packet are silently ignored. Do not send unrecognised tags.

**Decompile-verified wire order** (only tags present in a given packet are emitted; absent tags are skipped):

```
Position | Tag  | Notes
---------|------|----------------------------------------------------------
1        | 0x00 | Save & reboot — if present, always first
2        | 0x01 | IP address
3        | 0x02 | Connection state
4        | 0x03 | Admin password
5        | 0x04 | Network mode (0 = ad hoc, 1 = infrastructure)
6        | 0x05 | Ad-hoc channel number (only in ad-hoc requests)
7        | 0x06 | BSSID
8        | 0x07 | SSID
9        | 0x08 | Auth type
10       | 0x09 | Encryption type (1 open, 2 WEP-64, 4 WEP-128, 0 WPA), NOT a link state
11       | 0x0e | WEP-64 key index (always 1, only with WEP-64 keys; NOT a channel) — emitted HERE between 0x09 and 0x0a (out of numerical order)
12       | 0x0a | WEP key slot 0
13       | 0x0b | WEP key slot 1
14       | 0x0c | WEP key slot 2
15       | 0x0d | WEP key slot 3
16       | 0x0f | WEP-128 key
17       | 0x10 | WPA PMK  ──┐ mutually exclusive — dashboard sends one OR the other
18       | 0x12 | WPA passphrase ──┘ depending on user input (64 hex = 0x10, 8-63 ASCII = 0x12)
19       | 0x11 | Radio band (0 = b, 1 = a, 2 = g) — always last, after 0x10 or 0x12
```

The only intentional out-of-order position is Tag `0x0e` (WEP-64 key index; see the correction under Tag 0x0E below), which the dashboard places after Tag `0x09` and before Tag `0x0a` despite its numeric value being between them. This matches all wire captures. Tag `0x11` is always the final tag in the stream regardless of which WPA key tag precedes it.

### Type 0x07 Tag Table

```
Tag  | Name                | Size  | Description
-----|---------------------|-------|-----------------------------------------------------------
0x00 | Save & reboot       | 0     | Saves current config to flash and triggers reboot
0x01 | IP address          | 4     | Static IP address (big-endian)
0x02 | Connection state    | 1     | 0x02=enable interface, any other=disable
0x03 | Admin password      | 0–16  | XPP admin password. Len=0 clears the password.
     |                     |       | Factory default "admin". Max 16 printable ASCII chars.
0x04 | Network mode        | 1     | Real dash: 0x00=ad hoc, 0x01=infrastructure (capture-verified 2026-11-24).
     |                     |       | Older text said 0x00=disable radio, 0x01=enable radio; the dash never sends it so.
0x05 | Ad-hoc channel      | 1     | Channel number for an ad-hoc network (2.4 GHz channel, or an 802.11a channel
     |                     |       | from the 5 GHz list). Real dash sends it only in ad-hoc requests; infrastructure
     |                     |       | requests carry no channel at all (the AP decides).
0x06 | Target Xbox MAC     | 6     | MAC address of the paired Xbox console
0x07 | Target SSID         | 1–32  | Network SSID to connect to
0x08 | Security mode       | 1     | WEP/security flag written to hardware
0x09 | Encryption type     | 1     | Real dash: 0x01=open, 0x02=WEP-64, 0x04=WEP-128, 0x00=WPA (the same mapping as
     |                     |       | ADAPTER_INFO_RESP; decompile of xpp_encode_tag09_link_state, captures). It does NOT
     |                     |       | carry infrastructure/ad-hoc (that is tag 0x04): ad-hoc WEP-64 and infrastructure
     |                     |       | WEP-64 both send 0x02. Older text called it a link state (0x01 disassociate, 0x02
     |                     |       | infra, 0x04 ad hoc); our Windows tool still sends that form to a real adapter.
0x0A | WEP key slot 0      | 5     | WEP-40 5-byte key for slot 0
0x0B | WEP key slot 1      | 5     | WEP-40 5-byte key for slot 1
0x0C | WEP key slot 2      | 5     | WEP-40 5-byte key for slot 2
0x0D | WEP key slot 3      | 5     | WEP-40 5-byte key for slot 3
0x0E | WEP-64 key index    | 1     | Real dash: 1-based default WEP-64 key index, always 1, sent only with the WEP-64
     |                     |       | keys (xpp_ui_process_wep64_key_input). NOT a channel. Our Windows tool sends a
     |                     |       | channel here (older form).
0x0F | WEP-128 key         | 13    | 13-byte WEP-128 key written to all 4 slots
0x10 | WPA PMK             | 32    | 32-byte Pairwise Master Key (from 64-hex user input).
     |                     |       | ⚠ Stock firmware discards this — see WPA section.
0x11 | Radio band          | 1     | Real dash: 0=802.11b, 1=802.11a, 2=802.11g (dash field +0xf5f; see the Tag 0x11 section).
     |                     |       | Stock MN-740 firmware acts only on 0x00 and 0x02 (as a saved encryption state)
     |                     |       | and silently ignores 0x01; the MN-740 has no 802.11a radio.
0x12 | WPA passphrase      | 8–63  | ASCII WPA passphrase.
     |                     |       | ⚠ Stock firmware has no handler — aborts parse loop.

Only tags 0x00-0x12 are processed by the xonlinedash.xbe
```

## special function and device specific tags

```
Xbox networking tags
Tag  | Name                | Size  | Description
-----|---------------------|-------|-----------------------------------------------------------     
0x14 | MAC clone           | 6     | MAC address to spoof.
     |                     |       | No handler in stock firmware's Type 0x07 parser —
     |                     |       | MAC cloning operates implicitly via the HANDSHAKE path.

Mn-740 specific
Tag  | Name                | Size  | Description
-----|---------------------|-------|-----------------------------------------------------------  
0x81 | Session MAC init    | 6     | Register Xbox MAC as trusted peer, initialise session
0x82 | Interface reset     | 1     | 0x00=skip disconnect, go straight to MAC reinit.
     |                     |       | Non-zero=disconnect first then reinit.
0x83 | Net reset param     | 1     | Reconnect mode (0, 1, or 2). Factory default 1.
0x84 | Saved channel       | 1     | Stored channel value — reported as current channel when radio not associated (read-back of Tag 0x84 write)
0x85 | TX rate code        | 1     | Force TX rate. Invalid codes silently dropped.

WGA54G specific tags (not confirmed fully)
Tag  | size  | Description
-----|-------|-----------------------------------------------------------  
0x13 | 1-32  | WAN connection type
0x14 | 1-32  | WAN username (PPPoE)
0x15 | 1-32  | WAN password (PPPoE)
0x16 | 4     | WAN IP (static)
0x17 | 4     | WAN subnet mask
0x18 | 4     | WAN gateway
0x19 | 4     | Primary DNS
0x1a | 4     | Secondary DNS
0x1b | 2     | MTU
0x1c | 6     | WAN MAC clone
0x1d | 1     | Interface reset
0x1e | 1     | Net reset param
0x1f | 1     | Max channel ceiling
0x20 | 5     | WEP key slot 3
0x21 | 13    | WEP key slot 4 / WEP-128
0x22 | 1     | TX rate code
0x23 | —     | Silently dropped
0x24 | —     | Silently dropped
0x25 | —     | Silently dropped
0x26 | 1     | UPnP enable flag
0x27 | 1     | Firewall enable flag
0x28 | —     | Silently dropped
0x29 | —     | Silently dropped
0x2a | —     | Silently dropped
0x2b | —     | Silently dropped
0x2c | —     | HMAC auth block
0x2d | —     | HMAC auth block
0x2e | —     | HMAC auth block (string ref confirmed)
0x2f | —     | HMAC auth block
0x30 | —     | HMAC auth block
0x31 | —     | HMAC auth block
0x32 | —     | HMAC auth block
0x33 | —     | HMAC auth block
0x34 | —     | Default/error → no-op
0x35 | 1-4   | DHCP server config
```

**Tag 0x10 stub**: Stock firmware advances the parse pointer past the 34-byte tag (1 tag + 1 len + 32 data) but does not store the PMK. See [WPA/WPA2 Implementation](#wpawpa2-implementation).

**Tag 0x12 parse abort**: Stock firmware has no `case 0x12`. It logs "got_unknown" and exits the TLV loop immediately. Any tags after Tag 0x12 in the same packet are not processed.

**Tags above 0x12** are never sent by the Xbox dashboard, They are management tags for factory/ future purpose.

**Note** The dashboard has two mutually exclusive code paths for WPA key input. Only one of Tag 0x10 or Tag 0x12 will ever appear in a single CONNECT_REQ — never both. Which tag is sent depends entirely on what the user typed at the on-screen keyboard:

- Exactly 64 hex digits → dashboard pre-computes the PMK and sends it via Tag 0x10
- 8–63 ASCII characters → dashboard sends the raw passphrase via Tag 0x12

In both cases Tag 0x11 (radio band; called an auth mode flag in older text) follows as the final tag in the packet.


### Tag 0x03 — Admin Password

The admin password prevents other consoles from reconfiguring a paired adapter. When set, the adapter's TFTP WRQ auth on port 16932 uses this string as the HMAC input. Factory default is `"admin"`.

```
Set:   Tag 0x03, len=N, val="newpassword"
Clear: Tag 0x03, len=0x00
```

### Tag 0x04 Network mode
**Correction 2026-11-24:** in CONNECT_REQ the dash sends this tag as the network mode (dash field +0xf5c), not as a radio on/off switch. It is only present when the mode changed or the bitmask was set (infrastructure sets it through `set_shared_key_mode`). Capture-verified: ad-hoc requests carry `04 01 00`, infrastructure requests `04 01 01`.

```
Hex  | Description
-----|-------------
0x00 | Ad hoc
0x01 | Infrastructure
```
(ADAPTER_INFO_RESP tag 0x04, "radio active", is a different thing; see its section.)

### Tag 0x08 Security Mode (CONNECT_REQ)

Sets the 802.11 authentication algorithm the adapter should use for the connection. This is the authentication handshake method, not the encryption cipher.

Encoded by the dash using `xpp_encode_tag08_auth_type(enc_type, shared_key_flag)`.

```
Value | Meaning                                         | Wire seen
------|-------------------------------------------------|----------
0x00  | Open System authentication                      | Yes — all open and WEP open-auth captures
0x10  | WPA + Shared Key 802.11 auth (enc_type=4, shared_key=1) | WPA only
0x20  | WPA + Open System 802.11 auth (enc_type=4, shared_key=0)| WPA only
```

Note: `0x00` is sent for both open networks AND WEP connections using open-auth (the most common WEP mode). The presence of WEP keys in tags `0x0A`–`0x0D` or `0x0F` indicates WEP encryption regardless of this field's value.

---

### Tag 0x09 (encryption type; the function name xpp_encode_tag09_link_state is misleading)
**Correction 2026-11-24:** the dash builds this tag from its encryption type field (+0xf5e) with the same mapping as ADAPTER_INFO_RESP. It does not say infrastructure or ad hoc.

```
Val  | Meaning (real dash)
-----|------------------------
0x00 | WPA
0x01 | Open (no cipher)
0x02 | WEP-64
0x04 | WEP-128
```
Captures: open infrastructure sends 1, WEP-64 infrastructure and ad hoc both send 2, WEP-128 infrastructure sends 4. The older reading (0x01 disassociate, 0x02 infrastructure, 0x04 ad hoc) is what our Windows tool still sends to a real adapter, and the adapter answered it; how the MN-740 firmware (NML.bin) really treats the values is not audited yet. Earlier notes that a 0x01 with an SSID means "disassociate first" were captures of ordinary open-network connects, so treat that as unverified.
### Tag 0x05 - Ad-hoc channel (documented here as Tag 0x0E until 2026-11-24)
**Correction 2026-11-24:** the real dash sends the ad-hoc channel in **Tag 0x05**, not Tag 0x0E. Tag 0x0E in the dash is the WEP-64 default key index: it is always 1 and only appears together with the WEP-64 keys (`xpp_ui_process_wep64_key_input` writes 1 into it; no other code path writes it). Capture-verified: `adhocopen` sends `05 01 06` and no 0x0E; WEP-64 infrastructure with the AP on channel 9 sends `0e 01 01` and no channel at all. The channel is validated against the 2.4 GHz channel mask (bytes 176-179 of the handshake) or, for 802.11a, the extended channel list (bytes 180-207), and changing the band reloads it from the first entry of the new list. The text below describes the channel, which belongs to Tag 0x05.

This tag is used as the channel used in the setup Of an Ad-hoc network.
This is used more for the hosting device that sets up the initial connection,
Any other device join an existing Ad-hoc network will ignore this and scan for the SSID in the connect request and use the channel found during scan to setup the network.
valid values depends on the country code stored in the EEPROM from factory.

```
Value | Region                  | Allowed Channels (2.4 GHz)
------|-------------------------|-----------------------
0x00  | USA / Canada (FCC)      | 1-11
0x01  | Japan (TELEC)           | 1-14
0x02  | Europe (ETSI)           | 1-13
0x03  | Australia / New Zealand | 1-13
0x04  | Korea                   | 1-13
```

**Ad-hoc channel limits:**

The Ad-hoc channel creation option in the Xbox UI shows channels 1–12. This is a hardcoded limit of the dash.
this limit is completely independent of byte `Channel allow list bitmaskt`

When joining (not creating) an ad-hoc network, the channel comes from the SCAN_RESP entry,
this means if a device creates a network outside of channels 1-12 the Xbox can join the network by setting up the Ad-hoc network with the same SSID .

Additionally the dash has a guard that will downgrade a WPA connection to open
if WPA2 enterprise capability is absent, it is believed this is to minimize the risk of loosing BSS sync.

### Tag 0x10 — WPA PMK
This field IS the WPA Pairwise Master Key (PMK) entry.

### Tag 0x12 — WPA Passphrase
This field IS the WPA ASCII key entry.

**Tag 0x12 Wire Format**:
```
Offset | Size  | Field      | Description
-------|-------|------------|------------------
0      | 1     | Tag        | 0x12
1      | 1     | Length     | 8–63 (WPA2 passphrase length)
2-N    | 8-63  | Passphrase | Raw ASCII passphrase (0x20–0x7e only)
```

### Tag 0x14 — MAC Address Cloning
MAC cloning makes the Xbox and adapter appear as a single device to the router, solving NAT and MAC-filter issues. Rather than sending Tag 0x14 in a Type 0x07 packet, the Xbox NIC driver changes its source MAC to the cloned address. The adapter then implicitly registers this MAC during the handshake:

1. Xbox NIC broadcasts HANDSHAKE_REQ from the cloned MAC
2. Adapter stores the cloned MAC as the paired console identity
3. Adapter re-initialises the WLAN interface using the cloned MAC as its transmitter address
4. Router sees one consistent MAC for both Wi-Fi association and DHCP

The HMAC computation always uses the adapter's own hardware MAC as input, not the cloned identity. Tag 0x82 (Interface Reset) with a non-zero value will restore the hardware MAC.

This can also be used to bypass MAC based filtering blocks.

**Alternative use case (2004):** PPPoE-based MAC authentication.
Cloning the PC's MAC bypassed ISP MAC-lockout by making the device present as the official paired device.
With a normal home router the ISP never sees the Xbox MAC — the router's WAN MAC
is what the ISP sees. The MAC clone still benefits router-side DHCP/MAC filtering.

**Format**: 6-byte MAC address in standard network byte order.

### Tag 0x81 — Session MAC Init (hardware pairing)
This tag sets the MAC included in this payload as the trusted device for all communication, all other devices will be ignored even if they send a valid handshake, the Xbox will respond all communication to this MAC.
**Function**: `XPP_Establish_Secure_Identity_Link(p_mac_addr)`:
1. Calls `Net_Init_Socket_Logic(p_mac_addr, 6)` to validate/register the MAC.
2. If successful: calls `NET_Register_Peer_MAC(p_mac_addr)` to store the Xbox MAC as the trusted peer.
3. Sets `g_XPP_Current_Session_ID = XPP_Get_Identity_Token()` to start a new authenticated session.

**Note** The HMAC-SHA1 session authentication in HANDSHAKE derives from this peer MAC, be very at carefull when setting value as this can Softbrick the adaptor if you are unable to reply from the address paired to unset the pairing.

## Tag 0x82 — Interface Reset/Reinit
```
Value  | Meaning
-------|----------------------------------
= 0x00 | Skip disconnect_interface_handle(), go straight to MAC reinit
≠ 0x00 | First call disconnect_interface_handle(0, value) (tear down with that reason code), then reinit
```
**Note**: After the conditional disconnect, the firmware calls `NET_Reinit_Interface_With_MAC()` which reinitializes the WLAN interface using the hardware MAC from `ath_hal_get_hw_info()`. If that returns an all-zero MAC (hardware failure), the reinit step is silently skipped. This is one mechanism for **undoing MAC address spoofing** — reinit restores the hardware MAC.

### Tag 0x84 — Saved Channel / HTTP UI Channel

`g_CFG_Max_Channel` stores the last configured channel, persisted to NVRAM via `Flash_Commit_Settings`.

**What it actually does:**
- Read by `XPP_Get_Channel_Or_Fallback()` as the reported channel in HANDSHAKE_RESP byte 217 and Tag 0x05 response **when the radio is not currently associated**. When the radio is associated, the live channel from `wlan_freq_to_channel_number()` is returned instead.
- Displayed in the HTTP web UI channel dropdown via `net_spinlocked_global_state_reset()`.
- Returned verbatim by Tag 0x84 in ADAPTER_INFO_RESP as a read-back of the stored value.
- Initialised to `0x0b` (channel 11) on factory reset.

**What it does NOT do:**
- It is never consulted during scanning, connection, or channel selection.
- It has no interaction with the handshake channel bitmask (bytes 180–207).
- It does not enforce regulatory channel limits on the radio.

The handshake channel bitmask is the actual regulatory mechanism. Tag 0x84 and the bitmask are completely independent systems that never interact. For an emulator, Tag 0x84 is effectively a no-op — accept the write, store it, return it on read-back.

**Write clamping**: Values written outside the hardware EEPROM's regional min/max are clamped to `0x0b` (channel 11). This only affects the stored value — it does not influence radio behaviour.

```
Reg Domain | Min Channel | Max Channel | Default if invalid
-----------|-------------|-------------|-------------------
0x30       | 1           | 13          | 11
0x31       | 10          | 11          | 11
0x32       | 10          | 13          | 11
0x40       | 14          | 14          | 11
0x41       | 14          | 14          | 11
other      | 1           | 11          | 11
```
### Tag 0x85 - Rate Whitelist/ Tag 0x84 rate Index
**Note**: The "index" column is the Xbox-side sequential index inferred from firmware bounds checking in the Tag 0x84 chip revision table above. The "Hex" column is the actual PHY rate code written to `g_CFG_TX_Rate_Validated` and transmitted on the wire. These PHY rate codes are the same values returned in Type 0x0A BEACON_RESPONSE byte 2 (`tx_rate_code` via `drvr_get_tx_rate_code()`). The two tables are describing the same rate-code enumeration — one from the write path (Type 0x07), one from the read/status path (Type 0x0A).
```
 index    |Hex   | Rate (Mbps) | Standard  | Notes
----------|------|-------------|-----------|--------
          | 0x00 | Auto-select | -         | Automatic rate negotiation
 0x01     | 0x02 | 1 Mbps      | 802.11b   | Legacy compatibility
 0x02     | 0x04 | 2 Mbps      | 802.11b   | Legacy compatibility
 0x04     | 0x0B | 5.5 Mbps    | 802.11b   |
 0x0B     | 0x16 | 11 Mbps     | 802.11b   | Maximum 802.11b rate
 0x0C     | 0x0C | 6 Mbps      | 802.11g   | Basic rate
 0x12     | 0x12 | 9 Mbps      | 802.11g   |
 0x18     | 0x18 | 12 Mbps     | 802.11g   |
 0x24     | 0x24 | 18 Mbps     | 802.11g   |
 0x30     | 0x30 | 24 Mbps     | 802.11g   |
 0x48     | 0x48 | 36 Mbps     | 802.11g   |
 0x60     | 0x60 | 48 Mbps     | 802.11g   |
 0x6C     | 0x6C | 54 Mbps     | 802.11g   | Maximum 802.11g rate
```
**Note**: .5 Mbps is the firmware clamp/ fall-back value set if an invalid rate code is received.
And the index column is speculative / inferred as there is no index in the firmware with mapping.

### Examples:

**Open network** (real adapter capture, infrastructure open, channel 9):
```
Raw (60 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 09 07 bf dc 87 0a 04 07 0b 6f 70 65
  0020: 6e 5f 63 68 39 5f 62 67 08 01 00 09 01 01 11 01
  0030: 00 00 00 00 00 00 00 00 00 00 00 00

XPP type=0x07, TLV count=4
  Tag 0x07 SSID         len=11  "open_ch9_bg"
  Tag 0x08 Sec mode     len=1   0x00  (open)
  Tag 0x09 Enc type     len=1   0x01  (open, no cipher; older text read this as disassociate/idle)
  Tag 0x11 Auth mode    len=1   0x00  (no encryption)
  Padding: 00 00 00 00 00 00 00 00 00 00 00 00
```

**WEP-64 ASCII with 4 key slots** (real adapter capture, infrastructure WEP-64, channel 9):
```
Raw (78 bytes):
  0000: 00 12 5a 33 fa 31 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 10 07 db 02 46 01 08 07 0c 77 70 61
  0020: 5f 36 34 5f 63 68 39 5f 62 08 01 00 09 01 02 0e
  0030: 01 01 0a 05 61 62 63 64 65 0b 05 61 62 63 64 65
  0040: 0c 05 61 62 63 64 65 0d 05 61 62 63 64 65

XPP type=0x07, TLV count=8
  Tag 0x07 SSID         len=12  "wpa_64_ch9_b"
  Tag 0x08 Sec mode     len=1   0x00
  Tag 0x09 Enc type     len=1   0x02  (WEP-64; older text read this as infrastructure connect)
  Tag 0x0E Key index    len=1   0x01  (WEP-64 key index 1; older text read this as channel 1)
  Tag 0x0A WEP key 0    len=5   61 62 63 64 65  ("abcde")
  Tag 0x0B WEP key 1    len=5   61 62 63 64 65
  Tag 0x0C WEP key 2    len=5   61 62 63 64 65
  Tag 0x0D WEP key 3    len=5   61 62 63 64 65
```

**Set admin password** (real adapter capture, admin password set):
```
Raw (60 bytes):
  0000: 00 0d 3a 1f 26 09 00 0d 3a 50 22 73 88 6f 58 42
  0010: 4f 58 01 01 07 07 7b c4 d8 a4 01 03 0a 61 61 62
  0020: 62 63 63 64 64 65 65 00 00 00 00 00 00 00 00 00
  0030: 00 00 00 00 00 00 00 00 00 00 00 00

XPP type=0x07, TLV count=1
  Tag 0x03 Admin pwd    len=10  "aabbccddee"
```

Beacons/multicast cap at 2 Mbps
unicast cap at 11 Mbps
ARF steps up to 11 Mbps ceiling
These rates are a hardcoded firmware limitation designed to ensure BSS stability and prevent 'Hidden Node' collisions during System Link play.

## Clock Synchronization:
Ad-Hoc peers rely on TSF (Timing Synchronization Function) found in beacons to keep their hardware clocks in sync. If these were sent at 54 Mbps, a peer at the edge of the range might miss them, causing the Ad-Hoc network to "split."

Because Ad-Hoc networks lack a central Access Point to manage "Hidden Nodes" (where two Xboxes can see the host but not each other). High-speed OFDM (54 Mbps) is very sensitive to collisions. By capping the data at 11 Mbps (DSSS/CCK), the signal is much more "penetrating" and less likely to drop frames during intense System Link play.

**Related**: Tag 0x82 (`NET_Interface_Reset_And_Reconnect`) calls `NET_Reinit_Interface_With_MAC()`
which restores the hardware MAC from `ath_hal_get_hw_info()` — this clears the clone and restores
the real identity.

---

## Type 0x08 — CONNECT_TO_SSID_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Confirms the connection request result.

### Packet Format

```
Total size: 30 bytes (14 Ethernet + 12 XPP + 1 payload + 3 padding)
Body size:  0x04 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x08, body=0x04 DWORDs
1 byte   | Result code     | See table below
3 bytes  | Padding         | Zeros
```

### Result Codes

```
Code | Description
-----|------------------------------------------------------------------
0x00 | Success — connection accepted and config committed (wire-verified)
0x01 | Rejection / error
0x02 | Retry requested — dashboard retries after ~8 seconds
0x03 | Rejection / error
0x04 | Error (connect-specific)
0x05 | Unconfirmed    | Timed Out
0xFF | Unconfirmed    | General error
```

---

## Type 0x09 — BEACON_REQUEST

**Direction**: Xbox → Adapter  
**Transport**: NLB (EtherType 0x886f)

Keepalive heartbeat. Sent every 1 second while connected.

### Packet Format

```
Total size: 26 bytes (14 Ethernet + 12 XPP)
Body size:  0x03 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x09, body=0x03 DWORDs
```

**Timing**: Sent every 1 second. If no response is received for 5 seconds the adapter enters standby mode. The adapter also has a 30-second watchdog — if no Ethernet frame is received from the paired Xbox MAC for 30 seconds, the radio shuts down.
the adaptor monitors for any valid Packet to reset the watchdog timer.
If the watchdog timer should elapse the adaptor Requires full re-authentication (Type 0x01 handshake)

---

## Type 0x0A — BEACON_RESPONSE

**Direction**: Adapter → Xbox  
**Transport**: NLB (EtherType 0x886f)

Response to Type 0x09. Returns authentication status, signal strength, and current TX rate. Sent within ~100 ms of receiving a beacon request.

### Packet Format

```
Total size: 46 bytes (14 Ethernet + 12 XPP + 4 payload + 16 uninitialised padding)
Body size:  0x04 DWORDs

Size     | Segment         | Description
---------|-----------------|-----------------------------
14 bytes | Ethernet header | Standard
12 bytes | XPP header      | type=0x0A, body=0x04 DWORDs
4 bytes  | Payload         | See below
16 bytes | Firmware padding| Uninitialised memory — ignore
```

**⚠ The 16 bytes after the 4-byte payload are uninitialised memory, not part of the protocol.** The body size correctly covers only the 4-byte payload. Implementations should tolerate and ignore this trailing data.

### Payload Structure (4 bytes)

```
Offset | Size   | Field        | Values
-------|--------|--------------|----------------------------------------------------
0      | 1 byte | Auth status  | 0x00=authenticated, 0x01=associating,
       |        |              | 0x02=open/idle (also steady-state for open networks),
       |        |              | 0x03=WEP association in progress. Values >0x03 rejected.
1      | 1 byte | Smoothed RSSI| Firmware quality index (unsigned byte, firmware-specific scale).
       |        |              | 0xBA=seed value when not authenticated.
       |        |              | When associated: 10-sample growing-window average (adapter firmware).
       |        |              | See Signal Strength Scaling.
2      | 1 byte | TX rate code | Raw 802.11 rate code with basic-rate bit stripped (& 0x7F).
       |        |              | See rate code table in Type 0x06.
       |        |              | Ad-hoc mode cap: maximum 0x16 (11 Mbps).
3      | 1 byte | Reserved     | Always 0x00
```

### Auth Status (Byte 0)
```
Value | Meaning
------|------------------------------------------------------------
0x00  | Authenticated (also briefly seen mid-association on open networks)
0x01  | Associating
0x02  | Open/idle, and the usual steady state of a real adapter (mostly 02 with a 00 every ~4-9 beacons)
0x03  | Association in progress after ANY CONNECT_REQ (open, WEP and WPA alike; about 37-45 beacons on a real adapter)
```

### How the dash uses the auth status (verified on a stock Xbox, 2026-11-24)

- The dash polls BEACON_REQ every 1000 ms and keeps a 5-sample ring of the replies. Status 0x01 and 0x03 reset the ring; 0x02 is buffered but never counts as connected.
- The **only** way to reach the connected state is an assoc-0 sample inside the 5-sample window: that gives "authenticated" with the averaged RSSI. Without it the status screen (name, speed, strength, connected) shows "not connected" and flips back and forth.
- The Wireless Status screen also needs: link up, error flag not `0x80000001`, and beacon state 0. Bars: RSSI > -58 dBm = 5 bars.
- While connecting, the dash gives each request a 3000 ms timeout, reset by any accepted response; expiry clears "connected" and sets `0x80000001`.
- **Joined**: send `00 rssi rate 00`. **Not joined, after a CONNECT_REQ**: a real MN-740 sends status 0x03 (rate 0x16 / 0x6c, sometimes 0x00) for about 40-50 beacons with occasional `00 rssi` frames, then 0x02. It never sends 0x01. The wrong-password or missing-network screen appears once the status settles on 0x02. Sending 0x02 while actually joined (e.g. the tool restarted and lost the CONNECT_REQ) gives the "security type or key incorrect" screen even with the right key.
- CONNECT_REQs without an SSID (for example `01 04 01 01` radio on, or `01 05 01 09` channel only) are partial updates, not disconnects. Only tag 0x09 value 0x01 means disassociate (UNVERIFIED: the dash sends 0x01 for any open network, see the Tag 0x09 correction; no capture of a deliberate disconnect has been checked against this).
- INFO_RESP tag 0x04 (radio active) must be 0 or 1; sending 2 makes the dash discard the reply and show "technical difficulties" on the More Info screen.
- **Real MN-740 sequences** (real adapter captures, run-length of BEACON_RESP auth status): after CONNECT_RESP `A03 x17, A00 x1-2, A03 x12-18, A00 x1, A03 x6` (about 37 in all), then steady state `A02 x5-8, A00 x1, A02 x3, A00 x2 ...`. Open connect with a WAN, WEP, ad-hoc and password captures all follow this pattern, and no capture contains 0x01. The 0x03 phase is not WEP-specific.

### Smoothed_rssi (Byte 1)

This byte is produced by a **10-sample growing-window average** on the adapter firmware side (`drvr_get_smoothed_rssi`, NML_bin.c firmware-verified). The window grows from 1 sample to 10, then stays at 10. The dashboard (`xonlinedash.xbe`) then stores up to 5 of the received values in its own circular buffer for further smoothing — these are two independent layers.

```
return      | Description / Value
------------|---------------------
0x80        | pre-seed buffer state (uninitialised global — firmware does not write this)
0xBA        | seed value written explicitly when link_state == 0x01 or 0x03
other       | 10-sample growing-window average RSSI (firmware-side; stored only when link_state == 0x00 AND rssi > −91 dBm on dashboard side)
```

**Forced 0xa6 substitution (decompile-verified)**: When `link_state == 0x02` (open/idle), the firmware
forcibly stores `0xa6` in the circular buffer for that sample slot — the actual received RSSI byte is
**discarded**. Only `link_state == 0x00` entries contribute real RSSI measurements to the average.
This prevents an idle/open-network state from polluting the RSSI history.

**Minimum threshold guard (decompile-verified)**: When `link_state == 0x00`, the RSSI byte is only
stored if it is **greater than `−0x5b` (−91 dBm)** as a signed value. If the received RSSI is ≤ −91 dBm,
the handler returns failure (0) and does not update the state. Emulators should always return a RSSI
value above −91 dBm to avoid repeated handshake failures.

**Note**: byte 44 signal RSSI has custom scaling see [Signal strength / link quality scaling)](Signal strength / link quality scaling)
Seed value `0xba` written explicitly when not authenticated
Value `0x80` is pre-association default; `g_RSSI_Smoothed_Output` is an
uninitialised global — `0x80` is not written by firmware, it reflects BSS/memory state.

### Raw 802.11 rate code (Byte 2)

This byte shows the current rate code of the current connection

```
Result code | Description/ value
------------|---------------------
0x00        | Not associated / no data frame sent
0x02        | 1 Mbps (802.11b)
0x04        | 2 Mbps (802.11b)
0x0B        | 5.5 Mbps (802.11b)
0x16        | 11 Mbps (802.11b)
0x0C        | 6  Mbps (802.11g)
0x12        | 9  Mbps (802.11g)
0x18        | 12 Mbps (802.11g)
0x24        | 18 Mbps (802.11g)
0x30        | 24 Mbps (802.11g)
0x48        | 36 Mbps (802.11g)
0x60        | 48 Mbps (802.11g)
0x6C        | 54 Mbps (802.11g)
```

### ⚠ Rate limit Cap
The firmware enforces a hardware rate cap in ad-hoc mode:
- **Not Linked**:     tx_rate_code = `0x16` (11 Mbps) — returned as the pre-association / not-yet-linked default rate
- **Infrastructure**: tx_rate_code = `0x6C` (54 Mbps) — No Rate limit
- **Ad-hoc**:         tx_rate_code = `0x16` (11 Mbps) — hardcoded ceiling
This is a deliberate firmware design decision for BSS stability and Hidden Node collision avoidance. See Tag 0x07 section for full explanation.


### reserved (Byte 3)
```
Result code | Description/ value
------------|---------------------
  0x00      | hardcoded reserved
```

---

## Types 0x0B, 0x0C, 0x0F — Silently Dropped

The adapter silently discards any frame with these type bytes.
No response is sent. This type is undocumented — it is an unused slot possibly for future expansion.

- **0x0B**: Discarded, internal counter incremented
- **0x0C**: Discarded, internal counter incremented  
- **0x0F**: Discarded with no log and no counter

---

## Type 0x11 — WPA_ASSOC / WPA_EXCHANGE

> ⚠️ **CORRECTION (2026-11-24): this section describes the Xbox PPPoE client, not WPA.** The frames labelled "Type 0x11 / WPA_ASSOC_REQ" are PPPoE Discovery (EtherType 0x8863: `88 63`, `11` version/type, `09` PADI or `19` PADR). The "EAPOL 0x888e" transport and the WPA wording below came from a misread of the dash code. No adapter sends or answers these as XPP. WPA joins are done by CONNECT_REQ tag 0x12 / 0x10 only. See "PPPoE client (EtherType 0x8863 / 0x8864)" further down. The sub-type, frame-type-word and sub-TLV tables in this section are unverified until a PPPoE capture exists.

**Direction**: Bidirectional (Console ↔ Adapter)  
**Transport**: EAPOL (EtherType 0x888e)

Type 0x11 is the WPA authentication sub-protocol. It is **not** an XPP management packet — it has no XPP magic, no body size DWORD count, and no RFC 1071 checksum. No stock adapter firmware implements WPA, so no wire captures of this exchange exist. This section documents the protocol as implemented in the Xbox dashboard (`xonlinedash.xbe`), sufficient to drive the console through a full WPA session from the adapter side.

The real WPA connection (802.11 layer, happens outside XPP entirely):

The console sends Type 0x07 CONNECT_TO_SSID_REQUEST with Tag 0x10 (PMK) or Tag 0x12 (passphrase) to tell the adapter what network to join and what key to use
The adapter then does the standard 802.11 WPA association and 4-way EAPOL key exchange directly with the access point, completely independently of the console
This is the part that is currently broken in stock firmware (Gap 3 — the eapol_handle_key_exchange stub)

Type 0x11 only runs after the adapter is already 802.11-associated to the WPA network. It is XPP's mechanism for the adapter to hand the console an IP address and gateway configuration using a challenge/nonce scheme layered over EAPOL framing. Essentially it is a bespoke DHCP-replacement tunnel — the adapter negotiates an IP for the Xbox through the already-established wireless link and delivers it via the Type 0x11 exchange.

Type 0x11 then only matters if you want the Xbox IP stack to get its address through the adapter rather than through a normal DHCP exchange visible on the wired side. On an open or WEP network the Xbox gets its IP via normal DHCP bridged transparently.

This alternative DHCP path for WPA networks where the IP negotiation is handled differently was not implemented on any known adaptor.
The Type 0x11 section could arguably be trimmed from the adaptor as it just provides a second way to get a DHCP address.

Eapol is typically used to prove identity for WPA2 enterprise networks before allowing connection.


### Frame Header (all Type 0x11 frames)

```
Offset | Size    | Field           | Value
-------|---------|-----------------|------------------------------------------------
0      | 6 bytes | Destination MAC | FF:FF:FF:FF:FF:FF (broadcast) or unicast on retry
6      | 6 bytes | Source MAC      | Sender MAC
12     | 2 bytes | EtherType       | 0x888e
14     | 2 bytes | Frame type word | 0x6388 (normal) or 0x123c (first of a retry pair)
16     | 1 byte  | Type marker     | 0x11 (constant)
17     | 1 byte  | Sub-type        | Identifies direction and stage (see below)
18     | 2 bytes | Reserved        | 0x0000
20     | 2 bytes | Length          | Big-endian payload length in bytes
22     | 2 bytes | Reserved        | 0x0000
24     | var     | Payload         | Sub-TLVs: [tag:1][len:1][data:len]
```

The frame type word selects which sub-protocol is active and is checked by the console before parsing sub-TLVs:

```
Frame type word | Sub-protocol                        | Direction
----------------|-------------------------------------|--------------------
0x21c0          | IP negotiation + WPA challenge      | Adapter → Console
0x23c0          | ANonce/SNonce retransmit            | Adapter → Console
0x2180          | Post-auth IP configuration          | Adapter → Console
```

### Sub-type Values

```
Sub-type | Direction         | Meaning
---------|-------------------|--------------------------------------------------
0x09     | Console → Adapter | WPA_ASSOC_REQ — first attempt (broadcast)
0x19     | Console → Adapter | WPA_ASSOC_REQ — retry (unicast to AP MAC)
0x01     | Console → Adapter | Credential / IP exchange reply (always 0x01)
0x01     | Adapter → Console | IP negotiation or post-auth IP config
0x09     | Adapter → Console | ANonce delivery
```

⚠️ **NEVER send sub-types 0x05, 0x07, or 0x08 to the console** — these trigger an immediate unrecoverable abort (`XPP_fsm_fatal_error`), not a silent drop.

### Console → Adapter: WPA_ASSOC_REQ

Sent by the console to begin WPA association. The adapter receives this and begins 802.11 WPA association silently — there is no acknowledgement frame. Once the 802.11 association completes the adapter starts driving the console forward with its own Type 0x11 frames.

**First attempt** (sub-type `0x09`, broadcast):

```
Offset | Size  | Field    | Value
-------|-------|----------|-------------------------------------------------------
0      | 2     | Sub-tag  | 0x0101 (SSID record)
2      | 2     | Length   | Big-endian SSID length
4      | N     | SSID     | Target network SSID bytes
4+N    | 2     | Sub-tag  | 0x0301 (state counter)
6+N    | 2     | Length   | 0x0004
8+N    | 4     | Counter  | Session state change counter
```

**Retry** (sub-type `0x19`, unicast to AP MAC): same structure but the SSID sub-TLV is replaced by the ANonce material received from the AP in the previous exchange.

### Adapter → Console: Full Exchange Sequence

The adapter must drive the console through four frames in order. The console sends a reply after frames 1 and 3 (sub-type `0x01`).

```
Step | Sub-type | Frame type | Sub-TLVs to send                              | Console reply
-----|----------|------------|-----------------------------------------------|-----------------------------
1    | 0x01     | 0x21c0     | tag=0x03, len=4, data=0x23c0 (challenge)      | Sends sub-type 0x01 with
     |          |            | tag=0x05, len=6, data=<6-byte nonce>          | NOT(nonce) + 0x23c2 token
2    | 0x01     | 0x21c0     | tag=0x01, len=4, data=<proposed IP>           | Sends sub-type 0x01 with
     |          |            | tag=0x05, len=6, data=<6-byte nonce>          | confirmed IP + nonce echo
3    | 0x09     | 0x21c0     | 8-byte header then ANonce bytes               | Sends sub-type 0x01 with
     |          |            |                                               | SNonce material
4    | 0x01     | 0x2180     | tag=0x03, len=6, data=<gateway IP>            | No reply — console signals
     |          |            | tag=0x81, len=6, data=<DNS1 IP>               | IP stack ready and exits
     |          |            | tag=0x83, len=6, data=<DNS2 IP>               | WPA sub-states
```

**Frame 1 notes:** The console replies with the bitwise NOT of the received 4-byte nonce — not an echo. The challenge token `0x23c2` with trailing byte `0x05` confirms the handshake is in progress.

**Frame 3 notes:** The ANonce is delivered at payload offset 8 (after an 8-byte header). The console must have completed the IP negotiation steps from frames 1 and 2 before it will accept a sub-type `0x09` frame.

**Frame 4 notes:** All three IP addresses must be valid unicast addresses or the console sets error flags instead of storing them. After processing frame 4 the console signals the Xbox IP stack that a WPA-negotiated address is ready.

### Sub-TLV Format

All sub-TLVs in Type 0x11 frames use the same encoding: `[tag: 1 byte][len: 1 byte][data: len bytes]`.

```
Tag  | Len | Used in       | Field
-----|-----|---------------|----------------------------------------------
0x01 | 4   | 0x21c0, 0x23c0| Proposed or confirmed IP address (big-endian)
0x03 | 4+  | 0x21c0, 0x23c0| Challenge token (0x23c0 = challenge, 0x23c2+0x05 = response)
0x03 | 6   | 0x2180        | Gateway IP address
0x05 | 6   | 0x21c0, 0x23c0| DHCP transaction nonce (4-byte nonce + 2-byte extension)
0x81 | 6   | 0x2180        | Primary DNS IP address
0x83 | 6   | 0x2180        | Secondary DNS IP address
```

---

## PPPoE client (EtherType 0x8863 / 0x8864) — what the dash calls "WPA assoc request"

**Found 2026-11-24 (Ghidra, `xonlinedash.xbe`).** The functions named `xpp_build_wpa_assoc_request` (@0013d1bb), `xpp_send_wpa_assoc_request` (@0013d370) and the `xpp_fsm_*` / `xpp_wpa_*` family are the **Xbox's own PPPoE client**, not a WPA protocol. The "Type 0x11 WPA_ASSOC / WPA_EXCHANGE" section above was a misreading; see its correction notice.

### How the frame decodes

The dash stores the 16-bit value `0x6388` low byte first, so the wire bytes are `88 63`, which is **EtherType 0x8863 (PPPoE Discovery)**. The `0x11` that follows is the PPPoE version/type byte (version 1, type 1). The next byte is the PPPoE code:

| Wire bytes | Meaning |
|---|---|
| `88 63` | EtherType 0x8863 (PPPoE Discovery) |
| `11` | PPPoE version 1, type 1 |
| `09` | Code 0x09 = PADI (first attempt, destination ff:ff:ff:ff:ff:ff) |
| `19` | Code 0x19 = PADR (retry/request, unicast to the server MAC) |
| tag `01 01` | Service-Name (the "SSID" field in the dash code is the PPPoE service name, up to 40 bytes) |
| tag `01 03` | Host-Uniq (session counter, 4 bytes) |

Not yet re-verified against a wire capture: the "frame type word" values `0x21c0 / 0x23c0 / 0x2180 / 0x123c` in the old Type 0x11 tables. They are most likely PPPoE/PPP header fields read at the wrong offset. Treat those tables as unconfirmed until a PPPoE capture exists.

### When the Xbox sends it

`xpp_fsm_start_connection` (@0013dfa0) is called from `XnInit` (@00130db0) and from `FUN_00130a10`. It starts the state machine only when:

- the saved network profile has flag bit 1 (`profile+0x40`) set, meaning PPPoE credentials are present (two 64-byte strings, user name and password, plus the 40-byte service name), and
- the Ethernet link is up (`PhyGetLinkState`).

States: `0x11` PADI, `0x12` PADR, `0x13` / `0x15` credential exchange, `0x14` retransmit. A retry limit in state `0x11` ends in fatal error `0xC0000000` (a PPPoE timeout; related dash strings are `PPPOE_TIMEOUT`, `PPPOE_AUTH_ERROR`, `ERR_NTS_PPPOE_ACTIVE`).

The user-facing trigger is the Xbox **Network Settings → PPPoE** page: user name, password and service name. Separately, in a different part of the menu tree, there are host name and MAC address fields, probably for MAC spoofing and not PPPoE parameters (not yet traced in the dash).

### What this means for an adapter

A real adapter does not interpret these frames. They are ordinary Ethernet frames from the console and must be **bridged to the network** (the PPPoE server / ISP answers there, and its replies go back to the console). WPA joins use CONNECT_REQ tag `0x12` (passphrase) or `0x10` (PMK), handled entirely by the adapter. The Windows tool and the router daemon currently do **not** forward EtherTypes 0x8863 or 0x8864: the capture filter only takes 0x886f and there is no bridge path. See `xppd_refactor_todo.md`, "PPPoE passthrough".

---

## HMAC-SHA1 Authentication

The HANDSHAKE_RESPONSE (Type 0x02) includes a 20-byte HMAC-SHA1 digest at payload offset 0. This proves the adapter is genuine — only firmware with the correct ROM key and master key string can produce a valid digest. The adapter only needs to sign; it never verifies incoming packets beyond the RFC 1071 header checksum.

**Algorithm**: HMAC-SHA1 (RFC 2104)

**HMAC key** (`g_XPP_HMAC_Key`, 16 bytes, ROM address `0x800bf520`):
```
Hidden
```

**HMAC input** (139 bytes total):
```
[16 bytes] Random nonce from the HANDSHAKE_REQUEST
 [6 bytes] Adapter's own Ethernet MAC address
[117 bytes] g_XPP_HMAC_MASTER_KEY (ROM address 0x800bc364):
           "hidden."
```

**Output**: 20-byte SHA1 digest written at payload offset 0 of Type 0x02.

### Authentication Flow

```
Xbox                                  Adapter
 |                                       |
 |── Type 0x01 [16-byte nonce] ─────────>|
 |                                       | HMAC-SHA1(key, nonce + adapterMAC + masterKey)
 |<── Type 0x02 [20-byte digest + ...] ──|
 |                                       |
 | verify digest — compare all 20 bytes  |
 | ✓ match → adapter is authentic        |
```

The dashboard verifies using `XcHMAC(key, 16, input, 139, 0, 0, digest_out)` then compares all 20 bytes. Only genuine MN-740 firmware with the correct ROM key and master key string can produce a matching digest.

**Dashboard validation order** (decompile-verified from `xpp_process_handshake_response`):
1. `packet_type == 0x02` AND `frame_len == 0x11A` (282 bytes) → else SILENT DISCARD
2. Copyright string at payload+20 (84 bytes) — **fires BEFORE HMAC** — mismatch discards without HMAC attempt
3. HMAC-SHA1 full 20-byte compare
4. Per-field guards: byte214 < 2, byte215 < 4, byte216 < 2, byte218 < 3, byte219 < 33, byte208 & 0xF8 == 0, byte217 < 201
5. `xpp_fetch_adapter_wpa_caps()` validates bytes 174 + 175
6. `xpp_select_best_security_mode()` reads bytes 252 + 253 to set enc_type and pre-selected UI mode

---

## Checksum Calculation (RFC 1071)

The checksum ensures that integrity of the data contained within the XPP payload

All NLB (EtherType 0x886f) packets carry an RFC 1071 checksum in XPP header bytes 10–11.

- Computed over `body_size × 4` bytes starting at the XPP header (offset 0 of the XPP header)
- The checksum field must be treated as `0x0000` during calculation
- If the checksum fails, the adapter silently drops the packet with no response
- Used in all types: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A

---


### BBN Device Discovery Protocol
**Sources**: firmware update capture (wire; capture not published), `NML_bin.c` + `BBN_Handle_Discovery_Task` assembler (firmware-verified)

Before TFTP begins, MSBNUpdate.exe uses a proprietary discovery protocol on UDP port 42424 to locate adapters and obtain their IP address. This is separate from XPP.

**Session participants (wire-verified):**
```
PC (MSBNUpdate.exe): 169.254.250.55, MAC 00:15:5d:01:0a:1b
Adapter (MN-740):    169.254.38.9,   MAC 00:0d:3a:1f:26:09
```

### Transport

The firmware opens **two separate UDP sockets** at boot

- RX socket: bound to port **42424** — receives queries
- TX socket: unbound ephemeral port sends responses to broadcast `255.255.255.255:42424`

Responses are broadcast (not unicast) so multiple PC listeners on the subnet can receive them simultaneously. The adapter's fixed response source port observed on the wire is **1204**.

### Discovery Query Packet (PC → broadcast:42424)

```
Offset | Size    | Value             | Description
-------|---------|-------------------|----------------------------------
0      | 4 bytes | 0x50 0x00 0x00 0x00| Type marker (required — firmware validates)
4      | 4 bytes | variable          | Flags/version
8      | 8 bytes | 0x00...           | Reserved
16     | 4 bytes | random            | Session nonce — echoed in response
```

The firmware checks that the incoming packet is **exactly 20 bytes** and that the first 4 bytes equal `50 00 00 00`. Any other format is rejected.

### Discovery Response Packet (Adapter → broadcast:42424, 126 bytes)

```
Offset | Size     | Field               | Description
-------|----------|---------------------|---------------------------------------------------
0x00   | 4 bytes  | Type marker         | 0x51 0x00 0x00 0x00
0x04   | 4 bytes  | Protocol version    | 0x00 0x00 0x00 0x01
0x08   | 4 bytes  | Factory default flag| 0x01000000=defaults active, 0x00000000=customised
0x0C   | 32 bytes | Long device name    | "MN-740 Bridge" null-padded
0x2C   | 32 bytes | Short model name    | "MN-740" null-padded
0x4C   | 4 bytes  | Device IP           | Big-endian IP address (0.0.0.0 if unassigned)
0x50   | 4 bytes  | Reserved            | 0x00000000
0x54   | 4 bytes  | Subnet mask         | e.g. 0xFFFF0000 for APIPA /16
0x58   | 4 bytes  | Reserved            | 0x00000000
0x5C   | 4 bytes  | Primary DNS         | May retain stale value from prior DHCP lease
0x60   | 6 bytes  | Adapter MAC         | Adapter's hardware MAC address
0x66   | 4 bytes  | Nonce echo          | Bytes 16–19 of the query, copied verbatim
0x6A   | 4 bytes  | Capability flags    | Hardcoded 0x40 0x07 0x00 0x04
0x6E   | 2 bytes  | FW major version    | Byte-swapped (wire: 01 00 = version 1)
0x70   | 2 bytes  | FW minor version    | Byte-swapped
0x72   | 2 bytes  | FW revision         | Byte-swapped
0x74   | 2 bytes  | FW build            | Byte-swapped
0x76   | 2 bytes  | HW major version    | Byte-swapped
0x78   | 2 bytes  | HW minor version    | Byte-swapped
0x7A   | 2 bytes  | HW feature flags    | Byte-swapped
0x7C   | 2 bytes  | HW region ID        | Byte-swapped
```

**Version byte-swap encoding**: each 16-bit version field is stored in native MIPS big-endian order but written to the response buffer via a byte-reversal sequence. The wire value is the byte-reversed form of the stored value. Wire `01 00` → stored `0x0001` = 1. Wire `15 00` → stored `0x0015` = 21.

**Firmware version cross-reference**: the BBN response reports firmware 1.3.0.5 and hardware 1.0. Cross-referencing against the HANDSHAKE_RESP build string `"1.0.2.26 Boot: 1.3.0.06"` suggests the BBN fields encode the **boot firmware** version (1.3.x.x) separately from the runtime firmware (1.0.2.26). The hardware region ID 21 (`0x15`) corresponds to the regulatory domain code.

**Wire-verified response hex (126 bytes):**
```
51 00 00 00 00 00 00 01 01 00 00 00
4d 4e 2d 37 34 30 20 42 72 69 64 67 65 00 ...  ← "MN-740 Bridge" (+0x0c)
4d 4e 2d 37 34 30 00 00 00 00 00 00 00 00 ...  ← "MN-740" (+0x2c)
a9 fe 26 09                                    ← CFG_Device_IP (+0x4c)
00 00 00 00                                    ← zero-filled gap (+0x50)
ff ff 00 00                                    ← G_NET_ActiveSubnetMask (+0x54)
00 00 00 00                                    ← zero-filled gap (+0x58)
00 00 00 01                                    ← G_NET_PrimaryDNS (+0x5c)
00 0d 3a 1f 26 09                              ← adapter MAC (+0x60)
59 3f 80 3e                                    ← nonce echo (+0x66)
40 07 00 04                                    ← capability flags (+0x6a)
01 00 03 00 00 00 05 00                        ← FW major/minor/revision/build (+0x6e)
01 00 00 00 02 00 15 00                        ← HW major/minor/flags/regionID (+0x76)
```

**Nonce echo mechanism** (firmware-verified at `8009ba60`):

Bytes `[16..19]` of the 20-byte query (the session nonce) are copied verbatim to response offset `+0x66` via a direct `memcpy`. The adapter echoes back whatever nonce it received in the most recent valid query.

#### Discovery Timing
```
PC broadcasts query          → adapter responds within ~77ms (first seen response)
PC repeats query periodically → multiple discovery rounds before TFTP begins
Query interval: ~300–1300ms  → adapter responds to each independently
```

MSBNUpdate runs several discovery rounds while waiting for the adapter to become reachable (e.g. while it finishes APIPA address assignment). The session nonce changes each round; the adapter echoes back whatever nonce it received.

---

### Wire-Verified Firmware Block 1 Content
**Source**: firmware update capture (not published) — Frame 34, DATA block 1

The first 512-byte firmware block transferred contains the following human-readable strings, which identify it as the **boot stage** firmware (stage 1 of MSBNUpdate's two-stage update):

```
String                              | Significance
------------------------------------|------------------------------------------
"GL2454AP-LT1-M80     -0000.00.00"  | Hardware board identifier (GL2454AP chipset)
"Sat, 06 Sep 2003    "              | Firmware build date
"MN-740 Bootrom"                    | Firmware stage: boot ROM
00:11:22:33:44:55                   | Placeholder/test MAC in firmware image
```

This confirms that MSBNUpdate stages the boot firmware first, consistent with the `SKU_MN-740_BOOT_FW` → `SKU_MN-740_RUNTIME_FW` ordering documented from string analysis.

---

### Wire-Verified DHCP Behaviour (Adapter, No Server Present)
**Source**: firmware update capture (not published)

When no DHCP server responds, the adapter falls back to APIPA (`169.254.x.x`) and continues sending DHCP DISCOVER broadcasts indefinitely with exponential backoff:

```
DHCP Option 12 (Hostname):            "MN-740"
DHCP Option 60 (Vendor class):        "MSFT 98"
DHCP Option 50 (Requested IP):        192.168.1.181 (retained from previous session)
DHCP Option 61 (Client ID hw type):   0x01 (Ethernet)
DHCP Option 55 (Param request list):  Subnet Mask, Router, DNS, Domain Name
DHCP Transaction ID pattern:          0x22334468, 0x22334469, ... (incrementing)
DHCP seconds elapsed:                 291 (first), increments per retry
Retry interval (observed):            ~2s, ~4s, ~8s (doubling)
```

The adapter retains the last-used DHCP IP in NVRAM and requests it on every subsequent DISCOVER.

### IPHlpSvr.exe

`IPHlpSvr.exe` (Microsoft Broadband Networking IPHlpAPI Server Application)
is a Windows 9x/Me helper shim. It provides IP Helper API calls via window
messages to processes that cannot call `GetAdaptersInfo()` directly on those
platforms. It communicates via `SendMessageTimeout` to a hidden window
(`"Could not find IPHlpSvr window."`). It has no involvement in TFTP or XPP
protocol traffic and is irrelevant on Windows XP and later.

---

## TFTP Firmware Upgrade
> **Note**: TFTP is a supporting feature, not a packet type in the XPP management protocol. This section describes the adapter's built-in firmware upgrade mechanism accessed independently of XPP.

**Transport**: UDP ports 69 and 16932 — two distinct TFTP listening ports (see below)
**State Requirement**: UDP sockets open at boot, but transfers are gated by a prior XPP handshake.

### Two TFTP Ports — Firmware Confirmed
The adapter listens for TFTP on **two separate UDP ports**, both registered at boot by
`xpp_check_firmware_update_status()` via the same `xpp_udp_packet_dispatcher` callback.
They serve different purposes and have different auth behaviours.

```
Port      | Hex    | Registered by               | Path name   | Auth handler
----------|--------|-----------------------------|-------------|-----------------------------
69        | 0x0045 | xpp_sync_radio_state()      | Unpaired    | g_XPP_Active_Frequency
16932     | 0x4224 | xpp_sync_connection_status()| Paired      | XPP_Secure_Config_Update
```

The dispatcher uses sentinel values to distinguish which port received the packet:
- `0xffffff9d` → port 69 → `TFTP_Process_New_Request(..., param_4=0)`
- `0xffffff9c` → port 16932 → `TFTP_Process_New_Request(..., param_4=1)`

**Session handle gate**: Both ports check `g_XPP_Session_Handle == -1` before
allowing any transfer. If the handle is not set (i.e. no XPP handshake has occurred),
the adapter responds with `"Transfers currently disabled"` on either port. The
`g_XPP_Session_Handle` is set to `0xffffffff` (-1) by `TFTP_Session_Enable()` during the XPP
handshake flow, and cleared to `0` by `TFTP_Session_Disable()`. **A prior XPP
handshake is therefore required before TFTP transfers are accepted on either port.**

**Data transfer port**: After auth passes, the session's port field is zeroed and
`hal_mailbox_query()` allocates a dynamic ephemeral port for the actual data transfer.
The adapter sends DATA blocks and ACKs from this ephemeral source port. The client
must direct subsequent DATA/ACK packets to this ephemeral port — standard TFTP
behaviour per RFC 1350.

### How TFTP Becomes Available
`net_main_task()` calls `XPP_check_firmware_update_status()` as a fixed step
during boot, before DHCP, before any Xbox connection exists:

    net_main_task()
      └─ XPP_check_firmware_update_status()
           ├─ xpp_sync_connection_status()   ← opens port 16932, registers paired auth callbacks
           └─ xpp_sync_radio_state()
                └─ UDP_Socket_Open(port 69, xpp_udp_packet_dispatcher)
                   UDP_Socket_Open(port 16932, xpp_udp_packet_dispatcher)

Both UDP sockets open at power-on. **Transfers are blocked until a valid XPP
handshake sets `g_XPP_Session_Handle = -1`.**

### TFTP Upgrade Sequence
1. Establish XPP session first — HANDSHAKE_REQ (Type 0x01) → HANDSHAKE_RESP (Type 0x02). This sets `g_XPP_Session_Handle = -1` enabling TFTP transfers.
2. Send TFTP WRQ to port **69** for firmware upload, or port **16932** for config/virtual files.
3. Send WRQ with filename `"image"` (or `"boot.bin"` for MSBNUpdate.exe) in `"octet"` mode.
4. Transfer firmware blocks (512 bytes each, RFC 1350).
5. Adapter buffers all blocks in `g_HTTP_UPLOAD_BUFFER` via `xpp_vfs_write_payload()`.
6. On final block (< 512 bytes), `xpp_flash_write_manager()` is called with the total byte count.
7. **Firmware image must be exactly `0x100000` (1 MB).** If the total received bytes do not equal `0x100000`, the flash write is silently skipped and no reboot occurs. Any other size is treated as a config partition write or ignored entirely.
8. Automatic reboot with new firmware.

**⚠ Third upload path — HTTP POST**: The adapter also has a built-in HTTP web server with a multipart form upload endpoint (`http_handle_post_upload`) that writes to the same `g_HTTP_UPLOAD_BUFFER`. This is a third firmware flash path alongside the two TFTP ports. It shares the same 1MB buffer and the same size/validation constraints.

### TFTP Protocol Details
- **Block Size**: 512 bytes (0x200) — firmware constant `TFTP_Block_size`
- **Transfer modes accepted**: `"image"`, `"octet"` (binary), `"netascii"` (text)
- **WRQ auth**: None — the firmware upload path performs no credential check on either port
- **RRQ auth**: None in practice — see Auth Logic section below
- **Concurrent sessions**: Only one TFTP session is permitted at a time (`g_TFTP_Session_Active_Flag` ref-count). A second request while a session is active is logged and rejected.
- **XPP session prerequisite**: `g_XPP_Session_Handle` must be `-1` (set by successful XPP handshake) or any request on either port gets `"Transfers currently disabled"`.
- **Data transfer port**: After auth passes, the adapter opens a new ephemeral UDP port for the actual DATA/ACK exchange. Ephemeral ports start at 1200 (0x4b0), allocated by `UDP_Allocate_Dynamic_Port()` seeded from uptime ticks. The client must send subsequent ACK packets to this ephemeral port, not to 69 or 16932.
- **Retransmit backoff**: Exponential — starts at 5 ticks, doubles on each retry, capped at 150 ticks. Minimum interval 10 ticks. Retry limit is set at session creation; exhaustion → ERROR `"Retry limit exceeded"`.
- **RTT-adaptive interval**: On each successful ACK, `xpp_calculate_link_latency()` adjusts the retry interval based on measured round-trip time. The interval converges toward `RTT + smoothed_RTT + 1`, clamped to [10, 150].
- **Filename length limit**: Filenames must be shorter than 80 characters (0x51). Longer names are silently ignored by `xpp_vfs_open()`.

**Port selection by use case:**
```
Use case                    | Port  | Notes
----------------------------|-------|------------------------------------------
Firmware flash (WRQ)        | 69    | Standard path, no auth, any client
Firmware flash (WRQ)        | 16932 | Also works — WRQ has no auth on either port
Read config files (RRQ)     | 16932 | Auth handler present but RRQ bypasses it (see below)
Read debug log (RRQ)        | 16932 | Auth handler present but RRQ bypasses it (see below)
Virtual file writes (WRQ)   | 16932 | No auth on WRQ, but payload has embedded tokens
```

---

### TFTP Wire Format — Port 16932 (RRQ and WRQ)

Both RRQ and WRQ packets sent to port 16932 use the same 67-byte UDP payload structure. The auth material is embedded inside the TFTP filename field as binary data. The firmware's auth handler reads auth bytes at fixed offsets into the UDP payload regardless of TFTP framing.

```
UDP payload offset | TFTP field           | Auth purpose
-------------------|----------------------|----------------------------------
0                  | opcode[0] = 0x00     | (not auth)
1                  | opcode[1] = 0x01/02  | (not auth — RRQ=1, WRQ=2)
2–7                | filename bytes 0–5   | auth.src_mac (6 bytes)
8–39               | filename bytes 6–37  | auth.padding (32 bytes, ignored by firmware)
40–59 (0x26–0x39)  | filename bytes 36–55 | auth.HMAC-SHA1 (20 bytes)
60                 | filename null term   | end of filename field
61–65              | mode string          | "octet"
66                 | mode null term       | end of mode field
```

Total packet length: **67 bytes**

**Wire-verified WRQ hex (firmware update capture frame 32, UDP payload):**
```
00 02                          ← TFTP opcode: WRQ
00 0d 3a 1f 26 09              ← auth.src_mac (adapter MAC in filename bytes 0–5)
d1 d0 de c1 2a 5d e5 5d f8 38
02 ed ba 6c 56 b8 cd 15 8e 23
25 52 16 08 2a b4 a2 04 fe 5f
6d 6b                          ← auth.padding (32 bytes, random in MSBNUpdate)
89 d3 e1 6d 31 54 09 6e 1c 89
f6 b5 94 af b6 f7 2a c2 49 80  ← auth.HMAC-SHA1 (firmware ignores for WRQ)
00                             ← filename null terminator
6f 63 74 65 74                 ← "octet"
00                             ← mode null terminator
```

**RRQ payload structure** (67 bytes, same layout):
```
00 01                          ← TFTP opcode: RRQ
<6 bytes src_mac>              ← auth.src_mac in filename bytes 0–5
<32 bytes padding>             ← ignored by firmware
<20 bytes HMAC-SHA1>           ← auth.HMAC at offset 0x26
00                             ← filename null terminator
6f 63 74 65 74                 ← "octet"
00                             ← mode null terminator
```

The actual VFS filename the client wants to read is **not present** in this packet. The firmware uses the auth bytes (which form the filename field on the wire) to perform auth, then maps the request to the VFS filename that was registered when the TFTP socket was opened. The client indicates which file it wants by choosing which port it targets: the files readable via port 16932 RRQ are fixed — `"dbgout.txt"`, `"ar5eepo.dat"`, `"ar5maco.dat"`, and `"image"`.

**Implementation note**: Because the filename field contains binary auth data, a TFTP opcode parser that tries to extract a printable filename string will read garbage. The firmware does not use the filename field for file selection on port 16932 — the registered VFS handler is invoked unconditionally once auth passes.

---

### Auth Logic — Port 16932

**Firmware function**: `XPP_Secure_Config_Update()` decompiled from `NML_bin.c`.

The firmware's auth callback receives `tftp_op_mode` as an inverted value relative to the TFTP opcode: WRQ (opcode 2) maps to `tftp_op_mode=1`, RRQ (opcode 1) maps to `tftp_op_mode=2`. This is an internal firmware encoding, not the wire opcode.

```c
void XPP_Secure_Config_Update(undefined4 param_1, char *param_2, uint tftp_op_mode)
{
    // param_2 = raw UDP payload pointer

    if ((tftp_op_mode & 0xffff) == 2) {
        // RRQ path — log and return immediately (NO auth checks performed)
        wlan_log_debug_info(4, s_tftp_update, s_tftpd_put);
    }
    else if ((tftp_op_mode & 0xffff) == 1) {
        // WRQ path — perform two auth checks:
        wlan_log_debug_info(4, s_tftp_update, s_tftpd_get);

        // CHECK 1: MAC match
        iVar1 = wlan_mac_addr_equal(param_2, &g_NET_Interface_MAC_Table, 6);
        if (iVar1 == 0) {
            // MAC matched — proceed to HMAC check

            // CHECK 2: HMAC verification
            strcpy(&DAT_800cdb6c, g_NVRAM_User_Settings.Legacy_Padding);
            sVar2 = strlen(g_NVRAM_User_Settings.Legacy_Padding);
            xpp_calculate_hmac_sha1((SHA_CTX *)&DAT_800cdb6c, sVar2, -0x7ff32014, 0x14);
            iVar1 = wlan_mac_addr_equal(param_2 + 0x26, &DAT_800cdfec, 0x14);
            if (iVar1 == 0) {
                wlan_log_debug_info(4, s_tftp_update, s_filename_ok);
            }
            else {
                wlan_log_debug_info(4, s_tftp_update, s_password_error1);
            }
        }
        else {
            wlan_log_debug_info(4, s_tftp_update, s_mac_error);
        }
    }
}
```

**Auth summary:**

```
Operation | tftp_op_mode | Auth performed
----------|--------------|------------------------------------------
RRQ       | 2            | NONE — returns immediately, no checks
WRQ       | 1            | MAC check then HMAC-SHA1 check (both must pass)
```

**WRQ auth checks (when auth is performed):**

```
Check     | What is compared                                        | Failure result
----------|--------------------------------------------------------|---------------------
MAC check | param_2[0x00..0x05] vs g_NET_Interface_MAC_Table:
          |   UNPAIRED adapter → adapter hardware MAC              | log "mac_error", refuse
          |   PAIRED adapter   → paired Xbox console MAC           |
HMAC check| param_2[0x26..0x39] vs HMAC-SHA1(key=g_XPP_HMAC_Key,
          |   input=g_NVRAM_User_Settings.Legacy_Padding (admin_id))| log "password_error1", refuse
```

`g_NET_Interface_MAC_Table` is dual-use: at boot it holds the **adapter hardware MAC** (populated by `eth_brecis_msp_init()`); after pairing it is overwritten with the **paired Xbox console MAC** by `CFG_Set_Paired_Xbox_MAC()`. The adapter hardware MAC is available in the BBN discovery response at offset `+0x60`.

**HMAC computation for WRQ auth (default config):**

```
Key:   Hidden  (g_XPP_HMAC_Key, 16-byte ROM constant)
Input: "admin"  (g_NVRAM_User_Settings.Legacy_Padding default)
Result: Hidden
```

**Both ports — WRQ has no access control from the firmware's perspective.** `XPP_Secure_Config_Update` performs MAC and HMAC checks but only on the WRQ path (`tftp_op_mode=1`). Port 69 WRQ has no auth handler registered at all. Any host that has established an XPP session can flash new firmware on either port.

**Note on dispatch paths**: The firmware also checks `if (param_4 == 0) OR (g_XPP_Link_State == NULL)` — if port 16932 is used but `g_XPP_Link_State` was never registered, it falls through to the port 69 auth path as a fallback.

---

### WRQ Initial ACK — Block 0 Sent Before DATA

From `TFTP_Process_New_Request()` decompile:

For a WRQ (write request), the adapter sends **ACK block 0 immediately** upon accepting the request — before receiving any DATA:

```c
// WRQ path (opcode == 2):
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 0;       // block number = 0
net_tftp_send_acknowledgment(p_tftp_session_desc, ...);     // send ACK 0
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 1;       // next expected = 1
*(undefined4 *)&p_tftp_session_desc->field_0x38 = 1;       // state = RECV
```

This is standard RFC 1350 WRQ behaviour — the server sends ACK 0 to signal readiness, client then sends DATA block 1. An emulator **must** send ACK block 0 in response to WRQ before the client will begin sending data. Failure to send ACK 0 causes the client to time out waiting.

**For RRQ (read request):**

The block number starts at 1 — the adapter opens the file and begins sending DATA block 1 immediately:

```c
// RRQ path (opcode == 1):
*(undefined4 *)&p_tftp_session_desc->field_0x38 = 6;       // state = SEND
*(undefined2 *)&p_tftp_session_desc->field_0x2c = 1;       // next block = 1
*(undefined4 *)&p_tftp_session_desc->field_0x28 = 0x200;   // block size = 512
```

No ACK 0 is sent for RRQ — the adapter sends DATA block 1 directly to the client's source port as soon as the request is accepted.

---

### Standard TFTP Packet Format

```
WRQ/RRQ:   [opcode:2][filename\0][mode\0]
DATA:      [opcode:2][block:2][data:≤512]
ACK:       [opcode:2][block:2]
ERROR:     [opcode:2][error_code:2][message\0]
```
Opcodes: 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR

### WRQ Filename
The standard firmware upgrade filename is `"image"`. MSBNUpdate.exe uses `"boot.bin"` as its WRQ filename. Both are accepted by the firmware — the completion callback (`xpp_tftp_commit_config`) does not validate the filename at all; it flashes whatever data was received into `g_HTTP_UPLOAD_BUFFER` regardless of what the file was named. Any filename triggers the same flash-and-reboot path.

### TFTP Credentials
The adapter has two separate credentials stored in NVRAM, both defaulting to `"admin"` at factory reset:

**HTTP username / XPP device identity**: `xpp_identity_username` (default `"admin"`).
Populated into `XPP_Identity_t.password` at boot. Used as the HTTP Basic Auth username.
No XPP TLV tag writes this field — it can only be changed via the HTTP web config page.

**HTTP password / TFTP WRQ auth input / CLI admin_id**: `g_NVRAM_User_Settings.Legacy_Padding` — the XPP admin identity password (max 16 chars + NUL = 17 bytes total).
This is the credential used by `XPP_Secure_Config_Update` as the HMAC input for TFTP WRQ authentication on port 16932. It is also used as the HTTP Basic Auth password and copied to `XPP_Identity_t.admin_id` at boot for CLI session auth.
Written by Tag 0x03 in Type 0x07 CONNECT_REQ. Also changeable via HTTP web UI.

Both default to `"admin"` at factory reset giving HTTP credentials of `admin:admin`.
Tag 0x03 changes only the password/HMAC side (`Legacy_Padding` / `admin_id`), not the username side (`xpp_identity_username`).
Factory reset restores both via `Flash_Commit_Settings()` → `strcpy(STR_DEFAULT_CREDENTIAL)`.

---

### TFTP — Emulator Implementation Checklist

The most likely causes of TFTP failure, ordered by probability:

```
Priority | Issue                                              | Fix
---------|----------------------------------------------------|----------------------------------------------
1 (HIGH) | Not sending ACK block 0 after WRQ accepted         | Send ACK opcode 4, block 0 immediately
         |                                                    | on WRQ receipt — before client sends DATA 1
2 (HIGH) | Sending ACK/DATA to wrong port after session starts| Re-address to adapter's EPHEMERAL TID port
         |                                                    | (learned from first DATA block's source port)
3 (HIGH) | XPP session handle not set before TFTP             | Must complete Type 0x01/0x02 handshake first
4 (HIGH) | ICMP port-unreachable from OS aborting transfer    | Bind a UDP socket to the client's src port
         |                                                    | (e.g. 32069) to absorb adapter DATA replies
         |                                                    | at OS level — prevents ICMP port-unreachable
         |                                                    | which the adapter treats as fatal
5 (MED)  | No IP route back to adapter (APIPA)                | Add a host IP in 169.254.0.0/16 on the NIC
         |                                                    | connected to the adapter before TFTP
6 (MED)  | Adapter cannot ARP for client's source IP          | Send a gratuitous ARP reply before and after
         |                                                    | the RRQ so the adapter's ARP table maps the
         |                                                    | client src IP → client MAC without an extra
         |                                                    | round-trip
7 (LOW)  | Final zero-length DATA packet not handled          | When file_size % 512 == 0, send a 4-byte
         |                                                    | zero-payload DATA as EOF. For port 16932
         |                                                    | client does NOT wait for ACK after this.
         |                                                    | For port 69 client waits but swallows timeout.
```

**Step-by-step WRQ flow:**

```
Client → Adapter  UDP dst=69     [WRQ opcode=2][auth_in_filename_field][mode\0]
Adapter → Client  UDP dst=client-src-port (ephemeral TID) [ACK opcode=4][block=0]
Client → Adapter  UDP dst=ephemeral-TID   [DATA opcode=3][block=1][512 bytes]
Adapter → Client  UDP dst=client-src-port [ACK opcode=4][block=1]
...
Client → Adapter  UDP dst=ephemeral-TID   [DATA opcode=3][block=N][<512 bytes final]
Adapter → Client  UDP dst=client-src-port [ACK opcode=4][block=N]
  (adapter: xpp_tftp_commit_config → xpp_flash_write_manager → reboot if size==0x100000)
```

**Step-by-step RRQ flow (port 16932):**

The client must use raw Ethernet/IP/UDP frames (Npcap or similar) rather than standard OS UDP sockets. The adapter's DATA replies come from an ephemeral source port back to the client's fixed source port. A standard OS UDP socket cannot reliably receive these because:
- Windows Firewall drops unsolicited inbound UDP from unpredictable source ports
- The source IP in the raw RRQ packet is typically a synthesised address not assigned to any NIC

The correct approach: send RRQ as a raw Ethernet frame, bind a dummy UDP socket to the client's src port to suppress ICMP port-unreachable, and receive DATA via a separate raw Npcap handle.

```
Client → Adapter  raw Ethernet/IP/UDP dst=16932  [RRQ 67-byte payload]
  (send gratuitous ARP reply: client-src-ip is-at client-mac — before and after RRQ)
Adapter → Client  UDP from ephemeral-TID → client-src-port [DATA opcode=3][block=1][512 bytes]
Client → Adapter  raw Ethernet/IP/UDP dst=ephemeral-TID [ACK opcode=4][block=1]
...
Adapter → Client  UDP from ephemeral-TID → client-src-port [DATA opcode=3][block=N][<512 final]
Client → Adapter  raw Ethernet/IP/UDP dst=ephemeral-TID [ACK opcode=4][block=N]
```

**Wire-verified RRQ session (firmware update capture adapted for RRQ context):**

```
Frame N:   Client → Adapter:16932  RRQ (67 bytes)
Frame N+1: Adapter:1205 → Client:32069  DATA block 1 (516 bytes)  ← RTT ~10ms
Frame N+2: Client → Adapter:1205   ACK block 1 (4 bytes: 00 04 00 01)
...
```

The adapter allocates ephemeral port starting from ~1200 (0x4b0). All subsequent DATA and ACK exchanges use `adapter:TID ↔ client:src_port`. The client must learn the TID from the first DATA block's source port and address all subsequent ACKs to it.

---

### Network Requirements for TFTP (APIPA Adapters)

When the MN-740 is connected directly to a PC with no router or switch, it
self-assigns an APIPA address (`169.254.x.x/16`) because no DHCP server is
present. The client must have an address on the same `/16` subnet; without one
the UDP reply from the adapter has no route back.

The adapter IP is learned from `HANDSHAKE_RESP` offset 210 (the `ip_address`
field). If that field is zero the adapter hasn't obtained an address yet; wait
for APIPA self-assignment (~15–30 s after power-on) and re-run the handshake.

**To add a temporary host address on Windows (run as Administrator):**
```
netsh interface ip add address "Ethernet" 169.254.1.1 255.255.0.0
```
Replace `"Ethernet"` with the actual NIC name from `ipconfig /all`.
Remove after TFTP completes:
```
netsh interface ip delete address "Ethernet" 169.254.1.1
```

`route add` does NOT work for 169.254.x.x. The Windows IP stack enforces
that APIPA destinations are only reachable via an interface that already has an
address in the `169.254.0.0/16` range.

**Synthesised source IP for raw RRQ frames**: When the client has no 169.254 address yet, the raw RRQ frame must carry a plausible src IP that the adapter can ARP for and route a reply to. A simple approach: XOR the last octet of the adapter's IP with 1 to produce a collision-free adjacent address in the same /24 (e.g. adapter at 169.254.250.49 → client uses 169.254.250.48). Send a gratuitous ARP reply associating this synthesised IP with the client's real MAC before sending the RRQ.

---

### Virtual File System — Complete File Catalogue
The firmware implements a virtual filesystem rooted in `g_HTTP_UPLOAD_BUFFER` (1 MB RAM).
All filenames are matched by `strcmp()` — there is no real filesystem on the adapter.

**RRQ — Files readable from the adapter** (all require a valid XPP session; auth bypassed for RRQ as described above):

⚠️ **RRQ is non-functional on all known stock firmware versions (including v1.0.2.26).** The ACK handler `xpp_tftp_process_ack` contains a firmware bug: the received block number is read from `*(p_session + 0x0C)` which is the VFS filename pointer field, not the packet buffer. The comparison always fails, so DATA block 1 is retransmitted until the retry limit kills the session. All four readable files are affected. WRQ firmware flash is unaffected (uses a different, correct code path).

**Two-instruction patch** to fix RRQ (NML_bin.c firmware-verified):
- In `xpp_tftp_process_ack`: change the MIPS load offset from `0x0C` to `0x18` to read from the packet buffer pointer instead of the filename string pointer.
- At the ACK dispatch in `xpp_signal_data_ready` (`0x80003200`): pass the packet buffer pointer as `a2` before the `jal` (`or a2, t8, zero`).

```
Filename       | Size   | Contents / Source
---------------|--------|-----------------------------------------------------------
"dbgout.txt"   | 32768  | Debug log ring buffer from RAM (0x807f8000). Contains
               |        | recent firmware serial console output.
"ar5maco.dat"  | ~32    | AR5212 hardware MAC address as formatted ASCII string:
               |        | "0x XXXX XX:XX:XX:XX:XX:XX" — reads from ath_hal_get_hw_info()
"ar5eepo.dat"  | 2048   | AR5212 EEPROM dump (0x800 bytes). Reads via
               |        | xpp_flash_read_wrapper(0, 0, 0x400). If read fails,
               |        | buffer is 0xFF-filled.
"image"        | 1 MB   | Full firmware image read from flash.
```

**WRQ — Files writable to the adapter** (no auth required for any WRQ):

All WRQ uploads buffer into `g_HTTP_UPLOAD_BUFFER` (1 MB max). Validation and effect
are applied in the completion callback after the full transfer completes. Each virtual
file write has an embedded credential in the file payload itself that the firmware
checks before acting — these are separate from the TFTP auth header HMAC.

```
Filename          | Payload size | Effect on success
------------------|--------------|----------------------------------------------------
"image"           | any          | Flash firmware: xpp_flash_write_manager() → reboot
"boot.bin"        | any          | Same as "image" — both accepted (MSBNUpdate specific)
"resdef.dat"      | 39 bytes     | Flash_Commit_Settings() + CFG_Save_To_Flash() +
                  |              | NET_Reload_Config() — restores factory config
"mac.dat"         | any          | xpp_finalize_console_pairing() → reboot.
                  |              | Writes Xbox pairing MAC. On unpaired adapter, MAC
                  |              | check trivially passes (adapter MAC matches itself).
"ar5maci.dat"     | any          | AR5212 MAC address import via config_helper().
                  |              | Payload embeds a 4-byte auth token checked against
                  |              | MAC_DAT_DESCRIPTOR_BLOCK.magic_header[0..3].
"ar5eepi.dat"     | any          | EEPROM refresh via nvram_flash_read_to_buffer().
                  |              | Payload embeds 4-byte auth token vs magic_header[4..7].
"tx_rate.dat"     | any          | Sets G_PENDING_TX_Rate_Code and reboots.
                  |              | 7-byte auth token embedded in payload.
"ee_ar531x.dat"   | 4096 bytes   | Writes full AR5212 EEPROM block via
                  |              | sys_flash_write_block(). Requires payload size ==
                  |              | 0x1004 and XOR checksum validation. 4-byte auth token.
```

⚠ The virtual file write tokens (embedded credentials) are derived from `MAC_DAT_DESCRIPTOR_BLOCK.metadata[]` and related ROM constants. Their exact values are hardware-specific and not documented here — they are not related to the TFTP auth header HMAC. These files are PC wizard / factory tool targets and are never requested by `xonlinedash.xbe`.

### AMACAEPM Magic Header
**Purpose**: Integrity check for paired Xbox configuration — firmware-verified
**Expansion** ("Adapter MAC Address & Endpoint Manager"): NOT firmware-verified, inferred label only

### Pairing Process (firmware-verified behaviour)
**Factory Reset**: `g_XPP_Paired_Flag = 0` (unpaired)

**Pairing**: `CFG_Set_Paired_Xbox_MAC()` copies the Xbox MAC and sets `g_XPP_Paired_Flag = 1`,
then calls `Flash_Commit_Settings()` + `CFG_Save_To_Flash()`

**Subsequent Connections**: adapter checks source MAC against stored paired MAC via
`NET_Register_Peer_MAC()` — only responds to the paired Xbox MAC

### Security Model
**Pairing Lock**: Once paired, adapter only responds to that Xbox MAC (firmware-verified)
**Reset**: Factory reset clears paired state (firmware-verified)

---

## MSBNUpdate.exe Firmware Update Tool

**Source**: String analysis of `MSBNUpdate.exe` (Microsoft Broadband Networking
Update Utility, build path `d:\Net2\src\DINGO\exe\MSBNUpdate\Release`).
This is the official Microsoft PC-side tool used to upgrade MN-740 firmware.

**Driver**: Uses `ISW32N50.dll` — a PCANDIS/ISLNDIS raw-packet wrapper that
provides `W32N_PacketSend` and related calls over EtherType 0x886F. Functionally
identical to what our Npcap layer does. Does **not** use UDP port 2002.

### Two-Stage Firmware Update Flow

The update sends **boot firmware first, then runtime firmware**, verifying each
stage before proceeding. The two internal SKU identifiers confirm the ordering:

```
Stage | SKU identifier        | Description
------|-----------------------|------------------------------------------
1     | SKU_MN-740_BOOT_FW    | Boot firmware image (sent first)
2     | SKU_MN-740_RUNTIME_FW | Runtime firmware image (sent second)
```

**Full update sequence (string-verified):**
```
1.  Discover MN-740 via XPP (EtherType 0x886F — same as our tool)
2.  Query firmware versions:
      "Bridge firmware runtime version:"
      "Bridge firmware get runtime version:"
      "Bridge firmware boot version:"
      "Bridge firmware get boot version string:"
3.  Check minimum version floor — "Firmware is too old to update"
4.  Validate admin password — "MN740 Connect, bad password"
    (sent via XPP CONNECT_REQ Tag 0x03 before TFTP begins)
5.  Log: "Updating firmware for MN740 MAC: '%S' IP: '%S'"
    (confirms TFTP target is adapter's actual IP, not broadcast)
6.  TFTP WRQ → "boot.bin" in "octet" mode to adapter IP:69
7.  Transfer boot firmware blocks (512 bytes each, RFC 1350)
8.  "sent last zero data packet, host timed out, but OK"
    (zero-length final DATA packet; ACK timeout expected and harmless)
9.  Wait for bridge reboot: "Waiting for Bridge reboot, mac: '%S' try: %d * 15 seconds"
10. Verify boot stage: "Verifying boot fw update...."
      "Current boot firmware did not match update file" (error)
      "Looking for bridge fw version to verify boot, cnt: %d"
11. TFTP WRQ → "boot.bin" in "octet" mode — runtime firmware
12. Transfer runtime firmware blocks
13. Wait for reboot again (same 15-second poll)
14. Verify runtime stage: "Verifying runtime fw update...."
      "Current runtime firmware did not match update file" (error)
      "Updating bridge firmware was a success"
```

### Key String Findings (MSBNUpdate.exe)

```
String                                          | Significance
------------------------------------------------|--------------------------------------
"Updating firmware for MN740 MAC: '%S' IP: '%S'"| TFTP goes to adapter's actual IP
"boot.bin"                                      | WRQ filename (not "image")
"octet"                                         | TFTP mode string (binary)
"sent last zero data packet, host timed out, but OK" | Final zero-length packet expected
"MN740 Connect, bad password"                   | Password validated before TFTP
"SKU_MN-740_BOOT_FW"                            | Boot firmware SKU identifier
"SKU_MN-740_RUNTIME_FW"                         | Runtime firmware SKU identifier
"Waiting for Bridge reboot, mac: '%S' try: %d * 15 seconds" | 15-second reboot poll
"Bridge did not reboot"                         | Reboot detection failure
" Runtime firmware version: %d.%d.%d.%d"       | Version string format (note leading space)
" Boot firmware version: %d.%d.%d.%d"          | Boot version string format
"TFTP, negotiating ports with MN740..."         | Separate MN-740 TFTP function
"TFTP send MN740 file"                          | Distinct from gateway TFTP
"No MN740 Bridge attached"                      | Discovery failure message
```

**WRQ filename is `"boot.bin"`, not `"image"`.** The firmware dump RRQ uses
`"image"` (firmware source: `XPP_flash_read_wrapper`). The official update WRQ
uses `"boot.bin"`. These are two different TFTP code paths.

### BOOT_ME Signal — Gateway Only

The `BOOT_ME` signal (`"Wait for BOOT_ME, recvd: %d"` / `"Received BOOT_ME"`)
appears only in the **gateway update path** (MN-700 base station, BCM94710AP
chipset). The MN-740 wireless bridge update does **not** use `BOOT_ME`. The
bridge reboot is detected by polling XPP handshake responses, not a broadcast
beacon signal.

### Final Zero-Length DATA Packet

`"sent last zero data packet, host timed out, but OK"` confirms that MSBNUpdate.exe deliberately sends a zero-length DATA packet as the final transfer step when the firmware image size is an exact multiple of 512 bytes.

**Behaviour differs by TFTP path (decompile-verified):**

- **Generic/CE path (`TFTP_SendFileGeneric`, port 69)**: sends the 4-byte zero-payload DATA packet, then calls `TFTP_WaitForACK`. If the adapter does not ACK (it may have already rebooted), the timeout exception is caught by `TFTP_FinalPacketTimeoutHandler` and swallowed.
- **MN-740 path (`TFTP_SendFileMN740`, port 16932)**: sends the 4-byte zero-payload DATA packet and **does not call `TFTP_WaitForACK` afterward**. The client simply does not wait. An emulator receiving firmware over port 16932 should not expect the client to wait for ACK on the final zero-payload block.

When the final block is a non-zero partial block (< 512 bytes), both paths call `TFTP_WaitForACK` normally.

### MSBNUpdate HMAC Keys — Two Independent Keys, Two Roles

**Source**: `MSBNUpdate.exe` decompile (`TFTP_BuildAuthHeader`, `TFTP_ComputeHMACSHA1`) + wire capture cross-verification.

MSBNUpdate.exe and the adapter firmware each use a **separate, independent HMAC-SHA1 key**. They are not derived from each other:

```
Party          | Key                                       | Size    | Used for
---------------|-------------------------------------------|---------|-----------------------------
MSBNUpdate.exe | Hidden                                    | 64 bytes| Computing HMAC in WRQ
               |                                           |         | filename field (firmware ignores)
               |                                           |         |
               |                                           |         |
Adapter FW     | Hidden                                    | 16 bytes| WRQ auth HMAC verification
               |                                           |         | (checked by XPP_Secure_Config_Update)
```

Both sides use `admin_id` (default `"admin"`) as the HMAC data input, but produce different digests because the keys differ:

```
HMAC-SHA1(key=MSBNUpdate_64byte_key, data="admin") = Hidden
    → value in WRQ auth.HMAC field (firmware update capture frame 32 ✅)

HMAC-SHA1(key=fw_rom_key_16byte,     data="admin") = Hidden
    → value firmware verifies in WRQ auth.HMAC field
```

The MSBNUpdate 64-byte key (`g_TFTP_HMACKeyBlock`) lives in the `.data` section of `MSBNUpdate.exe` at VA `0x004d8418` and is referenced only by `TFTP_BuildAuthHeader`. It has no relationship to any firmware constant.

Since RRQ bypasses all auth checks, no HMAC is required in an RRQ packet. Any value (including zeros) at the HMAC offset is silently ignored.

---

### Password Validation Flow

`"MN740 Connect, bad password"` appears in the TFTP code area, not the XPP
discovery code. The password is validated before the TFTP session opens.
Internally this is done via the XPP channel (CONNECT_REQ Tag 0x03) — the
same `g_NVRAM_User_Settings.Legacy_Padding` (`admin_id`) credential described in the TFTP credentials section above.
If the password is wrong the TFTP session is never attempted.


----

## HTTP Web Interface (MN-740 only)

**Source**: Ghidra decompile of `http_server_task_main_loop`, `http_server_listener`,
`http_request_dispatch`, `http_authenticate_request`, `http_handle_post_upload`
(firmware v1.0.2.26)

The MN-740 contains a complete HTTP/1.x web server implementation. The server is
**fully functional but deliberately not started** in production firmware — the task
launch function `cfg_http_firmware_upload_setup` (0x80016598) has no callers in
the boot sequence.

### Transport

```
Protocol  | TCP
Port      | 16868  (0x41E4) -- NOT port 80
Interface | Adapter IP address (e.g. 192.168.2.252:16868)
Auth      | HTTP Basic Authentication (username:password base64 encoded)
```

The server does not start until `g_XBOX_WIFI_IFACE+0x24` (adapter IP address) is
non-zero. It waits in a 10ms sleep loop until an IP is assigned via DHCP or static
config before opening the TCP listener.

### Credentials

```
Field     | Default | Source
----------|---------|----------------------------------------------------------
Username  | admin   | G_XPP_Identity_Password (NVRAM, cannot be changed via XPP)
Password  | admin   | g_NVRAM_User_Settings.Legacy_Padding (same as XPP Tag 0x03)
```

Username can only be changed via the HTTP web UI itself.
Password is shared with XPP Tag 0x03 and TFTP WRQ auth — changing one changes all three.
Factory reset restores both to `"admin"`.

The `Server:` response header leaks the firmware version string on every response,
even before authentication.

### Route Table (decompile-verified)

```
Method | Path                 | Handler                              | Auth Required
-------|----------------------|--------------------------------------|---------------
GET    | /index.htm           | static file (main config page)       | Yes
GET    | /wireless.htm        | static file (wireless settings)      | Yes
GET    | /advanced.htm        | static file (advanced settings)      | Yes
GET    | /xml/wlaninfo.xml    | live WLAN status as XML              | Yes
GET    | /xml/netinfo.xml     | network status as XML                | Yes
GET    | /xml/sysinfo.xml     | system info as XML                   | Yes
POST   | /cgi/apply.cgi       | HTTP_CGI_Save_And_Redirect           | Yes
POST   | /cgi/config.cgi      | http_apply_config_save_and_redirect  | Yes
POST   | /cgi/upload.cgi      | http_handle_post_upload (firmware)   | Yes
```

**Note on /cgi/apply.cgi**: Calls `Flash_Commit_Settings()` before applying new
values. Any fields not present in the form POST body revert to factory defaults.
This is the "Apply" button on the main config page.

### Firmware Upload via HTTP

`http_handle_post_upload` writes to `g_HTTP_UPLOAD_BUFFER` at `0x8024E4D0` —
the same 1MB buffer used by TFTP firmware uploads. Both upload paths call the same
`xpp_tftp_commit_config` completion handler which checks for exactly 0x100000 (1MB)
bytes before flashing.

**Multipart POST format** (for `/cgi/upload.cgi`):
```
POST /cgi/upload.cgi HTTP/1.1
Host: 192.168.2.252:16868
Authorization: Basic YWRtaW46YWRtaW4=
Content-Type: multipart/form-data; boundary=----FormBoundary
Content-Length: <size>

------FormBoundary
Content-Disposition: form-data; name="firmware"; filename="image.bin"
Content-Type: application/octet-stream

<1MB firmware image binary>
------FormBoundary--
```

This is the easiest firmware update path for WPA patching — no MSBNUpdate.exe
or raw TFTP tooling required.

### Re-enabling the HTTP Server (firmware patch)

The HTTP server is disabled by a single missing function call in the boot sequence.

**Method 1 — Minimal patch (4 MIPS instructions):**

In `NET_Subsystem_Init_Core` at `0x8009c1dc`, insert a call to
`cfg_http_firmware_upload_setup` (0x80016598) before the `OS_Timer` calls.
There is a `stub_nop_4()` call at approximately `0x8009c220` that can be replaced:

```
; Replace stub_nop_4 call at ~0x8009c220 with:
LUI   T9, 0x8001        ; 3C 19 80 01
ADDIU T9, T9, 0x6598    ; 27 39 65 98
JALR  T9                ; 03 20 F8 09
NOP                     ; 00 00 00 00
```

**Method 2 — Call cfg_http_firmware_upload_setup directly:**

`cfg_http_firmware_upload_setup` (0x80016598) configures the task with:
- Stack base: `DAT_800fceac`
- Stack size: 0x2000 (8192 bytes)
- Priority: 0x18
- Entry: `http_server_task_main_loop` (0x80016518)

**Precondition:** The adapter must have an IP address before HTTP accepts connections.
The server will loop on `os_msleep(10)` until `g_XBOX_WIFI_IFACE+0x24` is non-zero.
For a factory-fresh adapter this means waiting for DHCP on the wired side, or
setting a static IP via XPP first.


---

## Factory Test Backdoor (MN-740 only)

**Source**: Ghidra decompile of `AUTH_GATE_XPP_Force_Xbox_Mode` (0x8009d37c),
memory read of ROM at 0x800bc7a9, confirmed in firmware v1.0.2.26.

`AUTH_GATE_XPP_Force_Xbox_Mode` is called during boot initialisation. It contains
a hardcoded MAC address comparison that auto-connects to a fixed test SSID if the
adapter's hardware MAC matches a factory test value.

### Backdoor Logic (decompile-verified)

```
ROM address 0x800bc7a9: 11 22 33 44 55 00   (factory test MAC)
ROM address 0x800bc7b0: "GsTrD"              (factory test SSID)
ROM address 0x800bc790: "Wireless PC connected" (log string)

if wlan_mac_addr_equal(adapter_hw_mac, 0x800bc7a9, 6):
    g_NVRAM_Conn_State = 0x02          (infrastructure connect mode)
    strcpy(g_Current_SSID_Buffer, "GsTrD")  (hardcoded test SSID)
```

### Interpretation

Production MN-740 units are manufactured with unique hardware MACs burned into
the AR5212 EEPROM. The test MAC `11:22:33:44:55:00` is a placeholder used on
pre-production/engineering units during factory validation. On these units the
adapter automatically associates to an SSID named `"GsTrD"` without any user
interaction or XPP configuration.

The condition never triggers on retail hardware. It confirms that a dedicated
test AP named `GsTrD` existed on the Microsoft manufacturing line for automated
validation of wireless connectivity on each unit.

### Version Sentinel

The same function validates a 4-byte sentinel at `0x807fff98` (written by the
bootloader) before applying a pending TX rate code:

```
Sentinel value: 00 05 02 02  (correlates to firmware build fields)
If match:  g_CFG_TX_Rate_Index = G_PENDING_TX_Rate_Code (if valid)
After:     sentinel bytes cleared, G_PENDING_TX_Rate_Code cleared
```

This allows the bootloader to pass a TX rate override to the runtime without
requiring NVRAM access during the two-stage boot sequence.



---

## Signal Strength Scaling
the firmware scales the signal strength depending on what packet or payload the data is to be processed as below are the three different places the signal is scaled:

### BEACON_RESPONSE (Type 0x0A) — Smoothed RSSI

Byte 1 of the BEACON_RESPONSE payload is a firmware quality index produced by two independent smoothing layers:

**Adapter firmware layer** (`drvr_get_smoothed_rssi`, NML_bin.c firmware-verified): 10-sample growing-window average. Buffer accumulates samples 1 → 10, then rolls. Each sample = `raw_rssi_byte − 0x5F` (subtract 95). Firmware discards samples where the adjusted value is > 0 dBm or < −127 dBm (hardware noise floor guard). When `XPP_Check_Auth_Status() != 0` (not paired+connected), the buffer is reset and `g_RSSI_Smoothed_Output` is set to `0xBA`.

**Dashboard layer** (`xpp_beacon_rssi_preprocess`, xonlinedash.xbe decompile-verified): A separate 5-sample circular buffer of received smoothed_rssi values. The −91 dBm guard operates here — if the received byte represents rssi ≤ −91 dBm, the entire beacon response is discarded before the buffer is updated.

### NETWORKS_LIST_RESPONSE (Type 0x04) — Per-Slot Signal

Byte 44 of each network slot is a 0–255 scaled quality value.

### Dashboard Signal Bar Thresholds

The Xbox dashboard converts the smoothed RSSI byte from BEACON_RESPONSE into 0–5 signal bars:

```
| Bars | RSSI threshold | Raw value hex | Visual          |
|------|----------------|---------------|-----------------|
| 0    | rssi ≤ -0x5b   | ≤ -91         | ░░░░░ no signal |
| 1    | rssi ≤ -0x52   | ≤ -82         | █░░░░           |
| 2    | rssi ≤ -0x48   | ≤ -72         | ██░░░           |
| 3    | rssi ≤ -0x44   | ≤ -68         | ███░░           |
| 4    | rssi ≤ -0x3a   | ≤ -58         | ████░           |
| 5    | rssi > -0x3a   | > -58         | █████ excellent |
```

---

## Error code flags

XPP Wire Result Bytes (payload byte at offset 0x00 in Type 0x06 and 0x08 responses)

```
Wire Byte | Meaning                     | Dashboard sets error_code to
----------|-----------------------------|------------------------------
0x00      | Success — TLV data follows  | 0x00000000 (cleared)
0x01      | Error / rejected            | 0x80000003 (hard error)
0x02      | Retry requested             | 0x80000002 (retry), retries after ~8 seconds
0x03      | Error / rejected            | 0x80000003 (hard error)
0x04      | Error (connect only)        | 0x80000003 (hard error, Type 0x08 only)
```

## MAC.DAT Pairing File Format

**Firmware-verified** (`NML_bin.h`, `NML_bin.c`):

```c
struct XPP_VirtualFileDescriptor {
    char filename[8];      // e.g. "mac.dat"
    char magic_header[8];  // "AMACAEPM"
    byte metadata[16];     // Pairing/flags data — internal layout below
};
```

`MAC_DAT_DESCRIPTOR_BLOCK` is a real global (confirmed at `NML_bin.c` line 43).
The `metadata[16]` blob is accessed at offsets `[0]–[3]`, `[4]–[9]`, and `[0xc]–[0xf]`
by `XPP_finalize_console_pairing()` and the TFTP RRQ handler — but as raw bytes with
no named fields in the decompiled source.


**What is confirmed**:
- `AMACAEPM` magic string is real
- `metadata[0–3]` and `metadata[4–9]` and `metadata[0xc–0xf]` are used in pairing/auth logic
- `g_XPP_Paired_Flag` is set by `CFG_Set_Paired_Xbox_MAC()` (0=unpaired, 1=paired)
- Factory reset clears paired state

---

## Connection Workflows

### Infrastructure Mode

1. Xbox → Adapter:  HANDSHAKE_REQUEST (Type 0x01)
   - 16-byte random challenge

2. Adapter → Xbox:  HANDSHAKE_RESPONSE (Type 0x02)
   - 256 bytes with HMAC signature
   - Current SSID, BSSID, signal, channel, IP
   ✅ Authentication complete
   ✅ Xbox dashboard shows adapter info

3. Xbox → Adapter:  BEACON_REQUEST (Type 0x09)
4. Adapter → Xbox:  BEACON_RESPONSE (Type 0x0a)
   - Security status (02 80 03 00 = WPA2)
   [Repeat 3-4 at least 3 times]
   ✅ Link established

   **Note on beacon value**: `02 80 XX 00` = auth=0x02 (open/idle or open-connected), rssi=0x80 (pre-seed RSSI, wire default before association), rate=TX rate code. Value `0x03` in byte 0 indicates WEP association in progress. See Type 0x0A payload structure for full decode.

   [ONLY if user opens network list in dashboard]
5. Xbox → Adapter:  NETWORKS_LIST_REQUEST (Type 0x03)
6. Adapter → Xbox:  NETWORKS_LIST_RESPONSE (Type 0x04)
   - Array of 61-byte network slots
   ✅ User sees available networks

   [If user selects a network and enters password]
7. Xbox → Adapter:  CONNECT_TO_SSID_REQUEST (Type 0x07)
   - TLV: SSID + password + security type
8. Adapter → Xbox:  CONNECT_TO_SSID_RESPONSE (Type 0x08)
   - Result code (0x00 = success)
   ✅ Connection initiated

   [CONTINUOUS - Every 1 second while connected]
9. Xbox → Adapter:  BEACON_REQUEST (Type 0x09)
10. Adapter → Xbox: BEACON_RESPONSE (Type 0x0a)
    ✅ Keepalive maintained

   [PERIODIC - Every 5-10 seconds for status updates]
11. Xbox → Adapter:  ADAPTER_INFO_REQUEST (Type 0x05)
12. Adapter → Xbox: ADAPTER_INFO_RESPONSE (Type 0x06)
    - 4-byte status update
    ✅ Dashboard refreshes signal bars

----

### Ad-Hoc Mode

1-4. [Same handshake and beacon sequence as infrastructure]

5. Xbox → Adapter:  CONNECT_TO_SSID_REQUEST (Type 0x07)
   - Tag 0x07: SSID
   - Tag 0x04: 0x00 (ad hoc; 0x01 would be infrastructure)
   - Tag 0x05: channel number (e.g. 0x06 for channel 6; for 802.11a a 5 GHz channel such as 0x24 = 36)
   - Tag 0x11: band when it changed (0 = b, 1 = a, 2 = g)
   - Tag 0x09: encryption type (0x01 open, 0x02 WEP-64, 0x04 WEP-128), not a link state
   - Tag 0x0A-0x0D / 0x0F and 0x0E: WEP keys and the key index 1 (if encrypted)
   (Corrected 2026-11-24 from the dash decompile and the ad hoc open and ad hoc WEP-64 captures; see "Ad-hoc CONNECT_REQ" in the dash summary.)

6. Adapter → Xbox:  CONNECT_TO_SSID_RESPONSE (Type 0x08)
   - Result code 0x00
   ✅ Ad-hoc network created

7. [Adapter begins beaconing on specified channel]
8. [Other Xbox consoles can discover and join]
9. [Continue beacon keepalive as in infrastructure mode]

**Key Difference**: Ad-hoc **requires** Tag 0x02 (channel), infrastructure auto-selects.

---

### Wire-Verified: Open Network with WAN Connection (Channel 3)
**Source**: two real adapter captures of an open network connect on channel 3

These captures show the adapter connecting to an open (unencrypted) 802.11g network on channel 3
(SSID "open", BSSID c4:4b:d1:00:47:4e, DrayTek Vigor 2762 router) with a real WAN internet connection active.

**Key observations from the log:**

1. BEACON_RESP (Type 0x0a) payload consistently: `02 80 6c 00`
   - auth=0x02 (idle), rssi=0x80 (pre-seed), rate=0x6c (54 Mbps infrastructure) ✅

2. ADAPTER_INFO_RESP (Type 0x06) shows:
   - Tag 0x01 (IP): 192.168.1.150 — real DHCP address from router
   - Tag 0x05 (channel): 0x03 — wire-confirms channel 3 reported correctly ✅
   - Tag 0x06 (BSSID): c4:4b:d1:00:47:4e — DrayTek Vigor 2762 router MAC
   - Tag 0x07 (SSID): "open" (4 bytes)
   - Tag 0x08: 0x02 (open — no WEP active, wire-verified ✅)
   - Tag 0x09: 0x01 (open cipher — no encryption active, wire-verified ✅)
   - Tag 0x02: 0x00 (DHCP state machine not yet at 0x52)

3. The Xbox queries Type 0x05 / 0x06 every ~3-5 beacons while connected.

4. The Xbox sends ADAPTER_INFO_REQ without first sending a NETWORKS_LIST_REQ or CONNECT_REQ
   in this capture — the adapter was already configured from a previous session stored in NVRAM.

**note**   "The 16 bytes beyond the 4-byte payload are uninitialised firmware memory and captures
   have shown arbitrary values during transient states — these are not part of the protocol.

**Confirmed working configuration (for emulator implementors)**:
- Type 0x0a rate=`0x6c` (54 Mbps) is correct for infrastructure when radio associates
- Type 0x06 Tag 0x05 returns the raw channel number (e.g. Channel 3 = `0x03`) ✅
- Tag 0x09 = `0x01` (open cipher) is the correct value for an open network in ADAPTER_INFO_RESP. This is the encryption-type echo, not a link state. It can coexist with a saved IP in Tag 0x01 since Tag 0x01 returns the stored static/last-used IP regardless of current link state.

---

### Tag 0x11 - CFG_Set_XPP_Auth_Mode

**Firmware Function**: `CFG_Set_XPP_Auth_Mode()`  
**Purpose**: Sets `g_XPP_Auth_Mode_Enabled` (NVRAM, persists across power cycles) so the adapter can report the correct encryption state in ADAPTER_INFO_RESP Tag 0x11 before a live radio association exists.

**Accepted values** (only `0x00` and `0x02` are processed — all others silently ignored):
- `0x00` — sets `g_XPP_Auth_Mode_Enabled = 0` → ADAPTER_INFO_RESP Tag 0x11 reports `0x00` (link not active)
- `0x02` — sets `g_XPP_Auth_Mode_Enabled = 1` → ADAPTER_INFO_RESP Tag 0x11 reports `0x02` (link active)

**Correction 2026-11-24 - what the dash means by tag 0x11 in CONNECT_REQ:** it is the radio band (dash field +0xf5f: 0 = 802.11b, 1 = 802.11a, 2 = 802.11g), not an auth flag. It is sent when the Network Mode menu changes the band. The capture file names agree: `_b` captures send 0x00 and `_bg` captures send 0x02, whatever the encryption. The firmware still only stores 0x00 and 0x02, so 0x00 and 0x02 happen to line up with the old "auth mode" reading and 0x01 (802.11a) is dropped by a stock MN-740, which has no 802.11a radio. Earlier text said: `0x02` is sent in CONNECT_REQ for all WEP connections and `0x00` for open networks; that was the band in those captures. `0x01` in CONNECT_REQ Tag 0x11 would be silently ignored (not in accepted values whitelist).

**NVRAM vs HAL — the key distinction between Tag 0x11 and Tags 0x08/0x09:**

Tags 0x08 and 0x09 report the **NVRAM-configured** encryption state — what the adapter has been told to use. Tag 0x11 reports the **live HAL state** — what the Marvell 88W8310 chipset is actually doing right now. These can and do differ during association.

Wire-verified across 9 captures (`_b` = not yet associated, `_bg` = associated):

```
Network type | tag 0x08 | tag 0x09 | tag 0x11 (not assoc) | tag 0x11 (associated)
-------------|----------|----------|----------------------|----------------------
Open         | 0x02     | 0x01     | 0x00                 | 0x02
WEP-64       | 0x04     | 0x02     | 0x00                 | 0x02
WEP-128      | 0x04     | 0x04     | 0x00                 | 0x02
```

An adapter mid-association legitimately has `tag08=0x04` (WEP configured in NVRAM), `tag09=0x02` (WEP-64 configured in NVRAM), and `tag11=0x00` (HAL not yet encrypting) simultaneously. This is not an error state — tag 0x11 is the lagging indicator that only flips once the key material is installed in silicon.

**Dashboard field `AutoClass1+0xf5f` (corrected 2026-11-24): it is the radio band and it is exactly what CONNECT_REQ tag 0x11 carries.** The Ghidra setter names below (`set_auth_open_system`, `set_auth_shared_key`, `set_auth_wpa`) are misleading; they are called from the Network Mode menu click handler (@00078656) for the Ad hoc 802.11a and Ad hoc 802.11b/g entries and from `AutoClass1_load_scan_entry_to_cfg`. Meaning of the values:
```
field_0xf5f value | Set by function                  | 802.11 auth algorithm
------------------|----------------------------------|----------------------------
0x00              | xpp_set_auth_open_system()       | 802.11b (b/g entry when the adapter reports no 802.11g; inferred)
0x01              | xpp_set_auth_shared_key()        | 802.11a (the "Ad hoc 802.11a" menu entry)
0x02              | xpp_set_auth_wpa()               | 802.11g (b/g entry when the adapter reports 802.11g)
```
This dash-side value is the Tag 0x11 wire value when the tag is sent. Changing it sets bit 0x02 of bitmask byte 2, which adds tag 0x11 to the next CONNECT_REQ. The 802.11a value 1 has not been captured on the wire yet (decompile only); the 0 and 2 values are capture-verified.

---

## Dash behaviour summary (`xonlinedash.xbe`, audited 2026-11-24)

Findings from the decompile (Ghidra `xbox` project), checked against the real-adapter captures. Where the earlier sections of this manual disagree, this section wins.

### What the dash can send

The dash builds exactly **five** XPP request types, and each has a single builder (the only callers of `xpp_nlb_frame_buffer_alloc` besides the System Link connection code):

| Type | Builder | Sent from |
|---|---|---|
| 0x01 HANDSHAKE_REQ | `xpp_build_handshake_request` @000a346d | when the wireless UI object is created and when it re-handshakes (3 call sites) |
| 0x03 NETWORKS_LIST_REQ | `xpp_build_networks_list_request` @000a34e2 | `xpp_ui_scan_request_and_wait`, when the Select Network screen is entered |
| 0x05 ADAPTER_INFO_REQ | `xpp_build_adapter_info_request` @000a3cac | **only** `xpp_ui_wlan_status_screen_update` (the Wireless Status screen) |
| 0x07 CONNECT_REQ | `xpp_build_connect_request` @000a364e | the Wireless Settings **SAVE** handler and the Wireless **Password** handler |
| 0x09 BEACON_REQ | `xpp_build_beacon_request` @000a353b | every 1000 ms while the FSM is in the beacon state |

The dash never sends ECHO (0x00), 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, discovery, TFTP, HTTP or any admin-protocol frame. The dash contains no TFTP, firmware-update, discovery (port 42424) or MSBN strings at all. TFTP, HTTP and discovery are only for PC tools; an emulator that never implements them still works with a stock Xbox. The `xpp_nlb_connection_*` functions (open/connect/retransmit/teardown) are System Link between consoles and are not part of the adapter protocol.

### Request/response FSM

The dispatcher `xpp_poll_adapter_and_dispatch_response` @000a4a70 runs about every 100 ms. It only accepts the response type that matches the current request state (`this+0x0c`); any other type is dropped:

| State | Request | Accepted response | Timeout | Retries |
|---|---|---|---|---|
| 1 | HANDSHAKE_REQ | 0x02 | 2000 ms | 1 resend, then error 0x80000001 |
| 2 | NETWORKS_LIST_REQ | 0x04 | 10000 ms | resend, then 0x80000001 |
| 3 | ADAPTER_INFO_REQ | 0x06 | 3000 ms (the dash re-sends the same request on timeout) | then 0x80000001 |
| 4 | CONNECT_REQ | 0x08 | 10000 ms | then 0x80000001 |
| 5 | BEACON_REQ (every 1000 ms) | 0x0A | 3000 ms since the last accepted response (23000 ms in the post-connect wait, when `xpp_beacon_state_init_and_send` is called with a non-zero argument) | then 0x80000001 |

Error `0x80000001` makes the UI show `WIRELESS_ERR_COMMUNICATE_DEVICE` ("Technical difficulties when communicating with wireless adapter") via `xpp_ui_adapter_error_and_teardown`. This is the same screen PJ saw when INFO tag 0x04 was 2.

### CONNECT_REQ contents

CONNECT_REQ is built from a 32-bit **bitmask** (`connect_req_bitmask`, three bytes used). It can only ever contain tags 0x00–0x12. The dash **never sends tag 0x14 (MAC clone) or tags 0x81–0x85**, so an adapter does not need to handle them for a stock Xbox. Tags appear in this fixed order, each only if its bit is set: `0x00` (zero length, "save"), `0x01` IP, `0x02` enable, `0x03` admin password, `0x04` network mode (0 ad hoc, 1 infrastructure), `0x05` ad-hoc channel, `0x06` BSSID/target MAC (6 B), `0x07` SSID, `0x08` auth type, `0x09` encryption type, `0x0E` WEP-64 key index, `0x0A`–`0x0D` WEP-40 keys (5 B each), `0x0F` WEP-128 key (13 B), `0x10` PMK (32 B), `0x12` passphrase (max 63), `0x11` radio band last. The tag count byte is the popcount of the bitmask, and the bitmask is cleared after the send.

- **Admin password (tag 0x03):** set from the Xbox "Wireless Password" screen (`WIRELESS_PASS_*`). It must be 3–16 printable ASCII characters (0x20–0x7E); an empty value clears the password (the UI asks "disable the password?" first). The dash only sends it in this tag. I found no other use of it in the paths read. The adapter is expected to store it and answer CONNECT_RESP 0.
- **No password retry:** if CONNECT_REQ for the password fails the UI says `WIRELESS_PASS_ERR_CONFIG_DEVICE`.

### CONNECT_RESP handling (`xpp_process_connect_ssid_response` @000a3a85)

The response must be type 0x08 with body size 4.

| Result | Dash action |
|---|---|
| 0x00 | success: commit the pending config as the live config, clear pending flags |
| 0x01, 0x03, 0x04 | all identical: error `0x80000003`, pending flag set, request completes (UI shows `WIRELESS_SETTINGS_ERR_CONFIG_DEVICE`) |
| 0x02 | retry: error `0x80000002`, the dash re-arms a 10 s timer and returns without completing |
| 0x05 and above | error `0x80000003` set but the response is ignored (request stays pending until the 10 s timeout) |

A real MN-740 returned 0x00 in every capture, including for wrong keys and missing networks.

### How the dash decides a connection worked

After CONNECT_RESP 0 the UI shows a wait dialog (with CANCEL) and polls beacons. It uses the 5-slot ring in `xpp_beacon_rssi_preprocess` @000a2af6 (slots of `[auth, rssi]`; status 0x02 is stored as RSSI 0xA6; status 0x01 or 0x03 resets the ring):

1. If **any** of the 5 samples has auth 0, the ring state is 0 and the smoothed RSSI is the average of the 5 RSSI bytes (signed). If none does, the state is 2.
2. `xpp_rssi_alt_check` @000a2ae7 accepts the connection only if ring state == 0 **and** the average RSSI is above **-72 dBm** (signed byte > -0x48).
3. Otherwise the UI goes to an error screen: ring state 2 → screen 0x5f, state 1 → 0x61, anything else (never completed, or RSSI -72 dBm or weaker) → 0x60. The screen titles in the dash are `Wireless_Incorrect_Security`, `Wireless_No_Connection` and `Wireless_Poor_Connection`; the mapping of 0x5f/0x60/0x61 to those titles is likely (0x5f is the "security type or key incorrect" screen PJ saw when the adapter sent 0x02) but not yet traced.

Separately, `xpp_handle_beacon_response` @000a3563 sets the Wireless Status screen state (`+0x3c`) from the **latest** beacon only: auth 0 with RSSI above -91 dBm → 0 (connected), 1 → 1, 2 → 2, 3 → 3, any other value discards the beacon. The status screen shows "Connected" only while that state is 0.

### Non-XPP features in the dash that touch the network

- **PPPoE client** (EtherType 0x8863/0x8864): see the PPPoE section above. Needs bridging.
- **UPnP:** SSDP `M-SEARCH` (UDP 239.255.255.250:1900) for `WANIPConnection:1` and `WANPPPConnection:1`, then SOAP `AddPortMapping` over HTTP. This travels as ordinary IP and must pass through the adapter's bridge unchanged.
- **MAC clone / host name** (Network Settings): not XPP. The Xbox NIC simply changes its source MAC. **Capture-verified** in a capture with a cloned MAC: HANDSHAKE_REQ #1 and #15 come from 00:0d:3a:50:22:73, and #17 comes from the cloned MAC aa:bb:cc:dd:aa:ff, with no CONNECT_REQ tag involved. An adapter must accept a new HANDSHAKE_REQ from a different source MAC at any time and treat it as a new peer.

### Ad-hoc CONNECT_REQ (audited 2026-11-24, decompile checked against all real adapter captures)

What the dash puts in a CONNECT_REQ, each tag only when its bitmask bit is set:

```
Tag  | Dash field | Meaning in the real dash
-----|------------|------------------------------------------------------------
0x04 | +0xf5c     | Network mode: 0 = ad hoc, 1 = infrastructure
0x05 | +0xf5d     | Ad-hoc channel number. Checked against the 2.4 GHz mask or the
     |            | 802.11a channel list; ad hoc only, infrastructure sends none
0x09 | +0xf5e     | Encryption type: 1 open, 2 WEP-64, 4 WEP-128, 0 WPA
0x0E | +0xf71     | WEP-64 key index (always 1; only sent with WEP-64 keys)
0x11 | +0xf5f     | Radio band: 0 = b, 1 = a, 2 = g (set by the Network Mode menu)
```

Capture evidence (CONNECT_REQ tag lists):

```
ad hoc open       04=00 05=06 07="adhocopen"
ad hoc WEP-64     04=00 05=01 07=SSID 08=00 09=02 0E=01 0A-0D keys
infra open        08=00 09=01 11=00
infra WEP-64      08=00 09=02 0E=01 0A-0D keys   (AP on channel 9: no channel sent)
infra WEP-128     09=04 0F=key
```

Effects on an adapter or emulator:
- Ad hoc is signalled by tag 0x04 = 0, not by tag 0x09. Treating tag 0x09 = 4 as ad hoc misreads an infrastructure WEP-128 request as ad hoc, and misses every real ad-hoc request.
- The ad-hoc channel comes from tag 0x05. Reading tag 0x0E as the channel gives channel 1 for every WEP-64 connect.
- The "Ad hoc 802.11a" menu entry sets band 1, which goes out as tag 0x11 = 1 and reloads the channel from the first 802.11a list entry. This is from the decompile only; a real 802.11a connect has not been captured yet.
- A stock MN-740 is 802.11b/g only (handshake byte 208 = 0x05), so the dash never offers 802.11a on it and the firmware ignores band 1. The emulator (`allow_5ghz=1`, byte 208 = 0x07) is the only target that can show 802.11a.
- Our Windows tool's xbox mode still sends the older form to a real adapter (tag 0x04 = 1, tag 0x09 = 4, channel in tag 0x0E); the adapter accepted it and the network was seen broadcasting, but whether it used the requested channel has not been checked. The emulator parser (`tlv_parser.c`, build b85) accepts both forms.

### Not audited yet

Exact mapping of UI screen ids (0x5f/0x60/0x61, 0x24c–0x24e) to titles; the PPPoE and DHCP flows in the IP stack; whether `Wireless_Poor_Connection` is triggered by the beacon RSSI or by the TX rate; how the adapter firmware (NML.bin) uses tags 0x04, 0x05, 0x09 and 0x11 for ad hoc; WPA-PSK key handling in `xpp_ui_process_wpa_key_input`.

---

## Implementation Checklist
## Implementation Checklist

### Phase 1: Core Infrastructure ✅
- [ ] Raw Ethernet socket (EtherType 0x886f)
- [ ] RFC 1071 checksum implementation
- [ ] HMAC-SHA1 authentication
- [ ] Packet parser for XPP Headers
- [ ] Load secrets (hmac_key.bin, hmac_salt.bin, auth_copyright.bin)

### Phase 2: Discovery & Authentication ✅
- [ ] Type 0x01 handshake request handler
- [ ] Type 0x02 handshake response builder
- [ ] HMAC signature for Type 0x02

### Phase 3: Network Operations ✅
- [ ] Type 0x03 networks list request handler
- [ ] Wi-Fi scan integration (iw/nmcli/wpa_cli)
- [ ] Type 0x04 networks list response builder
- [ ] 61-byte network slot encoding
- [ ] Signal strength conversion (dBm 0-255)

### Phase 4: Connection Management ✅
- [ ] Type 0x07 TLV parser
  - [ ] Tag 0x01/0x04 (SSID)
  - [ ] Tag 0x02 (Channel for ad-hoc)
  - [ ] Tag 0x09 (Network mode)
  - [ ] Tag 0x0A (Password/WEP key)
  - [ ] Tag 0x0B-0x0E (WEP multi-key)
- [ ] Type 0x08 connect response
- [ ] Wi-Fi connection integration (wpa_supplicant)
- [ ] SavedProfile structure (flash simulation)

### Phase 5: Keepalive & Monitoring ✅
- [ ] Type 0x09 beacon request handler
- [ ] Type 0x0a beacon response builder
- [ ] 5-second beacon timeout detection
- [ ] Connection state machine
- [ ] Type 0x05/0x06 periodic status updates

### Phase 6: Advanced Features (Optional)
- [ ] MAC address pairing (mac.dat)
- [ ] Region code support (Tag 0x12)
- [ ] Static IP configuration (Tags 0x06-0x08)
- [ ] WEP-128 support (Tag 0x0F)
- [ ] Multi-adapter support

### Phase 7 — TFTP (Optional)
- [ ] BBN discovery responder (UDP port 42424)
- [ ] TFTP server on port 69 (WRQ firmware flash)
- [ ] TFTP server on port 16932 (WRQ with MAC+HMAC auth)
- [ ] ~~RRQ file reads~~ — **broken in all stock firmware; requires two-instruction patch** (see Virtual File System section for fix)
- [ ] Virtual file system (dbgout.txt, ar5eepo.dat, ar5maco.dat, image) — WRQ only until RRQ patched


### Phase 8: WPA/WPA2 (Firmware Patch)
**see [WPA/WPA2 Implementation](#wpa-wpa2-implementation)**

**Xbox sends PMK**:
- [ ] Patch `XPP_Parse_Entry()` case 0x10 to store 32-byte PMK to `G_WPA_PMK`
- [ ] Implement `eapol_handle_key_exchange()` body:
  - [ ] ANonce/SNonce exchange
  - [ ] PTK derivation via PRF-512(PMK, ANonce, SNonce, MACs)
  - [ ] MIC verification on handshake msg 3
  - [ ] PTK install via `ath_hal_set_key_cache_entry()`
  - [ ] GTK unwrap and install via `ath_hal_install_hw_key()`
  - [ ] Send handshake msg 4 confirmation
- [ ] Add `XPP_SEC_TKIP = 0x03` and `XPP_SEC_CCMP = 0x04` to `wlan_get_encryption_type()`

**Firmware calculates PMK**:
- [ ] Allocate `G_WPA_Passphrase[64]` in NVRAM
- [ ] Patch `XPP_Parse_Entry()` case 0x10 to store raw passphrase
- [ ] Wire `XPP_PBKDF2_F_Block()` into `wireless_worker_task()` async signal
- [ ] All items from Path 1 `eapol_handle_key_exchange()` above
- [ ] Add `XPP_SEC_TKIP = 0x03` and `XPP_SEC_CCMP = 0x04` to `wlan_get_encryption_type()`

** Receive Passphrase via Type 0x11 WPA_ASSOC_REQ


---

## Packet Flow Timing Diagrams

### Initial Connection Sequence
```
Time  Xbox                    Adapter                   State
─────────────────────────────────────────────────────────────────
0.0s  Type 0x01 ────────>                              DISCONNECTED
      (Challenge)           
                            Compute HMAC
                            Build status
0.1s                  <──────── Type 0x02              HANDSHAKE_DONE
                                (HMAC + Wi-Fi Status)

1.0s  Type 0x09 ────────>                              
      (Beacon #1)           Verify signature
1.1s                  <──────── Type 0x0a
                                (Security: 02 80 03 00)

2.0s  Type 0x09 ────────>                              
      (Beacon #2)           Check association
2.1s                  <──────── Type 0x0a
                                (Security: 02 80 03 00)

3.0s  Type 0x09 ────────>                              
      (Beacon #3)           Link confirmed
3.1s                  <──────── Type 0x0a              LINKED ✓
                                (Security: 02 80 03 00)
─────────────────────────────────────────────────────────────────
```

### Ongoing Operation (Connected State)

```
Time  Xbox                    Adapter                   Notes
─────────────────────────────────────────────────────────────────
0s    Type 0x09 ────────>                              Keepalive
      (Beacon)
0.1s                  <──────── Type 0x0a              Status OK

2s    Type 0x05 ────────>                              Status query
      (STATUS variant)      Read Wi-Fi stats
2.1s                  <──────── Type 0x06        Dashboard update
                                (Signal: 75%, Chan: 6)

4s    Type 0x09 ────────>                              Keepalive
4.1s                  <──────── Type 0x0a              Status OK

6s    Type 0x05 ────────>                              Status query
6.1s                  <──────── Type 0x06       Dashboard update

... (Repeat every 1-2 seconds) ...
─────────────────────────────────────────────────────────────────
```

### Network Discovery Flow

```
Time  Xbox                    Adapter                   Action
─────────────────────────────────────────────────────────────────
0s    [User opens Network List in Dashboard]

0.1s  Type 0x03 ────────>                              Scan request
      (Network List Req)    
                            Start Wi-Fi scan
                            Scan channels 1-11
                            Collect beacons
                            (Takes 50-900ms)

0.8s                  <──────── Type 0x04              Results ready
                                (16 networks × 61 bytes) //Max limit


      [Dashboard displays network list]
─────────────────────────────────────────────────────────────────
```

### Connection to New Network

```
Time  Xbox                    Adapter                   Action
─────────────────────────────────────────────────────────────────
0s    [User selects "MyNetwork" and enters password]

0.1s  Type 0x07 ────────>                              Connect request
      (TLV: SSID, Pwd,      Parse TLV
       Security, Region)
                            Extract config
0.2s                  <──────── Type 0x08              Confirm
                                (Result: 0x00 = OK)

                            [Adapter starts connecting...]
                            Associate to AP
                            WPA handshake
                            DHCP request
                            (Takes 2-5 seconds)

      [Connection established - return to beacon cycle]
─────────────────────────────────────────────────────────────────
```

### Watchdog Timeout Scenario

```
Time  Xbox                    Adapter                   State
─────────────────────────────────────────────────────────────────
0s    Type 0x09 ────────>                              LINKED
      (Last beacon)
0.1s                  <──────── Type 0x0a

      [Xbox crashes / network cable unplugged]

5s                            5s beacon timeout         STANDBY
                            Radio stays on
                            Stop routing packets

30s                           30s watchdog timeout      ERROR
                            Call net_set_error_state
                            Shutdown Wi-Fi radio
                            Enter low-power mode

      [Xbox reboots]

60s   Type 0x01 ────────>                              Recovery
      (Handshake)           Full re-auth required
─────────────────────────────────────────────────────────────────
```

---

## WPA/WPA2 Implementation

**The MN-740 is fully capable of WPA (TKIP) and WPA2 (AES-CCMP) in hardware.**
The limitation is purely firmware. The hardware was designed for WPA/WPA2 from
the start. The Atheros AR5212 hardware key cache, AES-Rijndael engine, and TKIP
MIC generation are all present and accessible via the existing HAL functions
`ath_hal_set_key_cache_entry()`, `ath_hal_ccmp_aes_encrypt()`, and
`wlan_ccmp_decrypt_verify()`.

### The Three Gaps (Ghidra decompile-verified, firmware v1.0.2.21)

**Gap 1 — WPA not advertised in HANDSHAKE_RESP**

Two functions in `XPP_Type02_0x01_Handshake` return hardcoded values:

```
XPP_Get_SecurityCap_Stub_Returns0x06_WPA_GAP1  @ 0x8009914C  returns 0x06
XPP_Get_CipherCap_Stub_Returns0x07_WPA_GAP1    @ 0x8009913C  returns 0x07
```

These populate handshake payload bytes 174 and 175 respectively.

The dashboard runs two separate functions on these bytes:
- `xpp_fetch_adapter_wpa_caps()` checks bytes **174 + 175** (rejection/capability gate)
- `xpp_select_best_security_mode()` reads bytes **252 + 253** (UI pre-selection)

**Both byte pairs must be updated.** Fixing only byte 174 passes the capability
gate but the UI still shows WEP only because byte 252 is not updated.

```
Byte 174 fix: change return of 0x8009914C from 0x06 to 0x16 (adds bit 0x10 = WPA1/RSN)
Byte 175 fix: 0x07 is acceptable (bits 0x01+0x02+0x04 required, all set)
Byte 252 fix: must also be set to 0x16 for xpp_select_best_security_mode WPA path
Byte 253 fix: 0x07 is acceptable as-is

Patch 1: @ 0x8009914C  li v0, 6   ->  li v0, 0x16
           Bytes: 24020006 -> 24020016
```

**Gap 2 — PMK and passphrase received but discarded**

When the user enters a WPA key, the dashboard sends either:
- Tag 0x10 (64 hex chars): pre-computed 32-byte PMK → firmware advances parse
  pointer past the 34-byte entry but **never stores the value**
- Tag 0x12 (8-63 ASCII chars): passphrase → firmware has **no case 0x12 handler**,
  logs "got_unknown" and **aborts the entire TLV parse loop**

Required patches in `XPP_Type02_0x07_FlashConfig` TLV dispatcher:

```
Patch 2a — Tag 0x10 (PMK storage):
  Function: XPP_Type02_0x07_FlashConfig @ 0x8009A9B8
  Current:  case 0x10 -> advance parse pointer, discard 32 bytes
  Required: case 0x10 -> memcpy(G_WPA_PMK, payload, 32); set G_WPA_PMK_Ready = 1

Patch 2b — Tag 0x12 (passphrase handler):
  Current:  no case 0x12 -> falls to default -> logs "got_unknown" -> exits loop
  Required: case 0x12 -> store passphrase (8-63 bytes) to G_WPA_Passphrase buffer
            then schedule XPP_PBKDF2_F_Block() in worker task context

  XPP_PBKDF2_F_Block @ 0x8004114C -- fully implemented, NEVER called in stock firmware
  Call twice with iterations=4096 to produce 32-byte PMK from passphrase:
    block1 = PBKDF2_F(passphrase, ssid, 4096, 1)  -> G_WPA_PMK[0..19]
    block2 = PBKDF2_F(passphrase, ssid, 4096, 2)  -> G_WPA_PMK[20..31]
```

**Gap 3 — 4-way EAPOL handshake stubbed out**

The EAPOL key exchange function is present but logs "EAP Failure" and returns.
ANonce/SNonce exchange, PTK derivation, MIC verification, and GTK installation
are all absent.

```
Required implementation (eapol_handle_key_exchange):
  1. Receive ANonce from AP EAPOL message 1
  2. Generate SNonce via RC4_KSA_Key_Schedule (@ 0x8007CFEC)
  3. Derive PTK: PRF-512(G_WPA_PMK, "Pairwise key expansion",
                         min(AP_MAC,STA_MAC) || max(AP_MAC,STA_MAC) ||
                         min(ANonce,SNonce) || max(ANonce,SNonce))
  4. Verify MIC on EAPOL message 3 using PTK KCK (first 16 bytes of PTK)
  5. Install PTK via ath_hal_set_key_cache_entry()
  6. Unwrap GTK from message 3 using PTK KEK (bytes 16-31 of PTK)
  7. Install GTK via ath_hal_install_hw_key()
  8. Send EAPOL message 4 confirmation
```

### New cipher type constants required

`wlan_get_encryption_type()` currently returns only 0x00 (none), 0x01 (WEP), 0x02
(WPA/WPA2 generic). Two new values must be defined for Tag 0x11 in ADAPTER_INFO_RESP:

```c
XPP_SEC_TKIP = 0x03   // WPA-TKIP (write to Tag 0x11 when TKIP active)
XPP_SEC_CCMP = 0x04   // WPA2-AES-CCMP (write to Tag 0x11 when CCMP active)
```

### Patch summary table

```
Gap | Patch | Address     | Change                                     | Notes
----|-------|-------------|--------------------------------------------|------------------
1   | 1     | 0x8009914C  | li v0,6 -> li v0,0x16                      | 1 instruction
1   | 1b    | byte252 src | same function, second capability return     | same stub to fix
2   | 2a    | 0x8009A9B8  | Tag 0x10 case: store PMK, set ready flag    | ~8 instructions
2   | 2b    | 0x8009A9B8  | Add case 0x12 before default: store passph  | ~12 instructions
2   | 2c    | worker task | Call XPP_PBKDF2_F_Block x2 when passphrase  | ~20 instructions
3   | 3     | eapol fn    | Implement 4-way handshake body              | ~100+ instructions
```

### HTTP as the WPA firmware update path

With the HTTP server re-enabled (see HTTP Web Interface section), the simplest
workflow for deploying a WPA-patched firmware is:

```
1. Enable HTTP server via the 4-instruction boot patch
2. Flash original firmware to get HTTP working
3. Build patched firmware with Gaps 1-3 closed
4. POST patched firmware to http://192.168.2.252:16868/cgi/upload.cgi
   (multipart/form-data with filename= field, exactly 1MB image)
5. Adapter flashes and reboots automatically
```

## DHCP Implementation & XPP Interaction

### Overview
The MN-740 operates as a **Layer 2 Transparent Bridge**. While it does not act as a DHCP client itself for its primary function, it performs **Passive DHCP Snooping** to maintain its internal state. The adapter "listens" to the DHCP handshake between the Xbox console and the network Gateway to populate its internal status registers.

### DHCP Snooping Mechanic
When the Xbox Console initiates a DHCP transaction, the adapter’s firmware intercepts specific UDP packets on **Ports 67 (Server)** and **68 (Client)**.

1. **Intercept**: The firmware monitors traffic for the **DHCP Magic Cookie**: `0x63 0x82 0x53 0x63`.
2. **Filter**: It specifically looks for **Option 53 (Message Type)** with a value of `0x05` (**DHCP ACK**).
3. **Extraction**: Upon detecting an ACK, the firmware extracts the `yiaddr` (Your IP Address) and **Option 54 (Server Identifier)**.

### Relationship to Type 0x02 (Status Response)
The IP address captured during snooping is mirrored in the **XPP Type 0x02** handshake response. This allows the Xbox Dashboard to verify that the wireless bridge has successfully bridged the console onto the local subnet.
```
Field     | Offset | Size    | Description
----------|--------|---------|----------------
Current IP| 0x12   | 4 Bytes | The IP address extracted from the last seen DHCP ACK.
Server ID | N/A    | 4 Bytes | Internal only; used to detect Gateway changes/roaming.
```

###DHCP Info
```
 Component           | Value      | Role
---------------------|------------|-----------------------
 **DHCP Port (Src)** | 68         | Xbox Console (Client)
 **DHCP Port (Dst)** | 67         | Router/Gateway (Server)
 **Option 53**       | 0x05       | DHCP ACK (Triggers IP Cache Update)
 **Option 54**       | IP Address | Server Identifier (Gateway IP)
 **Option 51**       | 4 Bytes    | Lease Time (Used for internal timeout logic)
```
### DHCP Sequence
**1. DHCP DISCOVER**
```
Adapter → Broadcast (255.255.255.255:67)
Source Port: 68
Contains: Client MAC, requested IP (if cached)
```

**2. DHCP OFFER**
```
Server → Broadcast (255.255.255.255:68)
Contains: Offered IP, subnet mask, gateway, DNS, lease time
```

**3. DHCP REQUEST**
```
Adapter → Broadcast (255.255.255.255:67)
Contains: Requested IP, server identifier (Option 54)
```

**4. DHCP ACK**
```
Server → Adapter (unicast or broadcast)
Contains: Confirmed IP configuration
```

> **NOTE on Static IP Behavior:** If the Xbox is configured with a Static IP, no DHCP ACK will traverse the bridge. In this scenario, the `0x12` field in the Type 0x02 response will remain `0.0.0.0` unless the Xbox explicitly pushes the configuration to the adapter using **XPP Tag 0x04**.

### Session Lifecycle

**1. Session Creation (Type 0x01 Handshake)**
```
Xbox → Type 0x01 (Challenge)
Adapter generates:
  - New session ID (incremented from previous)
  - Session handle (pointer to session context)
  - Security state = PENDING
  - Link state = DISCONNECTED
```

**2. Session Authentication (Type 0x02 Response)**
```
Adapter → Type 0x02 (HMAC signature valid)
Update states:
  - Security state = AUTHENTICATED
  - Link state = LINKED (after 3 beacons)
```

**3. Session Active (Beacon Exchange)**
```
Continuous Type 0x09/0x0a exchange
Security state = AUTHENTICATED
Link state = ACTIVE
Session ID remains constant
```

**4. Session Timeout (30-second watchdog)**
```
No traffic from Xbox MAC for 30 seconds:
  - Security state = TIMEOUT
  - Link state = ERROR
  - Session handle invalidated
Requires new Type 0x01 handshake
```

### Security State vs Link State
**Security State** (Authentication):
- `PENDING`: Challenge sent, awaiting response
- `AUTHENTICATED`: Valid HMAC received
- `TIMEOUT`: No activity timeout
- `REJECTED`: Invalid HMAC or malformed packet

**Link State** (Connection):
- `DISCONNECTED`: No association
- `LINKED`: Handshake complete, beacons starting
- `ACTIVE`: Regular beacon exchange (every 1 second)
- `ERROR`: Watchdog timeout or fatal error

**Independence**: Security can be `AUTHENTICATED` while link is `ERROR` (e.g., beacon timeout)

### 5.5 The "IP Mismatch" Logic
If the IP address reported in the Type 0x02 response does not match the IP the Xbox is currently using, the console may initiate a **Type 0x01 (Handshake Request)** to re-sync the adapter. If the adapter continues to report `0.0.0.0`, the Xbox Dashboard will trigger the "Wireless Adapter is connected but has no IP" error message.

---

## Firmware Version Detection

The MN-740 reports firmware version in Type 0x02 handshake response at offset 136 (32 bytes).

### Known Verified Firmware Versions (Not extensive)
```
 Version  | Release    | Notes
----------|------------|-------
 1.0.2.21 | 2004       | Early production firmware (latest public release available in update tool)
 1.0.2.26 | 2005       | Final production firmware (latest release only pre installed on hardware)
 1.0.2.28 | Unreleased | Debug/development build (no public release)
```
### Version-Specific Differences

**v1.0.2.21 (Early Production)**:
- Channel 14 (Japan) requires separate region flash update
- DHCP client has retry bug (3 attempts max)
- WEP key cache not implemented (slower reconnects)

**v1.0.2.26 (Final Production)**:
- Region code properly read from EEPROM at `0x800A984E`
- DHCP client improved (10 attempts with exponential backoff)
- WEP key cache added for fast roaming
- Watchdog timeout increased from 20s to 30s
- Bug fix: Hidden SSID length 0 handling

**v1.0.2.28 (Debug Build)**:
- UART debug logging enabled (115200 baud)
- Extra validation checks in TLV parser
- Never released to production
- Occasionally found on developer units
- Apparently leaked in 2020 Xbox giga leak

## Known Limitations
### Hardware Constraints
- MN-740 released 2004 (pre-WPA2 certification)
- 2.4GHz only (no 5GHz support)
- 802.11b/g maximum (no n/ac/ax)
- No WPA3/SAE support
- Single shared HMAC key (no per-device keys)

### Protocol Constraints
- SHA1 considered weak by modern standards
- No certificate-based authentication
- No key rotation mechanism
- Security types are adapter-specific values

---

## Required Secrets

The HMAC-SHA1 authentication requires three static values that are hardcoded in the MN-740 firmware ROM. For an emulator or software adapter, embed these directly:

```
HMAC key (16 bytes):
  Hidden

HMAC master key string (117 bytes):
  "Hidden."

HANDSHAKE_RESP copyright string (84 bytes, null-padded):
  "Hidden"
```


---

## Ghidra Struct Definitions

The following C-style structs have been created in Ghidra's XPP data type category based on decompile-verified field offsets. These are available in the Ghidra project for applying to function parameters and local variables.

### XPP_EthernetHeader (14 bytes)
```c
struct XPP_EthernetHeader {
    byte   dst_mac[6];       // +0x00  Destination MAC address
    byte   src_mac[6];       // +0x06  Source MAC address
    ushort ether_type;       // +0x0C  EtherType (0x886f=NLB, 0x888e=EAPOL)
};
```

### XPP_Header (12 bytes)
```c
struct XPP_Header {
    byte   magic[4];         // +0x00  "XBOX" (0x58 0x42 0x4F 0x58)
    byte   version_major;    // +0x04  0x01 (static)
    byte   version_minor;    // +0x05  0x01 (static)
    byte   body_size_dw;     // +0x06  (12 + padded_payload) / 4
    byte   packet_type;      // +0x07  Command ID (0x00–0x11)
    ushort xid;              // +0x08  Transaction ID
    ushort checksum;         // +0x0A  RFC 1071 (0x0000 during calculation)
};
```

### XPP_NlbFrame (variable)
```c
struct XPP_NlbFrame {
    XPP_EthernetHeader eth;  // +0x00
    XPP_Header         xpp;  // +0x0E
    byte               payload[1]; // +0x1A  payload start (variable length)
};
```

### XPP_HandshakeResp_Payload (256 bytes)
```c
struct XPP_HandshakeResp_Payload {
    byte   hmac_sha1[20];         // +0x00  HMAC-SHA1 signature
    char   copyright_string[84];  // +0x14  "Device is Xbox Compatible..."
    char   model_string[32];      // +0x68  "Xbox Wireless Adapter (MN-740)"
    char   firmware_version[32];  // +0x88  e.g. "1.0.2.26 Boot: 1.3.0.06"
    byte   bssid[6];              // +0xA8  Connected AP MAC or zeros
    byte   security_caps;         // +0xAE  Byte 174 — WPA capability flags
    byte   cipher_caps;           // +0xAF  Byte 175 — cipher capability flags
    uint   chan_bitmask_24ghz;    // +0xB0  Bytes 176-179 - ad hoc 802.11b/g channel mask
    byte   chan_bitmask_ext[28];  // +0xB4  Bytes 180-207 - ad hoc 802.11a channel mask
    byte   radio_mode_caps;       // +0xD0  Byte 208 — radio mode bitmask
    byte   dhcp_state;            // +0xD1  Byte 209 — DHCP state
    uint   ip_address;            // +0xD2  Bytes 210-213 — current IP big-endian
    byte   radio_active;          // +0xD6  Byte 214
    byte   auth_status;           // +0xD7  Byte 215
    byte   radio_active_guard;    // +0xD8  Byte 216 — must be <2
    byte   current_channel;       // +0xD9  Byte 217
    byte   auth_algorithm;        // +0xDA  Byte 218 — must be <3
    byte   ssid_len;              // +0xDB  Byte 219 — max 32
    char   ssid[32];              // +0xDC  Bytes 220-251
    byte   sec_caps_default;      // +0xFC  Byte 252 — UI pre-selection
    byte   cipher_caps_default;   // +0xFD  Byte 253 — UI pre-selection
    ushort reserved;              // +0xFE  Always 0x0000
};
```

### XPP_HandshakeResp_Trailer (4 bytes)
```c
struct XPP_HandshakeResp_Trailer {
    byte opmode_mask;  // +0x00  0x02=WEP disabled, 0x04=WEP enabled
    byte link_state;   // +0x01  0x01=no link, 0x02=infrastructure, 0x04=ad-hoc
    byte reserved0;    // +0x02  Always 0x00
    byte reserved1;    // +0x03  Always 0x00
};
```

### XPP_NetworkSlot (61 bytes)
```c
struct XPP_NetworkSlot {
    byte bssid[6];          // +0x00  AP MAC address
    byte privacy_flags;     // +0x06  UNRELIABLE — do not use for security check
    byte ssid_len;          // +0x07  0=hidden SSID
    char ssid[32];          // +0x08  Network name, null-padded
    byte network_mode;      // +0x28  0x00=softAP, 0x02=infrastructure. Must be <=2.
    byte channel;           // +0x29  AP channel number
    byte security_status;   // +0x2A  0x02=Privacy NOT set, 0x04=Privacy SET
    byte rate_indicator;    // +0x2B  0x01 when open, 0x06 when encrypted
    byte signal_rssi;       // +0x2C  0-255 scaled
    byte supported_rates[8];// +0x2D  802.11 rate codes
    byte padding[8];        // +0x35  Zeros
};
```

### XPP_BeaconResp_Payload (4 bytes)
```c
struct XPP_BeaconResp_Payload {
    byte auth_status;   // +0x00  0x00=authenticated, 0x01=associating, 0x02=open/idle, 0x03=WEP assoc
    byte smoothed_rssi; // +0x01  10-sample growing-window average (firmware). 0x80=pre-assoc uninit global, 0xBA=not-auth seed.
    byte tx_rate_code;  // +0x02  Raw 802.11 rate code & 0x7F. 0x6C=54Mbps infra, 0x16=11Mbps ad-hoc cap.
    byte reserved;      // +0x03  Always 0x00
};
// NOTE: 16 bytes of uninitialised firmware memory follow the 4-byte payload — NOT protocol data.
```

### XPP_TlvTag (variable)
```c
struct XPP_TlvTag {
    byte tag;     // +0x00  Tag ID
    byte len;     // +0x01  Data length
    byte data[1]; // +0x02  Variable-length data
};
```

### XPP_EapolFrame (variable)
```c
struct XPP_EapolFrame {
    byte   dst_mac[6];        // +0x00
    byte   src_mac[6];        // +0x06
    ushort ether_type;        // +0x0C  0x888e
    ushort frame_type_word;   // +0x0E  0x6388 or 0x123c
    byte   type_marker;       // +0x10  0x11 (constant)
    byte   sub_type;          // +0x11  Direction/state byte
    ushort reserved0;         // +0x12  0x0000
    ushort payload_length;    // +0x14  Big-endian payload length
    ushort reserved1;         // +0x16  0x0000
    byte   payload[1];        // +0x18  Sub-TLVs
};
```

### XPP_FsmState (key fields — XPP_FsmState struct in Ghidra, ~4003 bytes total)

Key fields confirmed by decompile. All offsets are from the `this` pointer (AutoClass1):

```c
// Selected named fields — see Ghidra XPP category for full struct
+0x05  byte   connection_mode_flags   // bit2=0→WPA path, bit2=1→CONNECT_REQ path
+0x08  byte   connection_flags        // General connection flags
+0x0C  byte   fsm_state               // Current FSM state (0x00–0x1b)
+0x0D  byte   is_connected            // 1 after successful handshake
+0x12  byte   timeout_ticks_short     // Timeout states 2,3,7,0xb,0x19 (×5 ticks)
+0x1D  byte   timeout_ticks_connect   // Timeout states 4,8,9,0xa (×5 ticks)
+0x24  byte   timeout_ticks_0f        // Timeout state 0x0f (×5 ticks)
+0x25  byte   wpa_retry_limit         // WPA retry limit before fatal error
+0x2A  byte   timeout_ticks_wpa       // WPA states 0x11–0x15 timeout (×5 ticks)
+0x2C  byte   nonce[16]               // 16-byte challenge nonce (HANDSHAKE_REQ)
+0x40  uint   recv_buf_ptr            // NLB receive buffer pointer
+0x44  uint   recv_buf_type           // NLB receive buffer type
+0x1D8 uint   current_tick            // Current FSM tick counter
+0x938 uint   dhcp_wpa_state[9]       // DHCP state block (IP/mask/gateway/DNS)
+0x962 byte   wpa_cred_buf0[64]       // WPA credential buffer 0
+0x9A2 byte   wpa_cred_buf1[64]       // WPA credential buffer 1
+0x9E2 byte   wpa_cred_buf2[40]       // WPA credential buffer 2
+0xA0A char   wpa_assoc_ssid[40]      // WPA association SSID
+0xA34 uint   wpa_anonce_ptr          // Pointer to WPA ANonce buffer
+0xA38 byte   wpa_handshake_flags[8]  // WPA handshake progress counters
+0xA60 uint   connection_start_tick   // Tick when WPA credentials loaded
+0xA68 uint   fsm_timer_target        // Next scheduled tick deadline
+0xA78 uint   error_flags             // Error code (ORed on error)
+0xAF8 uint   ip_ready_event_ptr      // KeSetEvent target — signalled at state 0x0c
+0xC7E byte   adapter_mac[6]          // Adapter hardware MAC
+0xD62 char   adapter_model_str[32]   // e.g. "Xbox Wireless Adapter (MN-740)"
+0xD82 char   adapter_fw_ver_str[32]  // e.g. "1.0.2.26 Boot: 1.3.0.06"
+0xD92 byte   security_caps           // Byte 174 from handshake response
+0xD93 byte   cipher_caps             // Byte 175 from handshake response
+0xE2E byte   best_security_mode      // enc_type: 1=Open, 2=WEP-64, 3=WEP-128, 4=WPA
+0xF5F uint   auth_algorithm          // 802.11 auth algo (0=Open, 1=SharedKey, 2=WPA)
```

---

### Quirky error handler string

The device has a very funny error handling string as a line from the
three stooges that is common on other dlink products:

"Hey Moe, it dont woik. NYUK NYUK NYUK NYUK"

Any unknown TLV tag sent will print this error on the debug serial port.

## Appendix: Serial CLI Reference

# MN-740 Serial CLI Reference
**Firmware:** v1.0.2.26 | **Source:** Ghidra decompilation of `NML_bin.c` / `NML_bin.h`

---

## 1. Physical Interface

| Parameter | Value |
|-----------|-------|
| Baud rate | 115200 |
| Data bits | 8 |
| Parity | None |
| Stop bits | 1 |
| Flow control | None |

The UART is polled from the main firmware watchdog loop via `UART_CLI_Poll_Handler()`. There is no interrupt-driven input path. Characters are read one at a time by `UART_Get_Char()` / `UART_Is_Data_Available()`.

---

## 2. Session Flow

### 2.1 Login Gate

On the first line received, the CLI is in **password mode** (`g_CLI_Echo_Mode_Flag == 0`). Characters are echoed as `*` rather than the typed character.

The entered string is compared against `G_XPP_Admin_Identity` (loaded from NVRAM at boot). The comparison is a full case-sensitive string match (`util_strcmp`).

**Login bypass:** If `G_XPP_Admin_Identity` is zero-length (i.e. the password field is blank), the login gate is bypassed entirely and the session proceeds directly to command mode. This is the firmware factory state.

On successful authentication the firmware calls `nvram_copy_and_rebuild_serial_str()`, which copies the current NVRAM config into a working buffer and constructs the prompt string.

On failure the error string at `DAT_800bff3c+0x6c` is printed and the login counter `DAT_800c023c` is cleared. There is no lockout or attempt counter.

**Empty line at password prompt:** Sends the password-prompt error message and returns without consuming any state. Does not allow blank-password bypass; the blank-password bypass is determined at string-length check before the compare, not by submitting an empty line.

### 2.2 Command Mode

Once authenticated, the session is in command mode (`g_CLI_Processing_Lock` tracks re-entrancy). The prompt is printed after each command:

```
A.B.C.D>
```

where `A.B.C.D` is the adapter's current IP address (all four octets, derived from `g_XBOX_WIFI_IFACE+0x24`).

An empty line (bare Enter) in command mode re-prints the current menu page and the prompt.

---

## 3. Input Handling

The input buffer starts at `g_Input_Buffer_Start` (RAM address `0x8024bea2`) and is limited to **127 bytes** (ceiling at `0x8024bf21`). Characters beyond the limit are silently discarded.

| Input | Action |
|-------|--------|
| Printable ASCII (0x20–0x7E) | Appended to buffer; echoed (or `*` in password mode) |
| `CR` (0x0D) or `LF` (0x0A) | Terminates line; dispatches to command handler |
| `BS` (0x08) | Destructive backspace — removes last char from buffer, sends `BS SP BS` to terminal |
| `ESC` (0x1B) | Clears entire line buffer; sends `BS SP BS` for each character already buffered; leaves a `0x1B` sentinel in the buffer start byte |
| Any other control character (< 0x20) | Silently ignored |
| Any character > 0x7E | Silently ignored |

---

## 4. Command Dispatch

Commands are tokenised by space. The dispatcher (`net_tx_dispatch_to_interface`) walks the command table registered for the current menu page, comparing the first word of input against each entry using `util_strncmp_word_boundary()` (word-boundary aware, stops at space or NUL). The first match wins.

`?` is a reserved input: it prints the current menu page's help listing (all command names and descriptions) without entering any handler.

Unknown input prints:
```
Unknown command: <input>
```

---

## 5. Menu Page System

The CLI is paged. Each menu page has its own command table. The current page index is stored in the session state at offset `+0x14`; the previous page at `+0x10`. Navigation commands manipulate these fields directly.

| State Index | Page |
|-------------|------|
| 0 | Top / login gate |
| 2 | Setup wizard |
| 3 | LAN settings |
| 5 | IP address entry |

---

## 6. Command Reference

### 6.1 Navigation

**`?`**
Prints the command list for the current menu page. Not dispatched through the command table; handled inline in the poll loop.

**`setup`** — handler: `cli_state_advance_setup_step`
Advances to the setup wizard (sets page state to 2). Does not take arguments.

**`lan`** — handler: `CMD_HANDLER_LAN_SETTINGS`
Navigates to the LAN settings sub-menu (sets page state to 3).

**`back`** — handler: `CMD_HANDLER_BACK_TO_PREVIOUS_PAGE`
Returns to the previous menu page (restores state from `+0x10`).

**`logout`** — handler: `CMD_HANDLER_LOGOUT_CONSOLE_MODE_WITHOUT_SAVE`
Returns the session to the login gate (sets `param_1[1] = 0`) without saving any pending changes. Config working buffer is discarded.

---

### 6.2 Status / Display

**`show`** — handler: `CMD_HANDLER_SHOW_CURRENT_STATION_SETUP`
Iterates all registered network interfaces and prints for each:
- Interface name
- MAC address (formatted with `-` separator)
- IP address
- Subnet mask
- Gateway

**`stats`** — handler: `cli_dump_packet_queue_stats`
Dumps TX/RX packet queue counters from the internal packet descriptor ring.

---

### 6.3 Network Configuration

**`ip <address>`** — handler: `cli_cmd_set_ip_address`
Sets the adapter IP address. The argument is a dotted-decimal IPv4 string. The address is validated by `NET_Parse_IP_Address()`; invalid input prints an error without modifying state. The new IP is written to the NVRAM working buffer (`DAT_800c3b0c`) but is **not** saved to flash automatically. A reboot or explicit save is required to persist.

Example:
```
192.168.1.100> ip 192.168.2.252
```

**`interface <n | name>`** — handler: `cli_cmd_select_interface`
Selects the active interface for subsequent commands. Accepts either a 1-based numeric index or an interface name string. If the index is out of range or the name is not found, an error is printed listing the valid range.

**`dhcp <subcommand>`** — handler: `dhcp_cli_dispatch_subcommand`
DHCP configuration sub-command. The first argument selects the sub-command; see the sub-command table below.

| Sub-command | Action |
|-------------|--------|
| `static-ip <addr>` | Sets static IP |
| `subnet <mask>` | Sets subnet mask |
| `gateway <addr>` | Sets default gateway |
| `dns1 <addr>` | Sets primary DNS server |
| `dns2 <addr>` | Sets secondary DNS server |
| `lease-time <seconds>` | Sets DHCP lease time |
| `pool-start <addr>` | Sets DHCP pool start address |
| `pool-end <addr>` | Sets DHCP pool end address |
| `wins <addr>` | Sets WINS server |
| `reservation` | Configures address reservation |

Entering `dhcp` with no argument or with an invalid sub-command prints:
```
1:DHCP client  2:Fixed IP
```

---

### 6.4 System

**`password [<string>]`** — handler: `CMD_HANDLER_SET_SYSTEM_PASSWORD`
Sets the CLI/admin password. The new password is written to both `DAT_800c3869` and `G_XPP_Admin_Identity` (the same field used by TLV tag `0x03` in the XPP protocol). After saving to flash, the device **reboots immediately**.

Constraints:
- Minimum length: 1 character
- Maximum length: 16 characters
- Calling `password` with no argument clears the password (sets it to zero-length, re-enabling the login bypass)

**`factory`** — handler: `CMD_HANDLER_RESTORE_FACTORY_DEFAULT_AND_REBOOT`
Calls `Flash_Commit_Settings()` then `CFG_Save_To_Flash()` then triggers a reboot. Restores all NVRAM fields to firmware defaults. This is a destructive, immediate operation with no confirmation prompt.

**`ping <host>`** — handler: `cli_cmd_ping`
Initiates an ICMP echo session to the specified host. The host argument is parsed as a dotted-decimal IP address or hostname. `ping` is also invoked internally by the DHCP gateway reachability check and is not exclusively a CLI command.

**`mem <address>`** — handler: `cli_cmd_memory_dump`
Dumps memory starting at the given hex address. There is no confirmed write counterpart in the command table for this firmware build.

---

### 6.5 Stub Handler

Any command entry that is registered in the table but has no implemented handler is routed to `STUB_Stooges_Error_Handler`, which prints:

```
Hey Moe, it dont woik. NYUK NYUK NYUK NYUK
```

This is a development-era placeholder. The same string is output on unknown TLV tag receipt in the XPP packet handler.

---

## 7. Password and Identity Relationship

The CLI password field (`G_XPP_Admin_Identity`) is the same NVRAM field that the XPP protocol exposes via TLV write tag `0x03`. Setting the password via the CLI and setting it via an XPP Type 0x02 / sub-command 0x07 write to tag `0x03` are equivalent operations on the same storage.

The separate field `G_XPP_Identity_Password` (loaded into `DAT_800cec48` at boot) is the HMAC/identity credential used by the TFTP firmware-upload authentication path, not the serial CLI login.

---

## 8. Boot Output on Serial

The following lines appear on the serial port during boot, before the CLI becomes interactive:

```
LOG_SYSTEM_STARTED
wlan0 started
<fw_ver> Boot: <boot_ver>          e.g.  1.0.2.26 Boot: 1.3.0.06
Set wlan0 radio frequency <MHz>
Initializing 802.11g(A) Interface...
```

After the boot sequence completes, the device is in login-gate state. The serial port does not print a login prompt unprompted; the prompt only appears after the first Enter keystroke.

---

## 9. Limitations and Notes

- **No command history.** There is no up-arrow recall; the input buffer is cleared after each line.
- **No tab completion.** The dispatcher does not implement partial-match expansion.
- **No debug command in release build.** The strings `DEBUG` and `Not debug build` exist in ROM but no corresponding command handler is registered in this firmware version.
- **`g_CLI_Processing_Lock` is not re-entrant.** If a command handler triggers a re-entrant call to the CLI poll loop (e.g. via an internal ping), the lock prevents the second call from processing input.
- **MIB dump commands** (`icmp`, `ip`, `udp`, `tcp`, `arp`) are present as `cli_output_log` call sites in the source but their command-table registrations were not confirmed in this analysis pass. They may be available on specific menu pages only.


---

### Footer
**All reverse engineering was based on the mn740 firmware version v1.0.2.21 with some WGA54G specific additions**
**All supplementary reverse engineering was based on xonlinedash.xbe from dash 5960**
**Captures and initial fuzzing was done using custom tooling**
**Live firmware update capture using MSBNUpdate.exe (capture not published) — MSBNUpdate.exe against real MN-740 hardware**
**MSBNUpdate.exe analysis: string extraction from official Microsoft update binary**
**BBN discovery protocol: firmware-verified from NML_bin.c decompile + BBN_Handle_Discovery_Task and BBN_Init_Sockets assembler (MIPS)**
**Disassembly was done using Ghidra v12.0.4**
**Some automated Disassembly work was done by Claude.AI attached to Ghidra MCP on xonlinedash.xbe after hand reverse engineering of mn740 and manual creation**
**Signed off by Jonathan Brophy — Professor_jonny@hotmail.com**
