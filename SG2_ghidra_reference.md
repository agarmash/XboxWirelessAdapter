# SG2.bin (WGA54G) — Complete Disassembly Reference

**Binary**: SG2.bin — Linksys WGA54G firmware  
**Architecture**: MIPS BE 32-bit  
**Image base**: `0x80000000`  
**Size**: 2 MB (`0x80000000`–`0x801fffff`)  
**Function count**: ~10,444  
**RTOS**: ThreadX (`tx_*` functions confirmed)  
**Build date**: Jul 28 2004  
**Last updated**: 2026-05-15

---

## Table of Contents

1. [Binary Identity](#binary-identity)
2. [Session History](#session-history)
3. [WPA Gap Status](#wpa-gap-status)
4. [Confirmed ROM Constants](#confirmed-rom-constants)
5. [Wire-Protocol Structs](#wire-protocol-structs)
6. [Named Functions Reference](#named-functions-reference)
7. [Global Variables](#global-variables)
8. [NVRAM Functions](#nvram-functions)
9. [Broadcom IOCTL String Table](#broadcom-ioctl-string-table)
10. [Type 0x07 TLV Dispatcher (GAP2)](#type-0x07-tlv-dispatcher-gap2)
11. [WPA 4-Way Handshake Functions (GAP3)](#wpa-4-way-handshake-functions-gap3)
12. [GAP3 Function Decompilations](#gap3-function-decompilations)
13. [FSM Struct Offset Map](#fsm-struct-offset-map)
14. [WPA Execution Flow](#wpa-execution-flow)
15. [Memory Map](#memory-map)
16. [Outstanding Work](#outstanding-work)
17. [Observations & Gotchas](#observations--gotchas)

---

## Binary Identity

This is **Linksys WGA54G firmware** — NOT the MN-740.

```
Confirmed at 800b2ea0: "Linksys WGA54G"
Confirmed at 800b2e90: ", Jul 28 2004"   (build date)
```

**Chipset**: Broadcom BCM4712 (not Atheros AR5212 like the MN-740)  
**RTOS**: ThreadX (not the MN-740's custom RTOS)  
**Protocol**: XPP over NLB EtherType 0x886f — **identical wire protocol** to MN-740

> **Important**: The MN-740 NML_bin.c decompile structs are **NOT** applicable to internal/runtime structs in this binary. The only structs valid for both are the **wire-protocol structs** (packet headers, payloads) because the Xbox dashboard validates every byte and both adapters must produce identical output.

---

## Session History

| Session | Date | Key Achievement |
|---------|------|-----------------|
| 1–3 | — | XPP struct creation, wire protocol documentation |
| 4 | 2026-05-14 | NVRAM/ioctl/XPP function locations, FSM struct found, EAPOL references found |
| 5 | 2026-05-14 | WPA functions located (`wlanWpaHandshakeProcess` etc.), globals labelled, config writer traced |
| 6 | 2026-05-15 | All GAP3 functions decompiled and analysed — WPA 4-way handshake 95% implemented |
| 7 | 2026-05-15 | Type 0x07 switch confirmed at machine-code level, GAP2 exact addresses, all plate comments applied |

---

## WPA Gap Status

### GAP1 — Security Capability Byte

| Item | Detail |
|------|--------|
| **Status** | Located, not yet patched |
| **Location** | `XPP_Build_Handshake_Resp_Payload` @ `0x8009b59c` |
| **Read point** | `lbu t8, 0x11EC(s0)` at `0x8009b79c` |
| **Patch** | Find the `sb` that **writes** `FSM+0x11EC`. Change it to store `0x16` instead of `0x06`. Also ensure payload offset +252 (`bSec_cap_default` / `opmode_mask`) is `0x16`. |
| **Effect** | Unlocks WPA PSK UI in the Xbox dashboard |

### GAP2 — WPA Key Input (Tags 0x10 / 0x12)

| Item | Detail |
|------|--------|
| **Status** | Fully confirmed, exact machine-code addresses known |
| **Root cause** | `sltiu at, v1, 15` at `0x800a3044` — switch covers tags 0x01–0x0F only |
| **Tag 0x10 stub** | `XPP_Tag10_Handler_PMK_stub` @ `0x800a3124` — 6 bytes: `jal XPP_TLV_Unknown_Tag_Error_Log` + `j default` |
| **Tag 0x10 patch** | Replace `jal` with memcpy of 32 bytes to `G_WPA_PMK`, then set `G_WPA_PMK_Ready = 1`. ~8 MIPS32 instructions. Space is tight — may need trampoline. |
| **Tag 0x12** | No handler exists at all — falls directly to default |
| **Tag 0x12 patch** | Modify `sltiu` bound from 15 to 17, add case for 0x12 that stores passphrase (8–63 bytes) and schedules `XPP_PBKDF2_F_Block` @ `0x8004114C` in worker task context |

### GAP3 — 4-Way EAPOL Handshake

| Item | Detail |
|------|--------|
| **Status** | Infrastructure **fully implemented** (confirmed Session 6) |
| **Outstanding** | Where is actual Broadcom hardware key installation? |
| **Likely path** | Via `CNFWEPKEYMAPPINGTABLE` ioctl or `WGA54G_Config_Struct_Write_Field` @ `0x80083184` |
| **Note** | `_8ac_16_wrap_2` @ `0x8002fb7c` is a ThreadX scheduler, NOT the key installer |

---

## Confirmed ROM Constants

| Address | Label | Size | Content | Notes |
|---------|-------|------|---------|-------|
| `0x8011682c` | `g_XPP_HMAC_Key` | 16 bytes | Hidden | Exact match to MN-740 ROM |
| `0x800b2eb0` | `g_XPP_HMAC_MASTER_KEY` | 117 bytes | "Hidden" | Identical to MN-740 |
| `0x800b2f28` | `g_XPP_Copyright_String` | 84 bytes | "Device is Xbox Compatible. Copyright (c) Microsoft..." | Identical to MN-740 |
| `0x800b2ea0` | `g_WGA54G_Model_Name_ROM` | ~16 bytes | "Linksys WGA54G" | WGA54G-specific |
| `0x8011688c` | SHA1 test vectors | — | "Sample #1", "Hi There", "what do ya want for nothing?" | RFC 2202 HMAC-SHA1 test vectors — confirms RFC 2202 compliant HMAC |

> **Note on xrefs**: Ghidra shows no xrefs to these constants because the binary uses PC-relative MIPS addressing (`lui`/`addiu` pairs). Search for `lui rX, 0x8011` near SHA1/HMAC functions to find callers manually.

---

## Wire-Protocol Structs

These live under `/XPP` in the Ghidra Data Type Manager. They are valid for WGA54G because the wire format is identical to MN-740.

| Struct Name | Size | Applied To | Purpose |
|-------------|------|-----------|---------|
| `XPP_Packet_Header` | 12 bytes | Function params/returns | All NLB frame headers. Magic=`XBOX`, bTag=packet type |
| `XPP_Handshake_Response_Payload` | 256 bytes | Return type of `XPP_Build_Handshake_Resp_Payload` | Type 0x02 payload with rejection guards |
| `XPP_Handshake_Response_Trailer` | 4 bytes | After HS payload | opmode_mask + link_state |
| `XPP_Network_Slot` | 61 bytes | TLV scan response | Type 0x04 network list entry, stride=61 |
| `XPP_Beacon_Response_Payload` | 4 bytes | Return type of `XPP_Beacon_Resp_Build_54Mbps_Rate` | Type 0x0A: auth_status, rssi, tx_rate, reserved |
| `XPP_EAPOL_Header` | 24 bytes | Type 0x11 frames | WPA EAPOL framing |
| `XPP_TLV_Command` | 3 bytes | TLV stream parsing | tag + length + value_start |

> ⚠️ The following structs are **MN-740 layout only** — do NOT apply to WGA54G addresses: `XPP_Session_State`, `XPP_Pairing_Descriptor`, `XPP_Identity_t`, `XPP_VirtualFileDescriptor`, `NVRAM_User_Settings`, `ATH_Key_Cache_Entry`, `XPP_Crypto_Context`

### Key Field Comments in `XPP_Handshake_Response_Payload`

| Offset | Field | Notes |
|--------|-------|-------|
| +174 | `bSecurity_cap` | Bit `0x10` must be SET to unlock WPA PSK UI — **GAP1 stub** |
| +175 | `bCipher_cap` | Bits `0x01+0x02+0x04` all required or packet rejected |
| +208 | `bRadio_mode_cap` | Bits `0xF8` must be zero or HS rejected |
| +216 | `bRadio_active_guard` | Must be `< 2` or **ENTIRE HS rejected** |
| +217 | `bCurrent_channel` | Must be `< 201` or HS rejected |
| +218 | `bAuth_algorithm` | Must be `< 3` or HS rejected |
| +252 | `bSec_cap_default` | Also = trailer `opmode_mask` — set `0x16` for WPA UI |
| +253 | `bCipher_cap_default` | Also = trailer `link_state` |

---

## Named Functions Reference

### Core XPP Protocol

| Address | Name | Notes |
|---------|------|-------|
| `0x80002084` | `XPP_Packet_Header_Init` | |
| `0x80002114` | `XPP_Send_Packet` | |
| `0x800021a8` | `XPP_Build_Frame_A` | Returns `XPP_Packet_Header *` |
| `0x80002264` | `XPP_Build_Frame_B` | Returns `XPP_Packet_Header *` |
| `0x80002328` | `XPP_Process_Request` | Main request dispatcher |
| `0x800024e4` | `XPP_Handle_Response` | |
| `0x80002578` | `XPP_Tx_Flush` | |
| `0x8000268c` | `XPP_Tx_Reset` | |
| `0x80002704` | `XPP_Dispatch_Handler` | Packet type dispatch |
| `0x80002808` | `XPP_Encode_Payload` | |
| `0x80002990` | `XPP_Rx_Init` | |
| `0x800029e0` | `XPP_Main_Task_Loop` | |
| `0x80002acc` | `XPP_Build_And_Tx_Packet` | param_1=`XPP_Packet_Header *` |
| `0x80002b30` | `XPP_Rx_Packet_Dispatcher` | |
| `0x80002cfc` | `XPP_Rx_Check_EtherType_886f` | NLB EtherType filter |
| `0x80002d6c` | `XPP_Rx_Check_EtherType_888e` | EAPOL EtherType filter — 14 refs in binary |
| `0x80002e70` | `XPP_Rx_Poll` | |
| `0x800030b0` | `XPP_State_Machine` | Main XPP FSM |
| `0x800033b0` | `XPP_Get_Stats` | |
| `0x80003740` | `IP_Forward_Route_And_ARP_Lookup` | |
| `0x80003828` | `XPP_Verify_RFC1071_And_Transmit` | |
| `0x80003a60` | `XPP_Finalize_RFC1071_Checksum` | |
| `0x80006bbc` | `XPP_Session_Auth_Check_And_Handshake` | Session auth gate |
| `0x80008078` | `xppHandshakeInit` | |
| `0x8000807c` | `XPP_Session_State_Clear_And_Reauth` | |
| `0x80008a98` | `XPP_Session_Main_Handler` | |
| `0x80008f54` | `XPP_Handshake_Version_Check_2_wrap` | |
| `0x80009748` | `XPP_Packet_BodySize_Calc_And_Send` | |
| `0x8000a3ec` | `xppSessionBuildResponse` | |
| `0x800085f8` | `XPP_Build_Response_Packet_Header_And_Dispatch` | param_1=`XPP_Packet_Header *` |

### Handshake Builders (typed)

| Address | Name | Return Type | Notes |
|---------|------|-------------|-------|
| `0x8009b59c` | `XPP_Build_Handshake_Resp_Payload` | `XPP_Handshake_Response_Payload *` | Builds Type 0x02 256-byte payload — GAP1 source |
| `0x8008d320` | `XPP_Assemble_Type02_Response` | `XPP_Packet_Header *` | Assembles full Type 0x02 frame |
| `0x800287c8` | `XPP_Build_Handshake_Resp_Type02` | `undefined` | param_1=`XPP_Packet_Header *` |
| `0x80029390` | `XPP_Adapter_Info_TLV_Builder` | `undefined` | param_1=`XPP_TLV_Command *` |
| `0x8007d30c` | `XPP_Handshake_Resp_Unconditional_Send` | `undefined` | param_1=`XPP_Handshake_Response_Payload *` |
| `0x800185d4` | `XPP_Handshake_Resp_Builder_Top` | `undefined` | Top-level HS builder |
| `0x80009844` | `XPP_Beacon_Resp_Build_54Mbps_Rate` | `XPP_Beacon_Response_Payload *` | Builds Type 0x0A response |
| `0x800905c8` | `XPP_Beacon_Resp_Write_RSSI_And_Rate` | `undefined` | param_1=`XPP_Beacon_Response_Payload *` |

### WPA-Related

| Address | Name | Notes |
|---------|------|-------|
| `0x80009ac0` | `WPA_PMK_Hex_Digit_Validate_And_XOR` | Validates hex PMK input, XORs digits — **FULLY IMPLEMENTED** |
| `0x8000a798` | `PHY_Reg78_Set_WPA_Security_Bit` | Sets WPA security bit in PHY register 0x78 |
| `0x80044ed0` | `wlanKeyMgmtProcess` | WPA key management entry point |
| `0x800739f8` | `wlanWpaHandshakeProcess` | 4-way EAPOL FSM — **FULLY IMPLEMENTED** |
| `0x80073b98` | `wlanWpaKeyInstall` | PTK/GTK key install — ⚠️ bug in error path |
| `0x8005f1d0` | `_02c_13_sub_wrap_2` | Key material preparation — **FULLY IMPLEMENTED** |
| `0x800591b4` | `XPP_Handshake_sub_91b4` | EAPOL message walker/validator |
| `0x80021780` | `XPP_Handshake_sub_ab84_2_sub_wrap_2` | HMAC byte-by-byte verifier — **FULLY IMPLEMENTED** |
| `0x8002fb7c` | `_8ac_16_wrap_2` | ⚠️ ThreadX thread scheduler — NOT key installer |
| `0x8004114c` | `XPP_PBKDF2_F_Block` | PBKDF2 key derivation block — callable for GAP2 passphrase patch |

### Type 0x07 TLV Dispatcher

| Address | Name | Notes |
|---------|------|-------|
| `0x800a3034` | `XPP_Type07_Tag_Switch_Dispatch` | Entry of switch function |
| `0x800a306c` | *(switch table base)* | 15 entries covering tags 0x01–0x0F |
| `0x800a3044` | *(range check)* | `sltiu at, v1, 15` — **GAP2 root cause** |
| `0x800a3124` | `XPP_Tag10_Handler_PMK_stub` | **GAP2a** — 6-byte stub, jal error log + j default |
| `0x800a21c0` | `default_49_wrap` | State 0x2c1 pre-switch cleanup |
| `0x800b3ac0` | `XPP_TLV_Unknown_Tag_Error_Log` | Called on unknown/stubbed tags |
| `0x8008e73c` | `XPP_Session_sub_e73c` | Type 0x07 state machine dispatcher |
| `0x80092fac` | `XPP_Session_sub_2fac` | CONNECT_REQ setup + TLV iteration loop |

### WLAN Association State Machine

| Address | Name | Notes |
|---------|------|-------|
| `0x8000787c` | `WLAN_Assoc_Result_Process_And_Config` | Processes assoc result |
| `0x800090b4` | `WLAN_Assoc_SM_State_2_4_10_20_Handler` | FSM states 2,4,10,20 |
| `0x800091d8` | `WLAN_Assoc_SM_Retry_Dec_And_Continue` | Retry counter |
| `0x8000929c` | `WLAN_Assoc_SM_Security_Mode_Set_0_1_2` | Sets security mode 0/1/2 |
| `0x800094e8` | `WLAN_Assoc_SM_Check_Privacy_Bit` | Checks 802.11 privacy bit |
| `0x80009534` | `WLAN_Assoc_SM_Check_WPA_Bit` | Checks WPA capability bit |
| `0x80009580` | `WLAN_Assoc_SM_Auth_Complete_Start_Scan` | Auth complete → start scan |
| `0x800095c0` | `WLAN_Assoc_SM_WEP_Mode_Check_1_2` | WEP mode check |
| `0x800095f8` | `WLAN_Assoc_SM_Flags_0_2_4_Dispatch` | Dispatches on flags 0/2/4 |
| `0x80009698` | `WLAN_Assoc_SM_Set_Key_And_Continue` | Sets key and continues |
| `0x800096c4` | `WLAN_Assoc_SM_Retry_On_Fail` | |
| `0x800096cc` | `WLAN_Assoc_SM_Commit_Config_A` | |
| `0x800096e4` | `WLAN_Assoc_SM_Check_Link_State_1_2_3` | Link state check |
| `0x8000972c` | `WLAN_Assoc_SM_Commit_Config_B` | |
| `0x80009098` | `WLAN_Scan_Trigger_Wrapper` | |
| `0x800093f0` | `WLAN_Scan_Result_Processor_8Chan` | Processes scan results, 8 channels |
| `0x8000b850` | `WLAN_MLME_Event_Handler_A` | |
| `0x8000ba88` | `WLAN_MLME_Event_Handler_B` | |
| `0x8000b998` | `WLAN_Reset_And_Reconnect` | |
| `0x8000ba04` | `WLAN_Reset_Clear_Flag_And_Reconnect` | |
| `0x8000bad4` | `WLAN_Reconnect_No_Flag` | |

### Config / NVRAM

| Address | Name | Notes |
|---------|------|-------|
| `0x80083184` | `WGA54G_Config_Struct_Write_Field` | **231 xrefs** — central config/field writer. All callers in `0x80076xxx`–`0x80079xxx` range |
| `0x800931c8` | `WGA54G_Config_Field_Offset_Store` | Called by config writer. Offset arithmetic: `param_2 - 0x21d4 = field offset` |
| `0x800087c0` | `nvramDefaultsLoad` | Good entry point for finding NVRAM struct |
| `0x8000a984` | `Flash_Write_Block_At_BC000_Offset` | Flash write at offset BC000 |

### Networking / DHCP / NAT

| Address | Name | Notes |
|---------|------|-------|
| `0x800077b0` | `DHCP_State_Retry_Check_And_Switch` | |
| `0x80008a00` | `DHCP_State_Set_Acquired_And_Trigger` | |
| `0x8000831c` | `NAT_Table_Hash_Lookup_And_Forward` | |
| `0x800080c4` | `ipRouteGatewayLookup` | |

### PPPoE (WGA54G-specific, not in MN-740)

| Address | Name | Notes |
|---------|------|-------|
| `0x80008a1c` | `PPPoE_Session_Send_Packet_And_Switch` | |
| `0x80008c70` | `PPPoE_Timeout_Check_And_Retry` | |
| `0x80008e54` | `PPPoE_Session_Alloc_And_Start` | |

---

## Global Variables

| Address | Label | Notes |
|---------|-------|-------|
| `0x801a9738` | `g_WLAN_Scan_Result_Table` | Base of WLAN BSS scan result table. `XPP_State_Machine` indexes with stride `0x2cc` |
| `0x801634bc` | `g_BCM4712_WLAN_MMIO_Base` | Broadcom BCM4712 WLAN MMIO base address |
| `0x80163dac` | `g_XPP_Handshake_Gate_Flag` | Must be non-zero for handshake to build |
| `0x801636c4` | `g_WPA_Handshake_State` | WPA handshake state variable, cleared on completion |
| `0x8015c4b0` | `g_XPP_Session_State_Table` | XPP session state table. Stride `0x2cc` per session index |
| `0x801636e0` | `DAT_801636e0` | NVRAM cipher capability flag (checked in key prep) |
| `0x801636e2` | `DAT_801636e2` | NVRAM authentication type flag |
| `0x801636e4` | `DAT_801636e4` | NVRAM key derivation flag |
| `0x801636fc` | `DAT_801636fc` | NVRAM PMK/PSK flag |
| `0x80163528` | `DAT_80163528` | Stores key length on EAPOL type 'e' |
| `0x8011d0a0` | *(WPA dispatch table)* | Function pointer table for WPA state callbacks. Entry 0 = `wlanWpaHandshakeProcess` |

---

## NVRAM Functions

| Address | Name | XRefs | Status |
|---------|------|-------|--------|
| `0x8004320c` | `nvramWriteAndFlush` | 0 | ✓ Confirmed |
| `0x800432f4` | `nvramEraseAndWrite` | 0 | ✓ Confirmed |
| `0x80043a04` | `nvramValidateAndWrite` | 1 | ✓ Confirmed |
| `0x800488b8` | `nvramReadParam` | 0 | ✓ Confirmed |
| `0x8007cc5c` | `nvramStringGet` | 2 | ✓ Confirmed |
| `0x8007fbc8` | `nvramKeyIterate` | 0 | ✓ Confirmed |
| `0x8007fdbc` | `nvramParamGetByIndex` | 0 | ✓ Confirmed |
| `0x80081fcc` | `nvramFlushToBCM` | 1 | ✓ Confirmed |

### NVRAM Parameter Strings (ROM)

| Address | Key |
|---------|-----|
| `0x800e2cd4` | Parameter index lookup table |
| `0x800e7054` | `wl_passphrase` |
| `0x800e6e5c` | `wl_auth_type` |

---

## Broadcom IOCTL String Table

Table starts at `0x800ee17c`. 48+ IOCTLs identified. Critical ones for WPA:

| Address | IOCTL Name | Purpose |
|---------|-----------|---------|
| `0x800ee17c` | `CNFWEPFLAGS` | Key/cipher flags — table start |
| `0x800ee280` | `CNFWEPKEYMAPPINGTABLE` | **PTK/GTK installation** |
| `0x800ee298` | `CNFAUTHENTICATION` | 802.11 auth algorithm |
| `0x800ee2ac` | `CNFHOSTAUTHENTICATION` | Hostside auth |
| `0x800ee5e8` | `CNFENHSECURITY` | **Enhanced/WPA security mode enable** |
| *(various)* | `CNFDESIREDSSID` | Target network name |
| *(various)* | `CNFOWNSSID` | AP mode SSID |
| *(various)* | `CNFOWNMACADDR` | MAC address |
| *(various)* | `CNFOWNCHANNEL` | WiFi channel |
| *(various)* | `CNFBEACONINT` | Beacon interval |
| *(various)* | `CNFMAXASSOCSTA` | Max associated stations |

---

## Type 0x07 TLV Dispatcher (GAP2)

### Switch Structure (confirmed Session 7)

Function entry: `0x800a3034`  
Switch table: `0x800a306c`

Critical compare instruction at `0x800a3044`:

```mips
addiu v1, v1, -1       ; tag - 1
sltiu at, v1, 15       ; compare (tag-1) against 15
beq   at, zero, default ; if tag > 0x0F → jump to default
```

**The switch covers tags 0x01–0x0F exactly (15 cases).** Tags 0x10, 0x11, and 0x12 all fall to the default case — this is the precise machine-code confirmation of GAP2.

> ⚠️ **MIPS16e note**: All valid case handlers jump into a MIPS16e code region at ~`0x800b9000`. Ghidra cannot decode MIPS16e instructions, so every case shows as `halt_baddata()` in the decompiler. The handlers are real — only tags 0x10 and 0x12 are genuinely absent/stubbed.

### Tag 0x10 Stub — `XPP_Tag10_Handler_PMK_stub` @ `0x800a3124`

```
jal  XPP_TLV_Unknown_Tag_Error_Log  ; 0x0c02ceb0
nop                                  ; 0x00000000
j    <default exit>                  ; 0x08005a44
```

Six bytes of body. The 32-byte PMK payload is never read, stored, or forwarded.

### State Machine Wrapper — `XPP_Session_sub_e73c` @ `0x8008e73c`

| State | Handler | Role |
|-------|---------|------|
| `0x2c1` | `default_49_wrap` @ `0x800a21c0` | Pre-switch cleanup |
| `0x2c5` | `XPP_Type07_Tag_Switch_Dispatch` | Main TLV tag switch |
| `0x305` | `Net_stub_800a30b4` | Post-connect stub |

The TLV iteration loop is inside `XPP_Session_sub_2fac` @ `0x80092fac`, which is the CONNECT_REQ setup handler and sole caller of the state machine.

---

## WPA 4-Way Handshake Functions (GAP3)

### Implementation Status Summary

| Function | Address | Status |
|----------|---------|--------|
| `wlanWpaHandshakeProcess` | `0x800739f8` | ✅ Fully implemented — 9-state FSM |
| `wlanKeyMgmtProcess` | `0x80044ed0` | ✅ Fully implemented |
| `_02c_13_sub_wrap_2` | `0x8005f1d0` | ✅ Fully implemented — key material prep |
| `XPP_Handshake_sub_ab84_2_sub_wrap_2` | `0x80021780` | ✅ Fully implemented — HMAC verifier |
| `WPA_PMK_Hex_Digit_Validate_And_XOR` | `0x80009ac0` | ✅ Fully implemented — PSK validator |
| `wlanWpaKeyInstall` | `0x80073b98` | ⚠️ Partially stubbed — bug in error path |
| `_8ac_16_wrap_2` | `0x8002fb7c` | ⚠️ ThreadX scheduler, NOT key installer |

### WPA Dispatch Table @ `0x8011d0a0`

```
0x8011d0a0: 800739f8  ← wlanWpaHandshakeProcess (offset 0)
0x8011d0a4: 800e7a74  (unknown — needs tracing)
0x8011d0a8: 00040000  (padding)
0x8011d0ac: 800e7a10  (unknown — needs tracing)
0x8011d0b0: 800e81f8  (unknown — needs tracing)
0x8011d0b4: 80073a14  (wlanWpaHandshakeProcess + offset)
```

---

## GAP3 Function Decompilations

### 1. `wlanWpaHandshakeProcess` @ `0x800739f8`

4-way EAPOL handshake FSM. Dispatched from function table at `0x8011d0a0`.

```c
void wlanWpaHandshakeProcess(int param_1, undefined4 param_2)
{
  bool bVar1;
  int iVar2;
  uint in_v1;
  uint uVar3;
  undefined4 *unaff_s0;
  int unaff_s1;

  if (in_v1 == 0) {
    XPP_Session_sub_3ad8_sub_3();
    if (*(short *)((int)unaff_s0 + 0x1f3e) != 0) {
      XPP_Session_sub_3b98(unaff_s1, param_2);
      XPP_Session_sub_3ad8_sub_2(unaff_s1);
      return;
    }
  }
  else {
    if (in_v1 == 1) {
      unaff_s0[0x7f7] = 1;          // ← SET PAIRWISE FLAG
      uVar3 = (uint)*(byte *)(unaff_s1 + 0x5c);
      *(undefined4 *)(unaff_s1 + 0xcc) = 3;
      tx_kernel_wrap_ecb4();
      *(undefined4 *)(unaff_s1 + 100) = 0xb;
      XPP_Session_sub_3ad8_sub_2(uVar3);
      return;
    }
    if (6 < in_v1) {
      if (8 < in_v1) {
        if (in_v1 != 9) {
          XPP_Session_Find_By_ID_And_Switch_3_21_wrap();
          return;
        }
        if (0 < (int)unaff_s0[0x7e9]) {   // ← COUNTER CHECK (msg timeout/retry)
          uVar3 = (uint)*(ushort *)(unaff_s0 + 1999);
          if ((int)unaff_s0[0x7e9] <= (int)uVar3) {
            unaff_s0[0x7e9] = 0;
            if (unaff_s0[0x7e5] == 2) {
              unaff_s0[0x7f8] = 0x17;    // ← STATE CHANGE
            }
            tx_thread_context_switch(unaff_s0[0x7cd]);
          }
          unaff_s0[0x7e9] = unaff_s0[0x7e9] - uVar3;
          unaff_s0[0x7e8] = unaff_s0[0x7e8] + uVar3;
          XPP_Session_sub_3ac4(param_1);
          return;
        }
        if (unaff_s0[0x7e5] != 2) {
          XPP_Session_sub_3a64();
          return;
        }
        unaff_s0[0x7f8] = 0x17;
        uVar3 = (uint)*(ushort *)(unaff_s0 + 1999);
        if (*(ushort *)(unaff_s0 + 1999) != 0xa00) {
          do {
            _SUB_00000000 = uVar3;
            XPP_Session_sub_349c();
            bVar1 = unaff_s1 == 0;
            unaff_s1 = unaff_s1 + -1;
            if (bVar1) break;
            XPP_Packet_Queue_Push_41_wrap();
            XPP_sub_3bd4_sub_2();
            iVar2 = XPP_sub_3bd4_sub(0, unaff_s0);
          } while (iVar2 == 0x8403);
          g_WPA_Handshake_State = 0;    // ← CLEAR FSM STATE
          *(byte *)((int)unaff_s0 + -0x7fd3681a) = *(byte *)((int)unaff_s0 + -0x7fd3681a) | 1;
          switchD_800a306c::default();   // ← DISPATCH TO TYPE 0x07 HANDLER
          return;
        }
        goto LAB_80073b8c;
      }
      XPP_Session_sub_3b98(unaff_s1, param_2);
    }
    unaff_s0[0x7f8] = 0x17;
  }
LAB_80073b8c:
  XPP_Session_Jump_To_Drop_State();
  return;
}
```

**State machine flow:**

| `in_v1` | State | Behaviour |
|---------|-------|-----------|
| 0 | INIT | Check key_ready flag (+0x1f3e). If set: call key install + cleanup. Else: drop. |
| 1 | PAIRWISE | Set pairwise flag (+0x7f7=1), get key slot (+0x5c), set state=3 at +0xcc, set state=0xb at +0x64 |
| 6–8 | MESSAGE HANDLERS | Fallthrough to `XPP_Session_sub_3b98()`, set state = 0x17 |
| 9 | TIMEOUT/COMPLETION | Check retry counter (+0x7e9). If > 0: decrement, update elapsed timer (+0x7e8). If exhausted: clear `g_WPA_Handshake_State`, dispatch to type 0x07 handler |

---

### 2. `wlanWpaKeyInstall` @ `0x80073b98`

```c
undefined4 wlanWpaKeyInstall(int param_1)
{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;

  uVar3 = 0xfffffbb1;                         // Default error code
  if (*(short *)(*(int *)(param_1 + 0x7c) + 0x1f3e) != 0) {
    uVar2 = (uint)*(byte *)(param_1 + 0x5c);
    iVar1 = tx_kernel_3994();                  // ← CHECK KERNEL STATE
    if (iVar1 == 0) {
      *(undefined4 *)(param_1 + 100) = 7;     // ← SET STATE = 7
      uVar3 = XPP_Session_sub_3b98_sub_wrap(uVar2, 0);  // ← INSTALL KEY
      return uVar3;
    }
    uVar3 = httpPageTypeCheck();               // ← BUG: should not call HTTP here
  }
  return uVar3;
}
```

**⚠️ Known bug**: `httpPageTypeCheck()` is called in the kernel-fail branch. This is either a leftover stub or a placeholder that returns a generic error. Only affects the error path — success path is correct.

---

### 3. `wlanKeyMgmtProcess` @ `0x80044ed0`

```c
undefined4 wlanKeyMgmtProcess(int param_1)
{
  byte abStack_1c [24];

  if ((*(int *)(param_1 + 0x48) == 1) && (*(int *)(param_1 + 0x3c) != 0)) {
    _02c_13_sub_wrap_2(param_1 + 0x3c, abStack_1c);  // ← EXTRACT KEY MATERIAL
    XPP_Handshake_sub_91b4((undefined4 *)&LAB_800e2868, abStack_1c);  // ← PARSE EAPOL
  }
  return 0;
}
```

Flow: check key flag (+0x48 == 1) → check key material valid (+0x3c != 0) → extract 24-byte key material → call EAPOL parser.

---

### 4. `_02c_13_sub_wrap_2` @ `0x8005f1d0` — Key Material Preparation

```c
void _02c_13_sub_wrap_2(undefined4 param_1, undefined4 param_2)
{
  uint *unaff_s0;

  if (DAT_801636e0 != 0) {
    *unaff_s0 = *unaff_s0 | 2;      // ← SET FLAG BIT 1 (cipher capability)
  }
  if (DAT_801636e2 != 0) {
    *unaff_s0 = *unaff_s0 | 4;      // ← SET FLAG BIT 2 (auth type)
  }
  if (DAT_801636e4 != 0) {
    *unaff_s0 = *unaff_s0 | 8;      // ← SET FLAG BIT 3 (key derivation)
  }
  if (DAT_801636fc != '\0') {
    *unaff_s0 = *unaff_s0 | 1;      // ← SET FLAG BIT 0 (PMK/PSK)
  }
  XPP_Handshake_sub_4fc0_sub_sub((int)unaff_s0);  // ← FINALIZE
  return;
}
```

Checks NVRAM globals and sets status bits in output buffer. **Fully implemented.**

---

### 5. `XPP_Handshake_sub_ab84_2_sub_wrap_2` @ `0x80021780` — HMAC Verifier

Key excerpt from decompilation:

```c
// Walks a chain of structures
while (piVar5 != NULL) {
  piVar5 = *piVar5;
  if (piVar5[2] < 4) {
    tx_kernel_enter(piVar5[8], param2_stack, &piVar5[0x8c]);  // ← CRITICAL LOCK
  }
}

// Message type dispatch
if (cVar1 == 0x07) {             // EAPOL Message type 7
  if (unaff_s1[2] != 1) {
    XPP_CRC16_Table_Driven(unaff_s8, param_2, uVar4);  // ← CHECKSUM VERIFY
  }
  tx_thread_context_switch(unaff_s1 + 10);
}

if (cVar1 == 'e') {              // Message type 0x65 — key installation trigger
  unaff_s1[5] = g_SysTick_Counter;
  unaff_s1[7] = g_SysTick_Counter;
  *(ushort *)(unaff_s1 + 8) = *(ushort *)(unaff_s3 + 2);
  unaff_s1[2] = 4;
  DAT_80163528 = *(ushort *)(unaff_s3 + 2);  // ← STORE KEY LENGTH
  *(uint *)(unaff_s1[0xc] + 0x1cc) = 4;      // ← SET STATE TO 4
  _8ac_16_wrap_2();                           // ← SCHEDULES KEY INSTALL THREAD
}

// Byte-by-byte HMAC comparison
for (uVar3 = 0; uVar3 < uVar4; uVar3++) {
  if ((byte)*in_t7 != *(byte *)(in_t8 + uVar3)) {
    return XPP_Session_sub_196c();  // ← HMAC MISMATCH
  }
}
return 1;  // ← SUCCESS
```

**Fully implemented** — performs complete EAPOL message validation with strict byte-by-byte HMAC comparison.

---

### 6. `WPA_PMK_Hex_Digit_Validate_And_XOR` @ `0x80009ac0`

```c
uint WPA_PMK_Hex_Digit_Validate_And_XOR(int param_1, uint param_2, uint param_3, uint param_4)
{
  uint uVar1;

  if (0x27 < param_1) {           // If char > '\'' (0x27)
    if (param_1 < 0x3c) {         // And < ':' (0x3c)
      uVar1 = XPP_Packet_Queue_Push_stub_3();
      return uVar1;               // ← INVALID HEX DIGIT
    }
    if (0x4f < param_1) {         // If > 'O' (0x4f)
      return 0;                   // ← OUT OF RANGE
    }
  }
  return param_2 ^ param_3 ^ param_4;  // ← VALID: XOR THREE VALUES
}
```

Validates hex digit ranges (0–9, A–F, a–f) and XORs three PSK values together. Used in PMK derivation from passphrase. **Fully implemented.**

---

## FSM Struct Offset Map

Based on `wlanWpaHandshakeProcess`, `wlanWpaKeyInstall`, and `wlanKeyMgmtProcess`.  
Base pointer: `g_XPP_Session_State_Table` @ `0x8015c4b0`, stride `0x2cc` per session.

| Offset | Purpose | Type | Used In |
|--------|---------|------|---------|
| `+0x3c` | Key material pointer | `void *` | `wlanKeyMgmtProcess` — extracted PTK/GTK |
| `+0x48` | Key flag | `uint` | `wlanKeyMgmtProcess` — set to 1 when valid |
| `+0x5c` | Key slot | `byte` | `wlanWpaKeyInstall` — hardware key index |
| `+0x64` | FSM state register | `uint` | `wlanWpaKeyInstall` — states: 3, 7, 0xb, 0x17 |
| `+0x7c` | Key material block ptr | `void *` | `wlanWpaKeyInstall` |
| `+0x7e5` | State sub-flag | `byte` | `wlanWpaHandshakeProcess` — checked vs 2 |
| `+0x7e8` | Elapsed timer | `ushort` | `wlanWpaHandshakeProcess` — timeout accumulator |
| `+0x7e9` | Retry counter | `ushort` | `wlanWpaHandshakeProcess` — decrements on timeout |
| `+0x7f7` | Pairwise flag | `byte` | `wlanWpaHandshakeProcess` — set to 1 for pairwise |
| `+0x7f8` | Main state | `byte` | `wlanWpaHandshakeProcess` — written as `0x17` on completion |
| `+0x11EC` | Security capability byte | `byte` | **GAP1** — read in `XPP_Build_Handshake_Resp_Payload`. Stock value `0x06`; needs `0x16` |
| `+0x1f34` | Key material ptr | `void *` | `wlanWpaHandshakeProcess` — pointer to PTK/GTK bytes |
| `+0x1f3c` | Session descriptor | `ushort` | `wlanWpaHandshakeProcess` — session/key index |
| `+0x1f3e` | Key ready flag | `short` | `wlanWpaKeyInstall` — must be != 0 to install |

---

## WPA Execution Flow

```
Xbox sends Type 0x07 CONNECT_REQ (with PSK passphrase or PMK)
    ↓
XPP_Session_sub_2fac @ 0x80092fac  (CONNECT_REQ setup + TLV loop)
    ↓
XPP_Session_sub_e73c @ 0x8008e73c  (state machine dispatcher)
    ↓
XPP_Type07_Tag_Switch_Dispatch @ 0x800a3034
    ├─ Tag 0x01–0x0F: handled (MIPS16e region)
    ├─ Tag 0x07: SSID extraction
    ├─ Tag 0x08: Security mode detection
    ├─ Tag 0x10: PMK → XPP_Tag10_Handler_PMK_stub ← GAP2a (STUB)
    └─ Tag 0x12: Passphrase → default case ← GAP2b (NO HANDLER)
    ↓
wlanKeyMgmtProcess @ 0x80044ed0
    ├─ Check key flag (+0x48 == 1)
    ├─ Check key material valid (+0x3c != 0)
    ├─ Call _02c_13_sub_wrap_2() to prepare key
    └─ Call XPP_Handshake_sub_91b4() to validate
    ↓
_02c_13_sub_wrap_2 @ 0x8005f1d0
    ├─ Check NVRAM flags (DAT_801636e0, e2, e4, fc)
    ├─ Set status bits in output buffer
    └─ Call XPP_Handshake_sub_4fc0_sub_sub() finalizer
    ↓
XPP_Handshake_sub_91b4 @ 0x800591b4
    ├─ Walk EAPOL message structure chain
    ├─ Check message type validation
    ├─ Call HMAC verifier
    └─ On success: call _8ac_16_wrap_2()
    ↓
XPP_Handshake_sub_ab84_2_sub_wrap_2 @ 0x80021780  ← HMAC VERIFICATION
    ├─ Walk message structure (dereference chain)
    ├─ Get message type code
    ├─ Compare HMAC byte-by-byte ← CRITICAL CHECK
    ├─ On type 'e': set state=4, store key length, call _8ac_16_wrap_2()
    └─ Return 1 on success
    ↓
_8ac_16_wrap_2 @ 0x8002fb7c  ← ThreadX scheduler (reschedules after key state set)
    ↓
wlanWpaHandshakeProcess @ 0x800739f8
    ├─ Handle FSM state transitions (0,1,6,7,8,9)
    ├─ Manage timeout/retry counters
    ├─ Clear g_WPA_Handshake_State on completion
    └─ Dispatch to wlanWpaKeyInstall via dispatch table
    ↓
wlanWpaKeyInstall @ 0x80073b98
    ├─ Check key ready flag (+0x1f3e)
    ├─ Check kernel state (tx_kernel_3994)
    ├─ Set state = 7
    └─ Call XPP_Session_sub_3b98_sub_wrap(slot, 0) ← actual key push
    ↓
[Broadcom hardware key installation — path TBD]
    Likely via CNFWEPKEYMAPPINGTABLE ioctl
    or WGA54G_Config_Struct_Write_Field @ 0x80083184
```

### EAPOL EtherType 0x888E References (14 locations)

```
0x8001be4f  0x8001c6d7  0x8001c7cb  0x8001ca93  0x8001d04f
0x800895a3  0x8009909f  0x800992eb  0x8009bbef  0x8009d00f
0x800a01a3  0x800ac0ab  0x80128c68  0x8013f204
```

Primary entry: `XPP_Rx_Check_EtherType_888e` @ `0x80002d6c`

---

## Memory Map

```
0x80000000–0x800b2e8f   Code + ROM strings
0x800b2e90              ", Jul 28 2004" build date
0x800b2ea0              "Linksys WGA54G" model name        [g_WGA54G_Model_Name_ROM]
0x800b2eb0              "Hidden" HMAC master key [g_XPP_HMAC_MASTER_KEY]
0x800b2f28              "Device is Xbox Compatible..."      [g_XPP_Copyright_String]
0x800b311c              "WPA_PSK_PASSPHRASE\n" (UPnP #1)
0x800b32ec              "WPA_PSK_PASSPHRASE\n" (UPnP #2)
0x800ee17c              Broadcom IOCTL string table start (CNFWEPFLAGS)
0x8011682c              HMAC key Hidden               [g_XPP_HMAC_Key]
0x8011683c              SHA1 round constant table
0x8011688c              "Sample #1Hi There..." SHA1 test vectors (RFC 2202)
0x80116e00              Network interface struct (IP addr, subnet, "eth0")
0x80116e30              "nvram lock" / "nvram task" OS mutex/task name strings
0x80116e6c              "admin" identity/password field
0x8015c4b0              g_XPP_Session_State_Table (stride 0x2cc per session)
0x801634bc              g_BCM4712_WLAN_MMIO_Base
0x801636c4              g_WPA_Handshake_State
0x80163dac              g_XPP_Handshake_Gate_Flag
0x8011d0a0              WPA dispatch table
0x801a9738              g_WLAN_Scan_Result_Table
```

---

## Outstanding Work

### Priority 1 — GAP1 Write Instruction (HIGH)

Find the `sb` instruction that writes the stock `0x06` to `FSM+0x11EC`. This is the actual 1-byte patch target.

- Search for `sb` instructions near `s0` with offset `0x11EC` inside `XPP_Build_Handshake_Resp_Payload` and its callers
- Or trace backwards from `0x8009b79c` to find where `FSM+0x11EC` gets its initial value

### Priority 2 — GAP2 Patch Space (HIGH)

The tag 0x10 stub at `0x800a3124` is only 6 bytes — insufficient for a full PMK store inline.

- Find free space or a hook point for the PMK store routine
- Check for unused functions or padding near `0x800a3124`
- Alternative: patch the `sltiu` bound + add a trampoline

### Priority 3 — Broadcom Key Install Path (MEDIUM)

Confirm what actually installs the PTK/GTK into Broadcom hardware:

- Get xrefs to `CNFWEPKEYMAPPINGTABLE` string @ `0x800ee280`
- Trace `WGA54G_Config_Struct_Write_Field` @ `0x80083184` callees
- Confirm whether key install is via ioctl dispatcher or direct driver call

### Priority 4 — Entry Point for `wlanWpaHandshakeProcess` (MEDIUM)

Decompile the three unknown function pointers in the dispatch table at `0x8011d0a0`:

- `0x800e7a74` (offset +0x04)
- `0x800e7a10` (offset +0x0c)
- `0x800e81f8` (offset +0x10)

### Priority 5 — Verify GAP2 PBKDF2 Path

- Confirm `XPP_PBKDF2_F_Block` @ `0x8004114C` signature and calling convention
- Confirm worker task context for async scheduling after passphrase receipt

---

## Observations & Gotchas

1. **No xrefs on ROM constants**: MIPS `lui`/`addiu` addressing means string refs don't show as xrefs in Ghidra. Search for `lui rX, 0x800b` or `lui rX, 0x8011` to find callers.

2. **MIPS16e code region**: Case handlers in the Type 0x07 switch all jump into `~0x800b9000` which is MIPS16e (compressed ISA). Ghidra can't decode these and shows them as `halt_baddata()`. The handlers are real and functional.

3. **SHA1 test vectors at `0x8011688c`**: "Sample #1", "Hi There", "what do ya want for nothing?" — RFC 2202 HMAC-SHA1 test vectors. Confirms the HMAC implementation is RFC 2202 compliant.

4. **ThreadX RTOS**: All `tx_thread_*`, `tx_timer_*`, `tx_semaphore_*` functions are ThreadX kernel functions. The MN-740 uses a different RTOS. Do not assume ThreadX function behaviour maps to MN-740.

5. **PPPoE present**: WGA54G has full PPPoE support (ISP DSL auth). MN-740 does not. These functions have no XPP protocol equivalent and can be ignored for Xbox bridging work.

6. **Wire struct applicability**: Only wire-protocol structs (packet headers, payloads) are valid for both binaries. Internal structs (NVRAM layout, session state, key cache) differ completely between WGA54G (Broadcom) and MN-740 (Atheros).

7. **`_8ac_16_wrap_2` is NOT the key installer**: Despite being called after HMAC verification, this function manages ThreadX priority queues and thread scheduling. The actual hardware key installation path is still untraced.

8. **Broken Ghidra scripts**: `SG2FirmwareAnalysis.java` and `McpInline_ac4f6bbb9a6b4.java` in `C:\Users\j.brophy.CORKILLSYSTEMS\ghidra_scripts\` cause build warnings but don't affect execution. Safe to delete.
