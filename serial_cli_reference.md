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
