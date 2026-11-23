# Xbox Wireless Adapter Communication Protocol

A clean room reverse engineering project of the official `Xbox MN-740 Wireless Bridge`, specifically how it interacts with the Xbox's dashboard. The original goal was to look for a juicy buffer overflow on the Xbox side, but since there weren't any, those results can still be used for educational purposes.

![](cover_image.jpg)
![](wpa.jpg)

## Contents

This repo currently contains the following bits:
 - A more-or-less working emulator of the wireless adapter, works both with a real Xbox and Xemu;
 - An  more or less complete [description](communication_protocol.md) of the communication protocol between the console, wireless adapter and the firmware update tool.
 - Debug symbols for the `xonlinedash.xbe` version `185ead00 (MD5: 8149654a030d813bcc02a24f39fd3ce9)` in a form of Ghidra XML.
 - Debug symbols for the `NML.MEM` version `1.0.2.26` (extracted from the mn740Update.exe) in a form of Ghidra XML.
 - A [description](serial_cli_reference.md) of the serial command line interface.
 - Raw debug captures are not published; their findings are summarised in the protocol description above

## Emulator how-to

### Prerequisites:
- A Linux system. The emulator need to be able to open a raw ethernet socket which is possible out of the box in Linux.
 Windows will require additional changes to the emulator to use Npcap with a compatible Python packet manipulation library such as Scapy or pcap-ct, macOS may probably require some additional changes;
- A copy of **one** of the following files:
    - The `xonlinedash.xbe` version `185ead00 (MD5: 8149654a030d813bcc02a24f39fd3ce9)`, **or**;
    - The MN-740 firmware `NLM.MEM` version `01.00.02.0021 (MD5: A9A58ADC4CEAEC337BAAB64F018FBA7F)`. You can obtain this file by:
        1. Downloading the `mn740Update.exe` tool (`MD5: c0ebb3f7fb5794f0952692a0b4922abd`, can be obtained [here](https://archive.org/details/mn740Update));
        2. Running the executable, it will place the file `MN740_01.00.02.0021_RUNTIME.bin` file into the temp directory;
        3. Extracting the file with the WinArj or a similar extraction tool, it will extract the `NLM.MEM` file.

 Note: these files are copyrighted material by Microsoft and are needed for the emulator to work. Needless to say they can't be distributed, so it will be extracted from the binary provided  by the user.

### Running the emulator:

1. First of all, you need to extract some secrets from either the console or the mn-740 firmware update.
You can do this by running  
`$ python3 extract_secrets.py <path_to_file>`


2. Now you can run the emulator itself:  
`$ sudo python3 emulator.py <network_interface>`  
Superuser privileges are required for opening a raw ethernet socket.  
As for the network interface - for a real Xbox, provide the name of the network adapter connected to same network as the Xbox; for Xemu, bind both Xemu and emulator to the same network interface, `lo` works just fine for this purpose.
