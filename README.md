# Xbox Wireless Adapter Communication Protocol

A clean room reverse engineering project of the official `Xbox MN-740 Wireless Bridge`, specifically how it interacts with the Xbox's dashboard. The original goal was to look for a juicy buffer overflow on the Xbox side, but since there weren't any, those results can still be used for educational purposes.

## Contents

This repo currently contains the following bits:
 - A more-or-less working emulator of the wireless adapter, works both with a real Xbox and Xemu;
 - Debug symbols for the `xonlinedash.xbe` version `185ead00 (MD5: 8149654a030d813bcc02a24f39fd3ce9)` in a form of Ghidra XML that I reacreated (or should I say guessed?) in the process.

## Emulator how-to

### Prerequisites:
- A Linux system. The emulator need to be able to open a raw ethernet socket which is possible out of the box in Linux. Windows and macOS may probably require some additional changes;
- A copy of `xonlinedash.xbe` version `185ead00 (MD5: 8149654a030d813bcc02a24f39fd3ce9)`. Some copyrighted material from the dashboard is needed for the emulator to work. Needless to say that I can't distribute it, so it will be extracted from the provided binary.

### Running the emulator:
1. First of all, you need to extract some secrets from the `xonlinedash`. You can do this by running  
`$ python3 extract_secrets.py <path_to_xonlinedash.xbe>`

2. Now you can run the emulator itself:  
`$ sudo python3 emulator.py <network_interface>`  
Superuser privileges are required for opening a raw ethernet socket.  
As for the network interface - for a real Xbox, provide the name of the network adapter connected to same network as the Xbox; for Xemu, bind both Xemu and emulator to the same network interface, `lo` works just fine for this purpose.