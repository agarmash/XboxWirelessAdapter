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
    - the rest of data is the payload.


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
- 16 bytes of auth challenge data;
- 18 bytes of zero padding.

### PACKET_TYPE_HANDSHAKE_RESPONSE
- 20 bytes of auth chalenge response;
- 84 bytes of auth copyright string (no zero termination, the size is fixed);
- 32 bytes of wireless adapter name string (padded with zeroes, no zero termination, the size is fixed);
- 32 bytes of wireless adapter firmware version (padded with zeroes, no zero termination, the size is fixed);
- 51 bytes of yet unknown data;
- 1 byte defining the current SSID length;
- 32 bytes of current SSID string (padded with zeroes, no zero termination, the size is fixed);
- 4 bytes of yet unknown data.

### PACKET_TYPE_BEACON_REQUEST
- 34 bytes of zeroes.

### PACKET_TYPE_BEACON_RESPONSE
- 2 bytes of yet unknown data (probably the current status);
- 32 bytes of zero padding.

TODO add the rest of the info