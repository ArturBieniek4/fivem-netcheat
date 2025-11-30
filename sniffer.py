from scapy.all import *
import msgpack
target_ip = "127.0.0.1"

MSG_SERVER_EVENT = 0xFA776e18 # Rage hash for "msgServerEvent"

def parse_client_server_event(payload):
    try:
        offset = 0
        
        # Packet type: 4 bytes, little-endian uint32
        packet_type = struct.unpack('<I', payload[offset:offset+4])[0]
        offset += 4
        
        if packet_type != MSG_SERVER_EVENT:
            return None

        # Event name length: little-endian uint16
        name_len = struct.unpack('<H', payload[offset:offset+2])[0]
        offset += 2
        
        # Event name (null-terminated string)
        event_name_bytes = payload[offset:offset+name_len]
        event_name = event_name_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
        offset += name_len
        
        # MessagePack serialized event data
        event_data_bytes = payload[offset:]
        
        # Try to deserialize MessagePack data
        try:
            event_data = msgpack.unpackb(event_data_bytes)
        except:
            event_data = event_data_bytes.hex()
        
        return {
            'packet_type': hex(packet_type),
            'event_name': event_name,
            'event_data': event_data,
            'raw_event_data': event_data_bytes.hex()
        }
    except Exception as e:
        print(f"Error parsing packet: {e}")
        return None

def is_enet_reliable_command(payload):
    """Checks if this is a reliable command in ENet"""
    if len(payload) < 2:
        return False
    flags = struct.unpack('>H', payload[0:2])[0]
    # first bit - command, second bit - reliable
    return (flags & 0x8000) == 0x8000 or (flags & 0x4000) == 0x4000
    return True

def process_udp_packet(packet):
    """Process UDP packets looking for client->server events"""
    if not packet.haslayer(UDP):
        return
    
    if Raw not in packet:
        return
    
    payload = bytes(packet[Raw].load)
    
    # Skip if packet is too small
    if len(payload) < 12:
        return
    
    # Check if this looks like an ENet reliable command
    if not is_enet_reliable_command(payload):
        return
    
    # Find event name hash in packet
    packet_type_bytes = struct.pack('<I', MSG_SERVER_EVENT)
    if packet_type_bytes not in payload:
        return
    offset = payload.find(packet_type_bytes)
    if offset == -1:
        return
    
    # Extract FiveM packet (from packet type onwards)
    fivem_payload = payload[offset:]
    
    # Parse the event
    result = parse_client_server_event(fivem_payload)
    
    if result:
        print("\n" + "="*60)
        print(f"CLIENT -> SERVER EVENT CAPTURED")
        print("="*60)
        print(f"Source: {packet[IP].src}:{packet[UDP].sport}")
        print(f"Dest: {packet[IP].dst}:{packet[UDP].dport}")
        print(f"Event Name: {result['event_name']}")
        print(f"Event Data: {result['event_data']}")
        print("="*60)

if __name__ == "__main__":
    sniff(filter="udp", iface="Software Loopback Interface 1", prn=process_udp_packet, store=0)
