from scapy.all import *
import msgpack
from rage_hash import RAGEHash
import gui_communication as gui

supportedEvents = {
'msgServerEvent': RAGEHash("msgServerEvent"),
'msgNetEvent': RAGEHash("msgNetEvent")
}

def parse_client_server_event(payload):
    try:
        offset = 0
        
        # Packet type: 4 bytes, little-endian uint32
        packet_type = struct.unpack('<I', payload[offset:offset+4])[0]
        offset += 4
        
        if packet_type not in supportedEvents.values():
            return None
        
        if packet_type == supportedEvents['msgNetEvent']:
            sourceNetId = struct.unpack('<H', payload[offset:offset+2])[0] # this is currently always -1, but may change
            offset+=2

        # Event name length: little-endian uint16
        name_len = struct.unpack('<H', payload[offset:offset+2])[0]
        offset += 2
        # Event name (null-terminated string)
        event_name_bytes = payload[offset:offset+name_len]
        event_name = event_name_bytes.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
        offset += name_len
        
        # MessagePack serialized event data
        event_data_bytes = payload[offset:]
        
        # Try to deserialize MessagePack data
        try:
            event_data = msgpack.unpackb(event_data_bytes)
        except msgpack.exceptions.ExtraData as e:
            event_data = e.unpacked
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

last_payload = None
def process_udp_packet(packet):
    global last_payload
    """Process UDP packets looking for client->server events"""
    if not packet.haslayer(UDP):
        return
    
    if Raw not in packet:
        return

    payload = bytes(packet[UDP].load)

    # Skip if packet is too small
    if len(payload) < 12:
        return
    
    # Check if this looks like an ENet reliable command
    if not is_enet_reliable_command(payload):
        return
    
    # Find event name hash in packet
    found_packet_type_bytes = None
    for eventName, eventHash in supportedEvents.items():
        packet_type_bytes = struct.pack('<I', eventHash)
        if packet_type_bytes in payload:
            found_packet_type_bytes = packet_type_bytes
            break
    if not found_packet_type_bytes:
        return

    offset = payload.find(found_packet_type_bytes)
    if offset == -1:
        return
    
    # Extract FiveM packet (from packet type onwards)
    fivem_payload = payload[offset:]
    
    # Parse the event
    result = parse_client_server_event(fivem_payload)
    
    # Deduplication
    if payload==last_payload: return
    last_payload=payload

    if result:
        print("\n" + "="*60)
        if int(result['packet_type'], 16)==supportedEvents['msgServerEvent']:
            print(f"CLIENT -> SERVER EVENT CAPTURED")
            direction = "OUT"
        elif int(result['packet_type'], 16)==supportedEvents['msgNetEvent']:
            print(f"SERVER -> CLIENT EVENT CAPTURED")
            direction = "IN"
        else:
            direction = "UNK"
        print("="*60)
        if IP in packet:
            src = f"{packet[IP].src}:{packet[UDP].sport}"
            dst = f"{packet[IP].dst}:{packet[UDP].dport}"
        elif IPv6 in packet:
            src = f"{packet[IPv6].src}:{packet[UDP].sport}"
            dst = f"{packet[IPv6].dst}:{packet[UDP].dport}"
        else:
            src = "unknown"
            dst = "unknown"
        print(f"Source: {src}")
        print(f"Dest: {dst}")
        print(f"Event Name: {result['event_name']}")
        print(f"Event Data: {result['event_data']}")
        #print(f"Raw Data: {result['raw_event_data']}")
        print("="*60)
        gui.send_event_to_gui(result, direction, src=src, dst=dst)

if __name__ == "__main__":
    gui.start_command_listener()
    sniff(filter="udp", iface="enp6s0", prn=process_udp_packet, store=0)
