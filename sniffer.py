from scapy.all import sniff, Scapy_Exception

def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        print(f'[*] New Packet: {ip_layer.src} -> {ip_layer.dst}')
        print(f'    Protocol: {ip_layer.proto}')
        print(f'    Payload: {bytes(packet.payload)}')

# List of interfaces to try
interfaces = ['en0', 'en1', 'en2', 'eth0']

for iface in interfaces:
    try:
        print(f'Trying interface {iface}...')
        sniff(iface=iface, prn=packet_callback, store=0)
        break  # Exit the loop if sniffing starts successfully
    except Scapy_Exception as e:
        print(f'Failed on {iface}: {e}')
    except OSError as e:
        print(f'OS error on {iface}: {e}')
    except Exception as e:
        print(f'Unexpected error on {iface}: {e}')
