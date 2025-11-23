#!/usr/bin/env python3
"""
Generate synthetic TOR traffic PCAP for testing
"""

from scapy.all import *
import random
from datetime import datetime, timedelta

def generate_test_pcap(output_file="data/pcap/test_tor_traffic.pcap", num_flows=10):
    """Generate synthetic TOR traffic PCAP"""
    
    # Known TOR guard nodes (examples)
    tor_guards = [
        "185.220.101.1",  # German guard
        "199.249.230.1",  # US guard
        "163.172.149.155", # French guard
        "89.234.157.254",  # Swiss guard
    ]
    
    # Simulated source IPs
    source_ips = [
        "192.168.1.100",
        "192.168.1.101",
        "10.0.0.50",
    ]
    
    packets = []
    timestamp = datetime.now()
    
    print(f"Generating {num_flows} TOR connection flows...")
    
    for flow_id in range(num_flows):
        src_ip = random.choice(source_ips)
        dst_ip = random.choice(tor_guards)
        src_port = random.randint(50000, 60000)
        dst_port = 9001  # TOR ORPort
        
        # Generate flow with ~50 packets
        for pkt_num in range(random.randint(30, 70)):
            # Calculate timestamp with realistic intervals
            timestamp += timedelta(milliseconds=random.randint(10, 100))
            
            # Create TCP packet
            if pkt_num == 0:
                # SYN packet
                pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S')
            elif pkt_num == 1:
                # SYN-ACK
                pkt = Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='SA')
            elif pkt_num == 2:
                # ACK
                pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A')
            else:
                # Data packets with varying sizes
                payload_size = random.randint(100, 1400)
                payload = Raw(load='X' * payload_size)
                pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A')/payload
            
            pkt.time = timestamp.timestamp()
            packets.append(pkt)
        
        print(f"  Flow {flow_id + 1}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    # Write PCAP
    wrpcap(output_file, packets)
    print(f"\n✅ Generated PCAP: {output_file}")
    print(f"   Total packets: {len(packets)}")
    print(f"   Duration: {(packets[-1].time - packets[0].time):.2f} seconds")

if __name__ == '__main__':
    generate_test_pcap()
