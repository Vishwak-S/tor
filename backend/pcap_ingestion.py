from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime
import hashlib
import logging
from database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PCAPIngestion:
    """PCAP file ingestion and flow extraction"""
    
    def __init__(self):
        self.db = Database()
    
    def calculate_flow_fingerprint(self, packets):
        """Generate fingerprint from packet characteristics"""
        if not packets:
            return ""
        
        # Extract packet size sequence (first 20 packets)
        sizes = [len(pkt) for pkt in packets[:20]]
        
        # Calculate inter-arrival times (milliseconds)
        if len(packets) > 1:
            times = []
            for i in range(1, min(len(packets), 20)):
                delta = float(packets[i].time - packets[i-1].time) * 1000
                times.append(int(delta))
        else:
            times = []
        
        # Create fingerprint string
        fingerprint_str = f"sizes:{','.join(map(str, sizes))};times:{','.join(map(str, times))}"
        
        # Hash it
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:32]
    
    def extract_flows(self, pcap_file):
        """Extract flows from PCAP file"""
        try:
            logger.info(f"Reading PCAP file: {pcap_file}")
            packets = rdpcap(pcap_file)
            
            # Group packets into flows
            flows = {}
            
            for pkt in packets:
                if not pkt.haslayer(IP):
                    continue
                
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = None
                src_port = 0
                dst_port = 0
                tcp_flags = ""
                
                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCP"
                    tcp_flags = str(tcp_layer.flags)
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDP"
                    tcp_flags = "--"
                else:
                    protocol = "OTHER"
                
                # Create flow key (5-tuple)
                flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                
                if flow_key not in flows:
                    flows[flow_key] = {
                        'packets': [],
                        'start_time': float(pkt.time),
                        'end_time': float(pkt.time),
                        'byte_count': 0,
                        'tcp_flags': tcp_flags
                    }
                
                flows[flow_key]['packets'].append(pkt)
                flows[flow_key]['end_time'] = float(pkt.time)
                flows[flow_key]['byte_count'] += len(pkt)
            
            logger.info(f"Extracted {len(flows)} flows from PCAP")
            
            # Insert flows into database
            flow_ids = []
            for flow_key, flow_data in flows.items():
                src_ip, dst_ip, src_port, dst_port, protocol = flow_key
                
                duration_ms = int((flow_data['end_time'] - flow_data['start_time']) * 1000)
                fingerprint = self.calculate_flow_fingerprint(flow_data['packets'])
                
                flow_record = {
                    'pcap_filename': pcap_file,
                    'timestamp': datetime.fromtimestamp(flow_data['start_time']),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'packet_count': len(flow_data['packets']),
                    'byte_count': flow_data['byte_count'],
                    'duration_ms': duration_ms,
                    'tcp_flags': flow_data['tcp_flags'],
                    'flow_fingerprint': fingerprint
                }
                
                flow_id = self.db.insert_flow(flow_record)
                flow_ids.append(flow_id)
            
            logger.info(f"Inserted {len(flow_ids)} flows into database")
            return flow_ids
            
        except Exception as e:
            logger.error(f"Error processing PCAP: {e}")
            raise
    
    def ingest_pcap(self, pcap_path):
        """Main ingestion entry point"""
        return self.extract_flows(pcap_path)

if __name__ == '__main__':
    ingestion = PCAPIngestion()
    # Example: ingestion.ingest_pcap('path/to/sample.pcap')
