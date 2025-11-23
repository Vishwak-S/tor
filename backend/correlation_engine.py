import logging
from datetime import datetime, timedelta
from database import Database
from config import Config
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CorrelationEngine:
    """Core correlation logic for TOR traffic analysis"""
    
    def __init__(self):
        self.db = Database()
        self.config = Config()
    
    def calculate_temporal_score(self, flow_timestamp, node_last_seen):
        """Calculate temporal proximity score"""
        try:
            if isinstance(flow_timestamp, str):
                flow_timestamp = datetime.fromisoformat(flow_timestamp)
            if isinstance(node_last_seen, str):
                node_last_seen = datetime.fromisoformat(node_last_seen)
            
            time_diff = abs((flow_timestamp - node_last_seen).total_seconds())
            
            # Score decays with time difference
            # Perfect score (1.0) if within 5 minutes
            if time_diff <= 300:
                return 1.0
            # Linear decay up to 1 hour
            elif time_diff <= 3600:
                return 1.0 - (time_diff - 300) / 3300
            else:
                return max(0.1, 1.0 - time_diff / 86400)  # 24 hour decay
                
        except Exception as e:
            logger.error(f"Error calculating temporal score: {e}")
            return 0.0
    
    def calculate_bandwidth_score(self, flow_byte_count, node_bandwidth_kb):
        """Calculate bandwidth feasibility score"""
        try:
            # Convert KB to bytes
            node_bandwidth_bytes = node_bandwidth_kb * 1024
            
            if node_bandwidth_bytes == 0:
                return 0.5  # Unknown bandwidth
            
            # Calculate utilization ratio
            utilization = flow_byte_count / node_bandwidth_bytes
            
            # Optimal range: 10-80% utilization
            if 0.1 <= utilization <= 0.8:
                return 1.0
            elif utilization < 0.1:
                return utilization / 0.1
            else:
                return max(0.2, 1.0 - (utilization - 0.8) / 0.2)
                
        except Exception as e:
            logger.error(f"Error calculating bandwidth score: {e}")
            return 0.0
    
    def calculate_pattern_score(self, flow_fingerprint, historical_fingerprints):
        """Calculate pattern similarity score"""
        try:
            if not flow_fingerprint or not historical_fingerprints:
                return 0.5
            
            # Simple Hamming distance for fingerprint matching
            matches = sum(1 for fp in historical_fingerprints if fp == flow_fingerprint)
            
            if matches > 0:
                return min(1.0, 0.5 + (matches * 0.1))
            else:
                return 0.3
                
        except Exception as e:
            logger.error(f"Error calculating pattern score: {e}")
            return 0.0
    
    def correlate_flow_to_guards(self, flow_id):
        """Correlate a single flow to probable guard nodes"""
        try:
            # Get flow details
            with self.db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT * FROM network_flows WHERE flow_id = %s", (flow_id,))
                    flow = cursor.fetchone()
            
            if not flow:
                logger.warning(f"Flow {flow_id} not found")
                return []
            
            # Extract flow data
            flow_timestamp = flow[2]  # timestamp column
            flow_dst_ip = str(flow[4])  # dst_ip
            flow_byte_count = flow[9]  # byte_count
            flow_fingerprint = flow[12]  # flow_fingerprint
            
            # Get candidate guard nodes
            # Check if destination IP is a known TOR node
            with self.db.get_connection() as conn:
                with conn.cursor() as cursor:
                    # First check if dst_ip is a known TOR exit
                    cursor.execute("""
                        SELECT fingerprint, last_seen, bandwidth_kb 
                        FROM tor_nodes 
                        WHERE ip_address = %s AND is_exit = TRUE
                    """, (flow_dst_ip,))
                    exit_node = cursor.fetchone()
            
            if not exit_node:
                logger.info(f"Flow {flow_id} dst IP {flow_dst_ip} is not a known TOR exit")
                return []
            
            # Now find probable entry guards based on temporal correlation
            time_window_start = flow_timestamp - timedelta(seconds=self.config.TIME_WINDOW_SECONDS)
            time_window_end = flow_timestamp + timedelta(seconds=self.config.TIME_WINDOW_SECONDS)
            
            # Get active guard nodes in time window
            guard_nodes = self.db.get_guard_nodes(limit=100)
            
            correlations = []
            for node in guard_nodes:
                # Calculate individual scores
                temporal_score = self.calculate_temporal_score(
                    flow_timestamp, 
                    node['last_seen']
                )
                
                bandwidth_score = self.calculate_bandwidth_score(
                    flow_byte_count,
                    node['bandwidth_kb']
                )
                
                # Get historical patterns (simplified)
                pattern_score = self.calculate_pattern_score(
                    flow_fingerprint,
                    []  # Would query historical fingerprints
                )
                
                # Weighted confidence score
                confidence_score = (
                    temporal_score * 0.5 +
                    bandwidth_score * 0.3 +
                    pattern_score * 0.2
                )
                
                # Only keep candidates above threshold
                if confidence_score >= self.config.MIN_CONFIDENCE_THRESHOLD:
                    correlation_data = {
                        'flow_id': flow_id,
                        'candidate_node_fingerprint': node['fingerprint'],
                        'confidence_score': round(confidence_score, 4),
                        'temporal_score': round(temporal_score, 4),
                        'bandwidth_score': round(bandwidth_score, 4),
                        'pattern_score': round(pattern_score, 4),
                        'evidence': json.dumps({
                            'node_nickname': node['nickname'],
                            'node_ip': str(node['ip_address']),
                            'node_country': node['country_code'],
                            'exit_node_used': str(flow_dst_ip),
                            'time_window_seconds': self.config.TIME_WINDOW_SECONDS
                        })
                    }
                    
                    self.db.insert_correlation(correlation_data)
                    correlations.append(correlation_data)
            
            # Sort by confidence and limit
            correlations.sort(key=lambda x: x['confidence_score'], reverse=True)
            correlations = correlations[:self.config.MAX_CANDIDATE_NODES]
            
            logger.info(f"Flow {flow_id}: Found {len(correlations)} candidate guard nodes")
            return correlations
            
        except Exception as e:
            logger.error(f"Error correlating flow {flow_id}: {e}")
            return []
    
    def correlate_all_flows(self):
        """Correlate all unprocessed flows"""
        try:
            # Get flows without correlations
            with self.db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT flow_id FROM network_flows
                        WHERE flow_id NOT IN (SELECT DISTINCT flow_id FROM correlation_results)
                    """)
                    flow_ids = [row[0] for row in cursor.fetchall()]
            
            logger.info(f"Correlating {len(flow_ids)} flows...")
            
            total_correlations = 0
            for flow_id in flow_ids:
                correlations = self.correlate_flow_to_guards(flow_id)
                total_correlations += len(correlations)
            
            logger.info(f"Correlation complete: {total_correlations} correlations found")
            return {
                'flows_processed': len(flow_ids),
                'total_correlations': total_correlations
            }
            
        except Exception as e:
            logger.error(f"Error in batch correlation: {e}")
            return {'error': str(e)}

if __name__ == '__main__':
    engine = CorrelationEngine()
    result = engine.correlate_all_flows()
    print(f"Correlation result: {result}")
