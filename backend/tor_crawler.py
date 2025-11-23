import requests
import logging
from datetime import datetime, timezone
from stem.descriptor.remote import get_consensus
import stem.descriptor.remote
from database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TORCrawler:
    """TOR topology crawler using Stem library and Onionoo API"""
    
    def __init__(self):
        self.db = Database()
        self.onionoo_base_url = "https://onionoo.torproject.org"
    
    def fetch_consensus_via_stem(self):
        """Fetch TOR consensus using Stem library"""
        try:
            logger.info("Fetching TOR consensus via Stem...")
            consensus = get_consensus()
            
            nodes_processed = 0
            for desc in consensus:
                node_data = {
                    'fingerprint': desc.fingerprint,
                    'nickname': desc.nickname,
                    'ip_address': desc.address,
                    'or_port': desc.or_port,
                    'dir_port': desc.dir_port if hasattr(desc, 'dir_port') else None,
                    'flags': list(desc.flags),
                    'bandwidth_kb': desc.bandwidth if hasattr(desc, 'bandwidth') else 0,
                    'consensus_weight': 0,  # Will update from details
                    'country_code': None,
                    'first_seen': datetime.now(timezone.utc),
                    'last_seen': datetime.now(timezone.utc),
                    'is_guard': 'Guard' in desc.flags,
                    'is_exit': 'Exit' in desc.flags,
                    'is_running': 'Running' in desc.flags
                }
                
                self.db.insert_tor_node(node_data)
                nodes_processed += 1
            
            logger.info(f"Processed {nodes_processed} nodes from consensus")
            return nodes_processed
            
        except Exception as e:
            logger.error(f"Error fetching consensus via Stem: {e}")
            return 0
    
    def fetch_details_via_onionoo(self):
        """Fetch detailed relay information from Onionoo API"""
        try:
            logger.info("Fetching detailed relay info from Onionoo...")
            url = f"{self.onionoo_base_url}/details?type=relay&running=true"
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            nodes_updated = 0
            for relay in data.get('relays', []):
                # Extract guard nodes specifically
                if 'Guard' in relay.get('flags', []):
                    node_data = {
                        'fingerprint': relay.get('fingerprint'),
                        'nickname': relay.get('nickname'),
                        'ip_address': relay.get('or_addresses', [''])[0].split(':')[0],
                        'or_port': int(relay.get('or_addresses', [''])[0].split(':')[1]) if ':' in relay.get('or_addresses', [''])[0] else 0,
                        'dir_port': relay.get('dir_address', '').split(':')[1] if relay.get('dir_address') else None,
                        'flags': relay.get('flags', []),
                        'bandwidth_kb': relay.get('observed_bandwidth', 0) // 1024,
                        'consensus_weight': relay.get('consensus_weight', 0),
                        'country_code': relay.get('country'),
                        'first_seen': datetime.fromisoformat(relay.get('first_seen', '').replace('Z', '+00:00')) if relay.get('first_seen') else datetime.now(timezone.utc),
                        'last_seen': datetime.fromisoformat(relay.get('last_seen', '').replace('Z', '+00:00')) if relay.get('last_seen') else datetime.now(timezone.utc),
                        'is_guard': 'Guard' in relay.get('flags', []),
                        'is_exit': 'Exit' in relay.get('flags', []),
                        'is_running': 'Running' in relay.get('flags', [])
                    }
                    
                    self.db.insert_tor_node(node_data)
                    nodes_updated += 1
            
            logger.info(f"Updated {nodes_updated} guard nodes from Onionoo")
            return nodes_updated
            
        except Exception as e:
            logger.error(f"Error fetching Onionoo details: {e}")
            return 0
    
    def crawl_topology(self):
        """Main crawling function"""
        logger.info("Starting TOR topology crawl...")
        
        # Fetch consensus first (authoritative source)
        consensus_count = self.fetch_consensus_via_stem()
        
        # Enhance with Onionoo details
        onionoo_count = self.fetch_details_via_onionoo()
        
        logger.info(f"Topology crawl complete: {consensus_count} consensus nodes, {onionoo_count} enhanced")
        return {
            'consensus_nodes': consensus_count,
            'enhanced_nodes': onionoo_count,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

if __name__ == '__main__':
    crawler = TORCrawler()
    result = crawler.crawl_topology()
    print(f"Crawl result: {result}")
