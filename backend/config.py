import os
from datetime import timedelta

class Config:
    """Application configuration"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'True') == 'True'
    
    # Database settings
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '5432')
    DB_NAME = os.environ.get('DB_NAME', 'tor_unveil')
    DB_USER = os.environ.get('DB_USER', 'postgres')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'postgres')
    
    # Redis settings
    REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.environ.get('REDIS_PORT', '6379'))
    REDIS_DB = int(os.environ.get('REDIS_DB', '0'))
    
    # TOR settings
    TOR_DIRECTORY_AUTHORITIES = [
        'https://collector.torproject.org/recent/relay-descriptors/consensuses/',
        'https://onionoo.torproject.org/details'
    ]
    TOR_CONSENSUS_REFRESH_INTERVAL = timedelta(hours=1)
    
    # Correlation settings
    TIME_WINDOW_SECONDS = 300  # 5-minute window for correlation
    MIN_CONFIDENCE_THRESHOLD = 0.3
    MAX_CANDIDATE_NODES = 10
    
    # File paths
    PCAP_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'pcap')
    REPORT_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'reports')
    
    # Ensure directories exist
    os.makedirs(PCAP_UPLOAD_DIR, exist_ok=True)
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
