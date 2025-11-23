import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import logging
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Database:
    """PostgreSQL database handler"""
    
    def __init__(self):
        self.config = Config()
        self.connection_string = (
            f"host={self.config.DB_HOST} "
            f"port={self.config.DB_PORT} "
            f"dbname={self.config.DB_NAME} "
            f"user={self.config.DB_USER} "
            f"password={self.config.DB_PASSWORD}"
        )
    
    @contextmanager
    def get_connection(self):
        """Get database connection context manager"""
        conn = psycopg2.connect(self.connection_string)
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def initialize_schema(self):
        """Create database tables"""
        schema = """
        -- TOR relay nodes table
        CREATE TABLE IF NOT EXISTS tor_nodes (
            fingerprint VARCHAR(40) PRIMARY KEY,
            nickname VARCHAR(255),
            ip_address INET,
            or_port INTEGER,
            dir_port INTEGER,
            flags TEXT[],
            bandwidth_kb BIGINT,
            consensus_weight BIGINT,
            country_code VARCHAR(2),
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            is_guard BOOLEAN DEFAULT FALSE,
            is_exit BOOLEAN DEFAULT FALSE,
            is_running BOOLEAN DEFAULT TRUE
        );
        
        CREATE INDEX IF NOT EXISTS idx_tor_nodes_ip ON tor_nodes(ip_address);
        CREATE INDEX IF NOT EXISTS idx_tor_nodes_flags ON tor_nodes USING GIN(flags);
        CREATE INDEX IF NOT EXISTS idx_tor_nodes_guard ON tor_nodes(is_guard) WHERE is_guard = TRUE;
        
        -- Network flows table
        CREATE TABLE IF NOT EXISTS network_flows (
            flow_id SERIAL PRIMARY KEY,
            pcap_filename VARCHAR(255),
            timestamp TIMESTAMP,
            src_ip INET,
            dst_ip INET,
            src_port INTEGER,
            dst_port INTEGER,
            protocol VARCHAR(10),
            packet_count INTEGER,
            byte_count BIGINT,
            duration_ms INTEGER,
            tcp_flags VARCHAR(20),
            flow_fingerprint TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp);
        CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows(src_ip);
        CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON network_flows(dst_ip);
        
        -- Correlation results table
        CREATE TABLE IF NOT EXISTS correlation_results (
            correlation_id SERIAL PRIMARY KEY,
            flow_id INTEGER REFERENCES network_flows(flow_id),
            candidate_node_fingerprint VARCHAR(40) REFERENCES tor_nodes(fingerprint),
            confidence_score FLOAT,
            temporal_score FLOAT,
            bandwidth_score FLOAT,
            pattern_score FLOAT,
            evidence JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_correlation_flow ON correlation_results(flow_id);
        CREATE INDEX IF NOT EXISTS idx_correlation_confidence ON correlation_results(confidence_score DESC);
        
        -- Analysis sessions table
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            session_id SERIAL PRIMARY KEY,
            session_name VARCHAR(255),
            description TEXT,
            status VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            total_flows INTEGER DEFAULT 0,
            correlations_found INTEGER DEFAULT 0
        );
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(schema)
        logger.info("Database schema initialized successfully")
    
    def insert_tor_node(self, node_data):
        """Insert or update TOR node"""
        query = """
        INSERT INTO tor_nodes (
            fingerprint, nickname, ip_address, or_port, dir_port, flags,
            bandwidth_kb, consensus_weight, country_code, first_seen, last_seen,
            is_guard, is_exit, is_running
        ) VALUES (
            %(fingerprint)s, %(nickname)s, %(ip_address)s, %(or_port)s, %(dir_port)s,
            %(flags)s, %(bandwidth_kb)s, %(consensus_weight)s, %(country_code)s,
            %(first_seen)s, %(last_seen)s, %(is_guard)s, %(is_exit)s, %(is_running)s
        )
        ON CONFLICT (fingerprint) DO UPDATE SET
            nickname = EXCLUDED.nickname,
            last_seen = EXCLUDED.last_seen,
            flags = EXCLUDED.flags,
            bandwidth_kb = EXCLUDED.bandwidth_kb,
            is_running = EXCLUDED.is_running
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, node_data)
    
    def insert_flow(self, flow_data):
        """Insert network flow"""
        query = """
        INSERT INTO network_flows (
            pcap_filename, timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, packet_count, byte_count, duration_ms, tcp_flags, flow_fingerprint
        ) VALUES (
            %(pcap_filename)s, %(timestamp)s, %(src_ip)s, %(dst_ip)s, %(src_port)s,
            %(dst_port)s, %(protocol)s, %(packet_count)s, %(byte_count)s,
            %(duration_ms)s, %(tcp_flags)s, %(flow_fingerprint)s
        ) RETURNING flow_id
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, flow_data)
                return cursor.fetchone()[0]
    
    def insert_correlation(self, correlation_data):
        """Insert correlation result"""
        query = """
        INSERT INTO correlation_results (
            flow_id, candidate_node_fingerprint, confidence_score,
            temporal_score, bandwidth_score, pattern_score, evidence
        ) VALUES (
            %(flow_id)s, %(candidate_node_fingerprint)s, %(confidence_score)s,
            %(temporal_score)s, %(bandwidth_score)s, %(pattern_score)s, %(evidence)s
        )
        """
        
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, correlation_data)
    
    def get_guard_nodes(self, limit=None):
        """Retrieve guard nodes"""
        query = "SELECT * FROM tor_nodes WHERE is_guard = TRUE AND is_running = TRUE"
        if limit:
            query += f" LIMIT {limit}"
        
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query)
                return cursor.fetchall()
    
    def get_flows_by_timerange(self, start_time, end_time):
        """Get flows within time range"""
        query = """
        SELECT * FROM network_flows
        WHERE timestamp BETWEEN %s AND %s
        ORDER BY timestamp
        """
        
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (start_time, end_time))
                return cursor.fetchall()
    
    def get_top_correlations(self, session_id=None, limit=10):
        """Get top correlation results"""
        query = """
        SELECT 
            cr.*,
            nf.src_ip, nf.dst_ip, nf.timestamp,
            tn.nickname, tn.ip_address as node_ip, tn.country_code
        FROM correlation_results cr
        JOIN network_flows nf ON cr.flow_id = nf.flow_id
        JOIN tor_nodes tn ON cr.candidate_node_fingerprint = tn.fingerprint
        ORDER BY cr.confidence_score DESC
        LIMIT %s
        """
        
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, (limit,))
                return cursor.fetchall()
