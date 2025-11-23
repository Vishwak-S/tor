from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import logging
import os
from werkzeug.utils import secure_filename

from config import Config
from database import Database
from tor_crawler import TORCrawler
from pcap_ingestion import PCAPIngestion
from correlation_engine import CorrelationEngine
from report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize components
db = Database()
crawler = TORCrawler()
ingestion = PCAPIngestion()
engine = CorrelationEngine()
reporter = ReportGenerator()

# Initialize database schema
try:
    db.initialize_schema()
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'TOR-Unveil API',
        'version': '1.0.0'
    })

@app.route('/api/topology/crawl', methods=['POST'])
def crawl_topology():
    """Trigger TOR topology crawl"""
    try:
        result = crawler.crawl_topology()
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.error(f"Topology crawl error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/topology/nodes', methods=['GET'])
def get_nodes():
    """Get TOR nodes"""
    try:
        node_type = request.args.get('type', 'guard')
        limit = int(request.args.get('limit', 50))
        
        if node_type == 'guard':
            nodes = db.get_guard_nodes(limit=limit)
        else:
            nodes = []
        
        # Convert to JSON-serializable format
        nodes_json = []
        for node in nodes:
            nodes_json.append({
                'fingerprint': node['fingerprint'],
                'nickname': node['nickname'],
                'ip_address': str(node['ip_address']),
                'or_port': node['or_port'],
                'flags': node['flags'],
                'bandwidth_kb': node['bandwidth_kb'],
                'country_code': node['country_code'],
                'is_guard': node['is_guard'],
                'is_exit': node['is_exit']
            })
        
        return jsonify({
            'success': True,
            'count': len(nodes_json),
            'nodes': nodes_json
        })
    except Exception as e:
        logger.error(f"Error fetching nodes: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    """Upload and process PCAP file"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file provided'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'Empty filename'
            }), 400
        
        if file and (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['PCAP_UPLOAD_DIR'], filename)
            file.save(filepath)
            
            logger.info(f"PCAP file uploaded: {filepath}")
            
            # Ingest PCAP
            flow_ids = ingestion.ingest_pcap(filepath)
            
            return jsonify({
                'success': True,
                'filename': filename,
                'flows_extracted': len(flow_ids)
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid file type. Must be .pcap or .pcapng'
            }), 400
            
    except Exception as e:
        logger.error(f"PCAP upload error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/correlation/run', methods=['POST'])
def run_correlation():
    """Run correlation analysis"""
    try:
        result = engine.correlate_all_flows()
        return jsonify({
            'success': True,
            'data': result
        })
    except Exception as e:
        logger.error(f"Correlation error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/correlation/results', methods=['GET'])
def get_results():
    """Get correlation results"""
    try:
        limit = int(request.args.get('limit', 20))
        results = db.get_top_correlations(limit=limit)
        
        # Convert to JSON-serializable format
        results_json = []
        for r in results:
            results_json.append({
                'correlation_id': r['correlation_id'],
                'flow_id': r['flow_id'],
                'src_ip': str(r['src_ip']),
                'dst_ip': str(r['dst_ip']),
                'timestamp': r['timestamp'].isoformat(),
                'guard_fingerprint': r['candidate_node_fingerprint'],
                'guard_nickname': r['nickname'],
                'guard_ip': str(r['node_ip']),
                'guard_country': r['country_code'],
                'confidence_score': float(r['confidence_score']),
                'temporal_score': float(r['temporal_score']),
                'bandwidth_score': float(r['bandwidth_score']),
                'pattern_score': float(r['pattern_score']),
                'evidence': r['evidence']
            })
        
        return jsonify({
            'success': True,
            'count': len(results_json),
            'results': results_json
        })
    except Exception as e:
        logger.error(f"Error fetching results: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """Generate forensic report"""
    try:
        report_type = request.json.get('type', 'pdf')  # pdf or csv
        
        if report_type == 'pdf':
            filename = reporter.generate_pdf_report()
        elif report_type == 'csv':
            filename = reporter.generate_csv_report()
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid report type'
            }), 400
        
        return jsonify({
            'success': True,
            'filename': os.path.basename(filename),
            'path': filename
        })
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/report/download/<filename>', methods=['GET'])
def download_report(filename):
    """Download generated report"""
    try:
        filepath = os.path.join(app.config['REPORT_OUTPUT_DIR'], filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            return jsonify({
                'success': False,
                'error': 'File not found'
            }), 404
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
