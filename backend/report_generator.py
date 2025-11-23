from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import csv
import json
import logging
from database import Database
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate forensic reports in PDF and CSV formats"""
    
    def __init__(self):
        self.db = Database()
        self.config = Config()
        self.styles = getSampleStyleSheet()
    
    def generate_pdf_report(self, session_name="TOR_Analysis", top_n=20):
        """Generate comprehensive PDF forensic report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.config.REPORT_OUTPUT_DIR}/TOR_Unveil_Report_{timestamp}.pdf"
            
            doc = SimpleDocTemplate(filename, pagesize=letter)
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=1  # Center
            )
            story.append(Paragraph("TOR-Unveil Forensic Analysis Report", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Metadata
            meta_style = self.styles['Normal']
            story.append(Paragraph(f"<b>Session:</b> {session_name}", meta_style))
            story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", meta_style))
            story.append(Paragraph(f"<b>Analysis Type:</b> TOR Entry Guard Correlation", meta_style))
            story.append(Spacer(1, 0.5*inch))
            
            # Executive Summary
            story.append(Paragraph("<b>Executive Summary</b>", self.styles['Heading2']))
            
            # Get statistics
            correlations = self.db.get_top_correlations(limit=top_n)
            
            summary_text = f"""
            This forensic report presents the results of TOR traffic analysis performed using 
            the TOR-Unveil correlation engine. The analysis identified <b>{len(correlations)}</b> 
            high-confidence correlations between observed network flows and probable TOR entry 
            guard nodes.
            <br/><br/>
            The correlation methodology employs temporal alignment, bandwidth feasibility analysis, 
            and flow pattern matching to generate evidence-grade findings suitable for investigative 
            purposes.
            """
            story.append(Paragraph(summary_text, meta_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Top Correlations Table
            story.append(Paragraph("<b>Top Correlation Results</b>", self.styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            if correlations:
                # Table header
                table_data = [['Rank', 'Source IP', 'Timestamp', 'Guard Node', 'Country', 'Confidence']]
                
                for idx, corr in enumerate(correlations[:top_n], 1):
                    table_data.append([
                        str(idx),
                        str(corr['src_ip']),
                        str(corr['timestamp'].strftime('%Y-%m-%d %H:%M:%S')),
                        f"{corr['nickname']}\n({corr['node_ip']})",
                        corr['country_code'] or 'N/A',
                        f"{corr['confidence_score']:.3f}"
                    ])
                
                table = Table(table_data, colWidths=[0.5*inch, 1.3*inch, 1.3*inch, 1.5*inch, 0.7*inch, 0.8*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                story.append(table)
            
            story.append(Spacer(1, 0.5*inch))
            
            # Detailed Evidence Section
            story.append(PageBreak())
            story.append(Paragraph("<b>Detailed Evidence</b>", self.styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            for idx, corr in enumerate(correlations[:10], 1):  # Top 10 detailed
                story.append(Paragraph(f"<b>Finding #{idx}</b>", self.styles['Heading3']))
                
                evidence = json.loads(corr['evidence']) if isinstance(corr['evidence'], str) else corr['evidence']
                
                detail_text = f"""
                <b>Observed Flow:</b><br/>
                • Source IP: {corr['src_ip']}<br/>
                • Destination (Exit Node): {evidence.get('exit_node_used', 'N/A')}<br/>
                • Timestamp: {corr['timestamp']}<br/>
                <br/>
                <b>Probable Entry Guard:</b><br/>
                • Nickname: {corr['nickname']}<br/>
                • Fingerprint: {corr['candidate_node_fingerprint']}<br/>
                • IP Address: {corr['node_ip']}<br/>
                • Country: {corr['country_code']}<br/>
                <br/>
                <b>Confidence Breakdown:</b><br/>
                • Overall Confidence: {corr['confidence_score']:.4f}<br/>
                • Temporal Score: {corr['temporal_score']:.4f}<br/>
                • Bandwidth Score: {corr['bandwidth_score']:.4f}<br/>
                • Pattern Score: {corr['pattern_score']:.4f}<br/>
                <br/>
                <b>Correlation Window:</b> ±{evidence.get('time_window_seconds', 300)} seconds<br/>
                """
                
                story.append(Paragraph(detail_text, meta_style))
                story.append(Spacer(1, 0.3*inch))
            
            # Legal Disclaimer
            story.append(PageBreak())
            story.append(Paragraph("<b>Legal Notice & Chain of Custody</b>", self.styles['Heading2']))
            disclaimer_text = """
            This forensic analysis report provides <b>probabilistic correlations</b> between observed 
            network traffic and TOR network entry guard nodes. The findings represent investigative 
            leads and should be corroborated with additional evidence before use in legal proceedings.
            <br/><br/>
            <b>Limitations:</b><br/>
            • Correlations are based on timing analysis and network topology<br/>
            • Confidence scores indicate likelihood, not certainty<br/>
            • Guard node rotation and concurrent clients may affect accuracy<br/>
            • Findings require lawful collection of network traffic data<br/>
            <br/>
            <b>Chain of Custody:</b> All source data (PCAP files, consensus data) must be preserved 
            with proper timestamps and access logs. This report is reproducible from source data 
            using the documented methodology.
            """
            story.append(Paragraph(disclaimer_text, meta_style))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            raise
    
    def generate_csv_report(self, top_n=100):
        """Generate CSV export of correlation results"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.config.REPORT_OUTPUT_DIR}/TOR_Unveil_Data_{timestamp}.csv"
            
            correlations = self.db.get_top_correlations(limit=top_n)
            
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = [
                    'rank', 'source_ip', 'dest_ip', 'timestamp', 'guard_fingerprint',
                    'guard_nickname', 'guard_ip', 'guard_country', 'confidence_score',
                    'temporal_score', 'bandwidth_score', 'pattern_score', 'evidence'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for idx, corr in enumerate(correlations, 1):
                    writer.writerow({
                        'rank': idx,
                        'source_ip': str(corr['src_ip']),
                        'dest_ip': str(corr['dst_ip']),
                        'timestamp': corr['timestamp'],
                        'guard_fingerprint': corr['candidate_node_fingerprint'],
                        'guard_nickname': corr['nickname'],
                        'guard_ip': str(corr['node_ip']),
                        'guard_country': corr['country_code'],
                        'confidence_score': corr['confidence_score'],
                        'temporal_score': corr['temporal_score'],
                        'bandwidth_score': corr['bandwidth_score'],
                        'pattern_score': corr['pattern_score'],
                        'evidence': json.dumps(corr['evidence'])
                    })
            
            logger.info(f"CSV report generated: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            raise

if __name__ == '__main__':
    generator = ReportGenerator()
    pdf_file = generator.generate_pdf_report()
    csv_file = generator.generate_csv_report()
    print(f"Reports generated:\n  PDF: {pdf_file}\n  CSV: {csv_file}")
