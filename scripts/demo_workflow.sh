#!/bin/bash

echo "================================================"
echo "  TOR-Unveil Demo Workflow"
echo "================================================"
echo ""

API_URL="http://localhost:5000/api"

# Step 1: Check health
echo "Step 1: Checking system health..."
HEALTH=$(curl -s ${API_URL}/health)
echo "Response: $HEALTH"
echo ""

# Step 2: Crawl topology
echo "Step 2: Crawling TOR topology..."
CRAWL_RESULT=$(curl -s -X POST ${API_URL}/topology/crawl)
echo "Response: $CRAWL_RESULT"
echo ""
sleep 2

# Step 3: Generate test PCAP
echo "Step 3: Generating test PCAP..."
python3 scripts/generate_test_pcap.py
echo ""

# Step 4: Upload PCAP
echo "Step 4: Uploading PCAP..."
UPLOAD_RESULT=$(curl -s -X POST -F "file=@data/pcap/test_tor_traffic.pcap" ${API_URL}/pcap/upload)
echo "Response: $UPLOAD_RESULT"
echo ""
sleep 2

# Step 5: Run correlation
echo "Step 5: Running correlation analysis..."
CORR_RESULT=$(curl -s -X POST ${API_URL}/correlation/run)
echo "Response: $CORR_RESULT"
echo ""
sleep 2

# Step 6: Get results
echo "Step 6: Fetching correlation results..."
RESULTS=$(curl -s "${API_URL}/correlation/results?limit=5")
echo "Response: $RESULTS"
echo ""

# Step 7: Generate PDF report
echo "Step 7: Generating PDF report..."
REPORT_RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"type":"pdf"}' ${API_URL}/report/generate)
echo "Response: $REPORT_RESULT"
echo ""

echo "================================================"
echo "  Demo Complete!"
echo "================================================"
echo ""
echo "📊 View dashboard: http://localhost:8080"
echo "📄 Check reports in: data/reports/"
echo ""
