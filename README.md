# TOR-Unveil: Forensic Correlator + Analytical Dashboard

![TOR-Unveil Banner](https://img.shields.io/badge/TOR-Unveil-blue?style=for-the-badge&logo=tor)
![Python](https://img.shields.io/badge/Python-3.11-green?style=flat-square&logo=python)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square&logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

## 🎯 Overview

**TOR-Unveil** is a forensic-grade analysis system designed to correlate TOR network traffic with probable entry guard nodes. The platform combines network topology analysis, PCAP ingestion, temporal correlation, and interactive visualization to provide law enforcement and security researchers with actionable intelligence.

## 🏗️ Architecture

┌─────────────────────────────────────────────────────────────┐
│ TOR-Unveil System │
├─────────────────────────────────────────────────────────────┤
│ │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │ Topology │ │ PCAP │ │ Correlation │ │
│ │ Crawler │→ │ Ingestion │→ │ Engine │ │
│ └──────────────┘ └──────────────┘ └──────────────┘ │
│ ↓ ↓ ↓ │
│ ┌──────────────────────────────────────────────────┐ │
│ │ PostgreSQL Database │ │
│ │ (Nodes, Flows, Correlations, Sessions) │ │
│ └──────────────────────────────────────────────────┘ │
│ ↓ │
│ ┌──────────────────────────────────────────────────┐ │
│ │ Interactive Dashboard │ │
│ │ (Network Graph, Timeline, Results, Reports) │ │
│ └──────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────┘

text

## ✨ Features

### Core Functionality
- **🌐 TOR Topology Crawler**: Real-time fetching of consensus and relay descriptors
- **📦 PCAP Ingestion**: Deep packet inspection using Scapy/TShark
- **🔗 Correlation Engine**: Multi-factor scoring (temporal, bandwidth, pattern)
- **📊 Interactive Dashboard**: Real-time visualization with D3.js and vis.js
- **📄 Forensic Reports**: PDF and CSV export with chain-of-evidence

### Correlation Methodology
- **Temporal Alignment**: Time-window matching (±5 minutes default)
- **Bandwidth Feasibility**: Node capacity vs flow characteristics
- **Flow Fingerprinting**: Packet size sequences and inter-arrival timing
- **Confidence Scoring**: Weighted multi-factor analysis

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for local development)
- PostgreSQL 15+ (if running without Docker)
- Redis 7+ (if running without Docker)

### Installation

#### Option 1: Docker (Recommended)
