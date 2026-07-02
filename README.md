# Kenumerator
# 🔍 KEnumerator Pro

**Advanced Interactive Network Enumeration & Penetration Testing Tool**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SecLists](https://img.shields.io/badge/SecLists-Integrated-green.svg)](https://github.com/danielmiessler/SecLists)

<p align="center">
  <img src="https://img.shields.io/badge/Network-Scanner-red?style=for-the-badge&logo=network-wired"/>
  <img src="https://img.shields.io/badge/Penetration-Testing-blue?style=for-the-badge&logo=security"/>
  <img src="https://img.shields.io/badge/Interactive-Mode-green?style=for-the-badge&logo=terminal"/>
</p>

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [SecLists Integration](#-seclists-integration)
- [API Configuration](#-api-configuration)
- [Screenshots](#-screenshots)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔍 Discovery & Scanning
- **ARP Discovery** - Fast local network device discovery
- **Live Continuous Scanning** - Real-time network monitoring
- **TCP/UDP Port Scanning** - Full Nmap integration
- **Stealth Scanning** - Evasion techniques with fragmentation & decoys
- **OS Fingerprinting** - Operating system detection
- **Service Version Detection** - Banner grabbing & version analysis

### 🌐 Enumeration
- **SMB Enumeration** - Share discovery, null session testing
- **SNMP Enumeration** - Community string testing, OID walking
- **Web Technology Detection** - CMS & framework identification
- **Banner Grabbing** - Multi-protocol service identification

### 💥 Penetration Testing
- **Vulnerability Scanning** - NSE script integration
- **SSH Brute Force** - With SecLists wordlist support
- **FTP Brute Force** - Automated credential testing
- **Telnet Brute Force** - Legacy protocol testing
- **Web Directory Brute Force** - Hidden resource discovery

### 🧠 Intelligence
- **Shodan Integration** - External threat intelligence
- **VirusTotal Lookup** - IP reputation checking
- **Network Topology Mapping** - Visual network diagrams

### 📊 Reporting & Data
- **SQLite Database** - Persistent scan storage
- **Multiple Export Formats** - JSON, CSV, HTML reports
- **Scan History** - Track changes over time
- **Wordlist Management** - Integrated SecLists support

## 🔧 Installation

### Prerequisites

```bash
# Kali Linux / Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y python3 python3-pip nmap git

# macOS
brew install python nmap git

# Windows (with WSL recommended)
# Install WSL2, then follow Linux instructions

# Clone the repository
git clone https://github.com/yourusername/kenumerator-pro.git
cd kenumerator-pro

# Install Python dependencies
pip3 install -r requirements.txt

# Optional: Install recommended tools
pip3 install paramiko impacket pysnmp networkx matplotlib

# Option 1: Full SecLists (500MB+)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git seclists

# Option 2: Run setup from within KEnumerator
sudo python3 kenumerator_pro.py
# Then select Option 20 → Download Specific Wordlists

