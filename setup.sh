#!/bin/bash

# KEnumerator Pro Setup Script
# Run: chmod +x setup.sh && sudo ./setup.sh

set -e

echo "🔧 KEnumerator Pro Setup"
echo "========================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  Please run as root (sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
elif type lsb_release >/dev/null 2>&1; then
    OS=$(lsb_release -si)
else
    OS=$(uname -s)
fi

echo "📦 Installing system dependencies..."

# Install based on OS
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Kali"* ]]; then
    apt-get update
    apt-get install -y python3 python3-pip python3-venv nmap git
elif [[ "$OS" == *"Fedora"* ]] || [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]]; then
    dnf install -y python3 python3-pip nmap git
elif [[ "$OS" == *"Arch"* ]]; then
    pacman -Sy python python-pip nmap git --noconfirm
elif [[ "$OS" == *"Darwin"* ]]; then
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Please install Homebrew first."
        exit 1
    fi
    brew install python nmap git
else
    echo "⚠️  Unknown OS. Please install Python 3, pip, nmap, and git manually."
fi

echo "🐍 Setting up Python environment..."

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
echo "📚 Installing Python packages..."
pip install -r requirements.txt

echo "🔐 Setting up permissions..."
chmod +x kenumerator_pro.py

# Create config if not exists
if [ ! -f "config.yaml" ]; then
    echo "⚙️  Creating default config..."
    cat > config.yaml << EOF
scan:
  default_port_range: '1-1024'
  full_port_range: '1-65535'
  threads: 10
  timeout: 3

wordlists:
  seclists_path: 'seclists'

output:
  format: 'json'
  db_path: 'kenumerator.db'

api_keys:
  shodan: ''
  virustotal: ''
  macvendors: ''

bruteforce:
  max_threads: 5
  timeout: 5
EOF
fi

echo ""
echo "✅ Setup Complete!"
echo ""
echo "🚀 Quick Start:"
echo "   sudo ./venv/bin/python kenumerator_pro.py"
echo ""
echo "📖 Or activate venv first:"
echo "   source venv/bin/activate"
echo "   sudo python kenumerator_pro.py"
echo ""
echo "💡 Tip: Clone SecLists for enhanced wordlists:"
echo "   git clone --depth 1 https://github.com/danielmiessler/SecLists.git seclists"
