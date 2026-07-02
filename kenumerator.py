#!/usr/bin/env python3
"""
KEnumerator Pro - Interactive Network Enumeration & Pentesting Tool
Version: 2.2 - With Wordlist Management System
"""

import scapy.all as scapy
import os
import sys
import netifaces
import time
import threading
import itertools
import json
import csv
import socket
import sqlite3
import yaml
import shutil
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPNetwork
import requests
from colorama import Fore, Style, init
from datetime import datetime
import nmap
import paramiko
import ftplib
import telnetlib

# Optional imports
try:
    from impacket.smbconnection import SMBConnection
    IMPOCKET_AVAILABLE = True
except ImportError:
    IMPOCKET_AVAILABLE = False

try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False

try:
    import networkx as nx
    import matplotlib.pyplot as plt
    GRAPH_AVAILABLE = True
except ImportError:
    GRAPH_AVAILABLE = False

init(autoreset=True)

device_results = {}
results_lock = threading.Lock()
CONFIG = {}
DB_CONNECTION = None

# Wordlist management globals
WORDLIST_CATEGORIES = {
    'users': 'Usernames for brute force attacks',
    'passwords': 'Passwords for brute force attacks',
    'directories': 'Web directories for dir busting',
    'ssh_users': 'SSH specific usernames',
    'ftp_users': 'FTP specific usernames',
    'telnet_users': 'Telnet specific usernames',
    'snmp_communities': 'SNMP community strings',
    'subdomains': 'Subdomains for DNS enumeration'
}

def ask_yes_no(question, default="n"):
    """Ask yes/no question"""
    valid = {"yes": True, "y": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        prompt = " [y/n] "
    
    while True:
        sys.stdout.write(Fore.CYAN + question + prompt + Style.RESET_ALL)
        choice = input().lower().strip()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            print(Fore.RED + "Please respond with 'yes' or 'no' (or 'y' or 'n')." + Style.RESET_ALL)

def ask_input(question, default=None):
    """Ask for input with optional default"""
    if default:
        prompt = f" [{default}]: "
    else:
        prompt = ": "
    sys.stdout.write(Fore.CYAN + question + prompt + Style.RESET_ALL)
    answer = input().strip()
    if not answer and default:
        return default
    return answer

def pause_continue(message="Press Enter to continue..."):
    """Pause for user acknowledgment"""
    input(Fore.CYAN + message + Style.RESET_ALL)

# ============================================================================
# WORDLIST MANAGEMENT MODULE
# ============================================================================

def init_wordlist_system():
    """Initialize wordlist directory structure"""
    base_dir = 'wordlists'
    os.makedirs(base_dir, exist_ok=True)
    
    # Create category subdirectories
    for category in WORDLIST_CATEGORIES.keys():
        os.makedirs(os.path.join(base_dir, category), exist_ok=True)
    
    # Create default wordlists if they don't exist
    create_default_wordlists()
    
    return base_dir

def create_default_wordlists():
    """Create default wordlists in categorized structure"""
    
    # Common directories
    dirs_content = """admin
login
wp-admin
wp-login
dashboard
panel
api
test
dev
backup
config
phpmyadmin
mysql
db
uploads
files
images
assets
js
css
api/v1
api/v2
rest
graphql
swagger
administrator
manage
management
console
portal
"""
    
    # Common passwords
    passwords_content = """password
123456
admin
root
toor
password123
admin123
root123
123456789
qwerty
letmein
welcome
monkey
dragon
master
hello123
test123
user
guest
default
passw0rd
P@ssw0rd
Admin123
Root123
"""
    
    # Common users
    users_content = """root
admin
administrator
user
test
guest
oracle
postgres
mysql
ftp
pi
ubuntu
centos
debian
service
support
helpdesk
operator
manager
webmaster
postmaster
hostmaster
"""
    
    # SSH specific users
    ssh_users_content = """root
admin
ubuntu
centos
debian
pi
ec2-user
azureuser
administrator
vagrant
ansible
jenkins
git
docker
"""
    
    # FTP specific users
    ftp_users_content = """anonymous
ftp
admin
root
user
test
guest
upload
download
backup
web
www
"""
    
    # Telnet specific users
    telnet_users_content = """root
admin
administrator
user
guest
test
cisco
manager
operator
"""
    
    # SNMP communities
    snmp_content = """public
private
admin
manager
guest
default
internal
external
community
snmp
"""
    
    # Subdomains
    subdomains_content = """www
mail
ftp
localhost
webmail
smtp
pop
ns1
webdisk
ns2
cpanel
whm
autodiscover
autoconfig
ns3
m
imap
test
ns
blog
pop3
dev
www2
admin
forum
news
vpn
ns4
imap4
smtp3
login
chat
wap
mx
exchange
"""
    
    default_files = {
        'wordlists/directories/common.txt': dirs_content,
        'wordlists/passwords/common.txt': passwords_content,
        'wordlists/users/common.txt': users_content,
        'wordlists/ssh_users/common.txt': ssh_users_content,
        'wordlists/ftp_users/common.txt': ftp_users_content,
        'wordlists/telnet_users/common.txt': telnet_users_content,
        'wordlists/snmp_communities/common.txt': snmp_content,
        'wordlists/subdomains/common.txt': subdomains_content,
    }
    
    for filepath, content in default_files.items():
        if not os.path.exists(filepath):
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                f.write(content)
            print(Fore.GREEN + f"[+] Created default wordlist: {filepath}" + Style.RESET_ALL)

def get_wordlist_stats(filepath):
    """Get statistics about a wordlist file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            total = len(lines)
            non_empty = len([l for l in lines if l.strip()])
            unique = len(set(l.strip().lower() for l in lines if l.strip()))
            size = os.path.getsize(filepath)
            
            return {
                'total_lines': total,
                'non_empty': non_empty,
                'unique': unique,
                'size_bytes': size,
                'size_human': format_bytes(size)
            }
    except Exception as e:
        return None

def format_bytes(size):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def list_wordlists(category=None):
    """List available wordlists"""
    base_dir = 'wordlists'
    
    if category:
        # List specific category
        cat_dir = os.path.join(base_dir, category)
        if not os.path.exists(cat_dir):
            return []
        
        wordlists = []
        for file in os.listdir(cat_dir):
            if file.endswith('.txt'):
                filepath = os.path.join(cat_dir, file)
                stats = get_wordlist_stats(filepath)
                wordlists.append({
                    'name': file,
                    'path': filepath,
                    'category': category,
                    'stats': stats
                })
        return wordlists
    else:
        # List all categories
        all_wordlists = {}
        for cat in WORDLIST_CATEGORIES.keys():
            cat_dir = os.path.join(base_dir, cat)
            if os.path.exists(cat_dir):
                all_wordlists[cat] = []
                for file in os.listdir(cat_dir):
                    if file.endswith('.txt'):
                        filepath = os.path.join(cat_dir, file)
                        stats = get_wordlist_stats(filepath)
                        all_wordlists[cat].append({
                            'name': file,
                            'path': filepath,
                            'stats': stats
                        })
        return all_wordlists

def import_wordlist():
    """Import external wordlist file"""
    print(Fore.CYAN + "\n=== Import Wordlist ===" + Style.RESET_ALL)
    
    # Get source file path
    source_path = ask_input("Enter path to wordlist file to import")
    
    if not os.path.exists(source_path):
        print(Fore.RED + f"[!] File not found: {source_path}" + Style.RESET_ALL)
        return False
    
    # Validate file
    stats = get_wordlist_stats(source_path)
    if not stats:
        print(Fore.RED + "[!] Could not read file" + Style.RESET_ALL)
        return False
    
    print(Fore.GREEN + f"\n[+] File stats:" + Style.RESET_ALL)
    print(f"  Total lines: {stats['total_lines']}")
    print(f"  Non-empty lines: {stats['non_empty']}")
    print(f"  Unique entries: {stats['unique']}")
    print(f"  File size: {stats['size_human']}")
    
    # Select category
    print(Fore.CYAN + "\nSelect category:" + Style.RESET_ALL)
    categories = list(WORDLIST_CATEGORIES.keys())
    for i, cat in enumerate(categories, 1):
        print(f"  {i}. {cat} - {WORDLIST_CATEGORIES[cat]}")
    
    cat_choice = ask_input("Select category number", "1")
    try:
        category = categories[int(cat_choice) - 1]
    except:
        print(Fore.RED + "[!] Invalid selection" + Style.RESET_ALL)
        return False
    
    # Get filename
    default_name = os.path.basename(source_path)
    new_name = ask_input("Save as filename", default_name)
    if not new_name.endswith('.txt'):
        new_name += '.txt'
    
    # Copy file
    dest_dir = os.path.join('wordlists', category)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, new_name)
    
    # Check if exists
    if os.path.exists(dest_path):
        if not ask_yes_no(f"File {new_name} already exists. Overwrite?", "n"):
            return False
    
    try:
        shutil.copy2(source_path, dest_path)
        print(Fore.GREEN + f"[+] Wordlist imported successfully to: {dest_path}" + Style.RESET_ALL)
        
        # Ask if they want to set as default for this category
        if ask_yes_no(f"Set as default wordlist for {category}?", "n"):
            CONFIG['wordlists'][category] = dest_path
            save_config()
            print(Fore.GREEN + f"[+] Set as default for {category}" + Style.RESET_ALL)
        
        return True
    except Exception as e:
        print(Fore.RED + f"[!] Import failed: {e}" + Style.RESET_ALL)
        return False

def create_custom_wordlist():
    """Create a new wordlist from user input"""
    print(Fore.CYAN + "\n=== Create Custom Wordlist ===" + Style.RESET_ALL)
    
    # Select category
    categories = list(WORDLIST_CATEGORIES.keys())
    for i, cat in enumerate(categories, 1):
        print(f"  {i}. {cat}")
    
    cat_choice = ask_input("Select category", "1")
    try:
        category = categories[int(cat_choice) - 1]
    except:
        print(Fore.RED + "[!] Invalid selection" + Style.RESET_ALL)
        return False
    
    # Get entries
    print(Fore.CYAN + "\nEnter entries (one per line). Enter blank line when done:" + Style.RESET_ALL)
    entries = []
    while True:
        entry = input("> ").strip()
        if not entry:
            break
        entries.append(entry)
    
    if not entries:
        print(Fore.YELLOW + "[!] No entries provided" + Style.RESET_ALL)
        return False
    
    # Get filename
    filename = ask_input("Enter filename", f"custom_{category}.txt")
    if not filename.endswith('.txt'):
        filename += '.txt'
    
    # Save
    dest_dir = os.path.join('wordlists', category)
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, filename)
    
    try:
        with open(dest_path, 'w') as f:
            f.write('\n'.join(entries) + '\n')
        print(Fore.GREEN + f"[+] Created wordlist with {len(entries)} entries: {dest_path}" + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.RED + f"[!] Failed to create: {e}" + Style.RESET_ALL)
        return False

def select_wordlist_for_attack(category, default_path=None):
    """Interactive wordlist selection for an attack"""
    wordlists = list_wordlists(category)
    
    if not wordlists:
        print(Fore.YELLOW + f"[!] No wordlists found in category: {category}" + Style.RESET_ALL)
        return None
    
    print(Fore.CYAN + f"\nAvailable {category} wordlists:" + Style.RESET_ALL)
    
    for i, wl in enumerate(wordlists, 1):
        stats = wl['stats']
        if stats:
            print(f"  {i}. {wl['name']} ({stats['unique']} unique, {stats['size_human']})")
        else:
            print(f"  {i}. {wl['name']} (stats unavailable)")
    
    # Add option for custom path
    print(f"  {len(wordlists) + 1}. Enter custom path")
    print(f"  0. Cancel")
    
    choice = ask_input("Select wordlist", "1")
    
    if choice == "0":
        return None
    
    if choice == str(len(wordlists) + 1):
        custom_path = ask_input("Enter full path to wordlist")
        if os.path.exists(custom_path):
            return custom_path
        else:
            print(Fore.RED + "[!] File not found" + Style.RESET_ALL)
            return None
    
    try:
        return wordlists[int(choice) - 1]['path']
    except:
        print(Fore.RED + "[!] Invalid selection" + Style.RESET_ALL)
        return None

def wordlist_management_menu():
    """Main wordlist management menu"""
    while True:
        print(Fore.CYAN + """
╔══════════════════════════════════════════════════════════╗
║              WORDLIST MANAGEMENT MENU                  ║
╠══════════════════════════════════════════════════════════╣
║  1. List All Wordlists                                 ║
║  2. Import External Wordlist                           ║
║  3. Create Custom Wordlist                             ║
║  4. View Wordlist Stats                                ║
║  5. Delete Wordlist                                    ║
║  6. Set Default Wordlist                               ║
║  7. Download Popular Wordlists                          ║
║  0. Return to Main Menu                                ║
╚══════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
        
        choice = ask_input("Select option", "0")
        
        if choice == "0":
            break
        
        elif choice == "1":
            # List all wordlists
            all_wls = list_wordlists()
            print(Fore.GREEN + "\n=== Wordlist Inventory ===" + Style.RESET_ALL)
            for category, wordlists in all_wls.items():
                print(f"\n{Fore.YELLOW}[{category}]{Style.RESET_ALL} - {WORDLIST_CATEGORIES.get(category, '')}")
                for wl in wordlists:
                    stats = wl['stats']
                    if stats:
                        print(f"  ├─ {wl['name']} ({stats['unique']} entries, {stats['size_human']})")
                    else:
                        print(f"  ├─ {wl['name']}")
        
        elif choice == "2":
            import_wordlist()
        
        elif choice == "3":
            create_custom_wordlist()
        
        elif choice == "4":
            # View stats for specific wordlist
            all_wls = list_wordlists()
            print("\nSelect category:")
            categories = list(all_wls.keys())
            for i, cat in enumerate(categories, 1):
                print(f"  {i}. {cat}")
            
            cat_choice = ask_input("Category", "1")
            try:
                category = categories[int(cat_choice) - 1]
                wordlists = list_wordlists(category)
                
                print(f"\n{Fore.CYAN}Wordlists in {category}:{Style.RESET_ALL}")
                for wl in wordlists:
                    stats = wl['stats']
                    if stats:
                        print(f"\n{Fore.GREEN}{wl['name']}:{Style.RESET_ALL}")
                        print(f"  Path: {wl['path']}")
                        print(f"  Total lines: {stats['total_lines']}")
                        print(f"  Non-empty: {stats['non_empty']}")
                        print(f"  Unique entries: {stats['unique']}")
                        print(f"  File size: {stats['size_human']}")
                        
                        # Preview first 5 entries
                        if ask_yes_no("Preview first 5 entries?", "n"):
                            with open(wl['path'], 'r') as f:
                                for i, line in enumerate(f):
                                    if i >= 5:
                                        break
                                    print(f"    {i+1}. {line.strip()}")
                    else:
                        print(f"{wl['name']}: Stats unavailable")
                        
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)
        
        elif choice == "5":
            # Delete wordlist
            all_wls = list_wordlists()
            print("\nSelect category:")
            categories = list(all_wls.keys())
            for i, cat in enumerate(categories, 1):
                print(f"  {i}. {cat}")
            
            cat_choice = ask_input("Category", "1")
            try:
                category = categories[int(cat_choice) - 1]
                wordlists = list_wordlists(category)
                
                print(f"\nSelect wordlist to delete:")
                for i, wl in enumerate(wordlists, 1):
                    print(f"  {i}. {wl['name']}")
                print("  0. Cancel")
                
                wl_choice = ask_input("Select", "0")
                if wl_choice != "0":
                    to_delete = wordlists[int(wl_choice) - 1]
                    if ask_yes_no(f"Delete {to_delete['name']}?", "n"):
                        os.remove(to_delete['path'])
                        print(Fore.GREEN + "[+] Deleted" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)
        
        elif choice == "6":
            # Set default wordlist
            print("\nSelect category to set default:")
            categories = list(WORDLIST_CATEGORIES.keys())
            for i, cat in enumerate(categories, 1):
                print(f"  {i}. {cat}")
            
            cat_choice = ask_input("Category", "1")
            try:
                category = categories[int(cat_choice) - 1]
                selected = select_wordlist_for_attack(category)
                if selected:
                    CONFIG['wordlists'][category] = selected
                    save_config()
                    print(Fore.GREEN + f"[+] Set as default for {category}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}" + Style.RESET_ALL)
        
        elif choice == "7":
            download_popular_wordlists()
        
        pause_continue()

def download_popular_wordlists():
    """Download commonly used wordlists from public sources"""
    print(Fore.CYAN + "\n=== Download Popular Wordlists ===" + Style.RESET_ALL)
    print("This will download wordlists from public repositories.")
    
    if not ask_yes_no("Continue?", "y"):
        return
    
    downloads = {
        'passwords/rockyou.txt': {
            'url': 'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
            'description': 'RockYou password list (common passwords)'
        },
        'directories/common.txt': {
            'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt',
            'description': 'Common web directories (SecLists)'
        },
        'directories/directory-list-2.3-medium.txt': {
            'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt',
            'description': 'Directory List 2.3 Medium (SecLists)'
        },
        'subdomains/subdomains-top1million-5000.txt': {
            'url': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
            'description': 'Top 5000 subdomains'
        }
    }
    
    print("\nAvailable downloads:")
    for i, (path, info) in enumerate(downloads.items(), 1):
        print(f"  {i}. {path}")
        print(f"     {info['description']}")
    print("  a. Download all")
    print("  0. Cancel")
    
    choice = ask_input("Select", "0")
    
    if choice == "0":
        return
    
    to_download = []
    if choice == "a":
        to_download = list(downloads.items())
    else:
        try:
            key = list(downloads.keys())[int(choice) - 1]
            to_download = [(key, downloads[key])]
        except:
            print(Fore.RED + "[!] Invalid selection" + Style.RESET_ALL)
            return
    
    for path, info in to_download:
        full_path = os.path.join('wordlists', path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        
        print(Fore.CYAN + f"\n[*] Downloading {path}..." + Style.RESET_ALL)
        try:
            response = requests.get(info['url'], stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(full_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            print(f"\r  Progress: {percent:.1f}% ({format_bytes(downloaded)} / {format_bytes(total_size)})", end='')
            
            print(Fore.GREEN + f"\n[+] Downloaded: {path}" + Style.RESET_ALL)
            
            # Show stats
            stats = get_wordlist_stats(full_path)
            if stats:
                print(f"  Lines: {stats['non_empty']}, Size: {stats['size_human']}")
                
        except Exception as e:
            print(Fore.RED + f"\n[!] Failed to download {path}: {e}" + Style.RESET_ALL)

def save_config():
    """Save current configuration to config.yaml"""
    try:
        with open('config.yaml', 'w') as f:
            yaml.dump(CONFIG, f, default_flow_style=False)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not save config: {e}" + Style.RESET_ALL)

def load_wordlist_for_attack(category):
    """Load wordlist with fallback to selection"""
    # Check if default exists in CONFIG
    default_path = CONFIG.get('wordlists', {}).get(category)
    
    if default_path and os.path.exists(default_path):
        if ask_yes_no(f"Use default wordlist ({os.path.basename(default_path)})?", "y"):
            return load_wordlist_file(default_path)
    
    # Otherwise select interactively
    selected_path = select_wordlist_for_attack(category)
    if selected_path:
        return load_wordlist_file(selected_path)
    
    return []

def load_wordlist_file(filepath):
    """Load and return wordlist entries"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading wordlist: {e}" + Style.RESET_ALL)
        return []

# ============================================================================
# DATABASE MODULE
# ============================================================================

class ScanDatabase:
    def __init__(self, db_path='kenumerator.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                subnet TEXT,
                total_hosts INTEGER,
                scan_type TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ip TEXT,
                mac TEXT,
                vendor TEXT,
                os TEXT,
                hostname TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port INTEGER,
                protocol TEXT,
                state TEXT,
                service TEXT,
                version TEXT,
                banner TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                service TEXT,
                port INTEGER,
                username TEXT,
                password TEXT,
                valid INTEGER,
                timestamp TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        ''')
        self.conn.commit()
    
    def save_scan(self, scan_type, subnet, total_hosts):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO scans (timestamp, subnet, total_hosts, scan_type)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, subnet, total_hosts, scan_type))
        self.conn.commit()
        return cursor.lastrowid
    
    def save_host(self, scan_id, ip, mac, vendor, os_info=None, hostname=None):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO hosts (scan_id, ip, mac, vendor, os, hostname)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, ip, mac, vendor, os_info, hostname))
        self.conn.commit()
        return cursor.lastrowid
    
    def save_port(self, host_id, port, protocol, state, service, version, banner=None):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO ports (host_id, port, protocol, state, service, version, banner)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (host_id, port, protocol, state, service, version, banner))
        self.conn.commit()
    
    def save_credential(self, host_id, service, port, username, password, valid=True):
        cursor = self.conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO credentials (host_id, service, port, username, password, valid, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (host_id, service, port, username, password, int(valid), timestamp))
        self.conn.commit()
    
    def get_scan_history(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY timestamp DESC')
        return cursor.fetchall()
    
    def get_host_by_ip(self, ip):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM hosts WHERE ip = ? ORDER BY id DESC LIMIT 1', (ip,))
        return cursor.fetchone()
    
    def close(self):
        self.conn.close()

# ============================================================================
# CONFIGURATION
# ============================================================================

def load_config(config_file='config.yaml'):
    default_config = {
        'scan': {
            'default_port_range': '1-1024',
            'full_port_range': '1-65535',
            'threads': 10,
            'timeout': 3,
        },
        'wordlists': {
            'directories': 'wordlists/directories/common.txt',
            'passwords': 'wordlists/passwords/common.txt',
            'users': 'wordlists/users/common.txt',
            'ssh_users': 'wordlists/ssh_users/common.txt',
            'ftp_users': 'wordlists/ftp_users/common.txt',
            'telnet_users': 'wordlists/telnet_users/common.txt',
            'snmp_communities': 'wordlists/snmp_communities/common.txt',
            'subdomains': 'wordlists/subdomains/common.txt'
        },
        'output': {
            'format': 'json',
            'db_path': 'kenumerator.db'
        },
        'api_keys': {
            'shodan': '',
            'virustotal': '',
            'macvendors': ''
        },
        'bruteforce': {
            'max_threads': 5,
            'timeout': 5,
        }
    }
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    for key in default_config:
                        if key in user_config:
                            if isinstance(default_config[key], dict):
                                default_config[key].update(user_config[key])
                            else:
                                default_config[key] = user_config[key]
            print(Fore.GREEN + f"[+] Loaded configuration from {config_file}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.YELLOW + f"[!] Error loading config: {e}, using defaults" + Style.RESET_ALL)
    else:
        try:
            with open(config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            print(Fore.GREEN + f"[+] Created default config: {config_file}" + Style.RESET_ALL)
        except:
            pass
    
    return default_config

# ============================================================================
# UI MODULE
# ============================================================================

def animated_task(message, func, *args, **kwargs):
    result = {}
    stop_event = threading.Event()

    def worker():
        try:
            result["value"] = func(*args, **kwargs)
        except Exception as e:
            result["error"] = e
        finally:
            stop_event.set()

    thread = threading.Thread(target=worker)
    thread.start()

    spinner = itertools.cycle(["|", "/", "-", "\\"])
    bar_width = 30
    progress = 0

    while not stop_event.is_set():
        progress = (progress + 1) % (bar_width + 1)
        bar = "#" * progress + "-" * (bar_width - progress)
        sys.stdout.write(
            f"\r{Fore.CYAN}{message} {next(spinner)} "
            f"[{bar}]{Style.RESET_ALL}"
        )
        sys.stdout.flush()
        time.sleep(0.08)

    thread.join()
    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()

    if "error" in result:
        raise result["error"]

    return result.get("value")

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    ascii_banner = r"""
██╗  ██╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗
██║ ██╔╝██╔════╝████╗  ██║██║   ██║████╗ ████║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
█████╔╝ █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║█████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝
██╔═██╗ ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██╗███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

                                      K E N U M E R A T O R   P R O
                              Interactive Network Enumeration Tool
                                         Version 2.2
                              Now with Wordlist Management System
    """
    print(Fore.CYAN + ascii_banner + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 100 + Style.RESET_ALL)
    print(Fore.GREEN + "Purpose: Interactive network enumeration with user-controlled scanning" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 100 + "\n" + Style.RESET_ALL)

def print_menu():
    menu = f"""
    {Fore.CYAN}╔══════════════════════════════════════════════════════════╗
    ║              KENUMERATOR PRO - MAIN MENU               ║
    ╠══════════════════════════════════════════════════════════╣
    ║  {Fore.GREEN}DISCOVERY:{Fore.CYAN}                                              ║
    ║     1. ARP Discovery Scan                             ║
    ║     2. Live Continuous Discovery                      ║
    ║                                                          ║
    {Fore.YELLOW}  PORT SCANNING:{Fore.CYAN}                                         ║
    ║     3. TCP Port Scan (Custom Range)                   ║
    ║     4. UDP Port Scan                                  ║
    ║     5. Full Port Scan (1-65535)                       ║
    ║     6. Stealth Scan                                   ║
    ║                                                          ║
    {Fore.MAGENTA}  ENUMERATION:{Fore.CYAN}                                           ║
    ║     7. OS Fingerprinting                              ║
    ║     8. Service Version Detection                      ║
    ║     9. Banner Grabbing                                ║
    ║    10. SMB Enumeration                                ║
    ║    11. SNMP Enumeration                               ║
    ║                                                          ║
    {Fore.BLUE}  WEB SCANNING:{Fore.CYAN}                                          ║
    ║    12. Web Directory Brute Force                      ║
    ║    13. Web Technology Detection                       ║
    ║                                                          ║
    {Fore.RED}  PENTEST:{Fore.CYAN}                                               ║
    ║    14. Vulnerability Scan                             ║
    ║    15. SSH Brute Force                                ║
    ║    16. FTP Brute Force                                ║
    ║    17. Telnet Brute Force                             ║
    ║                                                          ║
    {Fore.WHITE}  EXTERNAL:{Fore.CYAN}                                              ║
    ║    18. Shodan Lookup                                  ║
    ║    19. VirusTotal Lookup                              ║
    ║                                                          ║
    {Fore.GREEN}  WORDLISTS:{Fore.CYAN}                                             ║
    ║    20. Wordlist Management                            ║
    ║                                                          ║
    {Fore.CYAN}  OUTPUT:{Fore.CYAN}                                                ║
    ║    21. View Discovered Devices                        ║
    ║    22. Network Topology Map                           ║
    ║    23. Export Results (JSON/CSV/HTML)               ║
    ║    24. View Scan History                              ║
    ║                                                          ║
    ║     0. Exit                                           ║
    ╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(menu)

# ============================================================================
# NETWORK MODULE
# ============================================================================

def get_local_subnet():
    try:
        gateway_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        iface_data = netifaces.ifaddresses(gateway_iface)[netifaces.AF_INET][0]
        ip = iface_data['addr']
        netmask = iface_data['netmask']
        cidr = IPNetwork(f"{ip}/{netmask}")
        return str(cidr)
    except Exception as e:
        print(Fore.RED + f"[!] Error getting subnet: {e}" + Style.RESET_ALL)
        return None

def lookup_vendor(mac):
    try:
        api_key = CONFIG.get('api_keys', {}).get('macvendors', '')
        if api_key:
            url = f"https://api.macvendors.com/v1/{mac}"
            headers = {'Authorization': f'Bearer {api_key}'}
            response = requests.get(url, headers=headers, timeout=3)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {}).get('organization_name', 'Unknown')
        
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text
        return "Unknown Vendor"
    except:
        return "Unknown Vendor"

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"

def arp_scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        mac = element[1].hwsrc
        vendor = lookup_vendor(mac)
        clients_list.append({
            "ip": element[1].psrc, 
            "mac": mac, 
            "vendor": vendor,
            "hostname": get_hostname(element[1].psrc)
        })
    return clients_list

# ============================================================================
# SCANNING MODULE
# ============================================================================

def record_scan_result(ip, mac, vendor, scan_type, protocol, ports, os_info=None):
    with results_lock:
        if ip not in device_results:
            device_results[ip] = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "os": os_info,
                "scans": []
            }

        if mac:
            device_results[ip]["mac"] = mac
        if vendor:
            device_results[ip]["vendor"] = vendor
        if os_info:
            device_results[ip]["os"] = os_info

        saved_ports = {}
        for port, data in ports.items():
            if isinstance(data, dict):
                saved_ports[str(port)] = dict(data)
            else:
                saved_ports[str(port)] = {"state": data}

        device_results[ip]["scans"].append({
            "type": scan_type,
            "protocol": protocol,
            "ports": saved_ports,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

def port_scan(ip, mac=None, vendor=None, port_range=None, stealth=False):
    if port_range is None:
        port_range = CONFIG['scan']['default_port_range']
    
    print(Fore.YELLOW + f"\n[+] Starting {'stealth ' if stealth else ''}TCP port scan on {ip} (ports {port_range})..." + Style.RESET_ALL)
    nm = nmap.PortScanner()
    
    try:
        args = "-sS" if stealth else "-sT"
        args += " -T4"
        
        def do_scan():
            return nm.scan(ip, port_range, arguments=args)
        
        animated_task(f"Running {'stealth ' if stealth else ''}TCP scan", do_scan)
        
        if ip in nm.all_hosts() and 'tcp' in nm[ip]:
            print(f"\n{Fore.GREEN}Nmap TCP scan report for {ip}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Host is up{Style.RESET_ALL}")
            if mac and vendor:
                print(f"MAC Address: {mac} ({vendor})")
            
            open_ports = []
            for port in sorted(nm[ip]['tcp']):
                state = nm[ip]['tcp'][port]['state']
                service = nm[ip]['tcp'][port]['name']
                version = nm[ip]['tcp'][port].get('version', '')
                
                color = Fore.GREEN if state == 'open' else Fore.RED
                print(f"{color}Port {port}/tcp: {state}\tService: {service} {version}{Style.RESET_ALL}")
                
                if state == 'open':
                    open_ports.append(port)
            
            record_scan_result(ip, mac, vendor, "tcp_stealth" if stealth else "tcp", "tcp", nm[ip]['tcp'])
            
            print(f"\n{Fore.GREEN}Scan complete. Found {len(open_ports)} open ports.{Style.RESET_ALL}")
            
            if open_ports:
                if ask_yes_no("Would you like to grab banners from open ports?", "n"):
                    print(Fore.CYAN + f"[*] Grabbing banners from {len(open_ports)} open ports..." + Style.RESET_ALL)
                    for port in open_ports:
                        banner = grab_banner(ip, port)
                        if banner:
                            print(f"  Port {port}: {banner[:100]}...")
            
            if ask_yes_no("Would you like to run service version detection?", "n"):
                version_scan(ip, mac, vendor)
            
            if ask_yes_no("Would you like to perform OS fingerprinting?", "n"):
                os_fingerprint(ip, mac, vendor)
            
            if ask_yes_no("Would you like to run vulnerability scan?", "n"):
                vuln_scan(ip, mac, vendor)
            
            return nm[ip]['tcp']
        else:
            print(Fore.RED + "[!] Host did not respond to TCP scan" + Style.RESET_ALL)
            
            if ask_yes_no("Would you like to retry with -Pn (skip host discovery)?", "n"):
                return pn_scan(ip, mac, vendor, port_range)
            
            return {}
    except Exception as e:
        print(Fore.RED + f"[!] TCP port scan error: {e}" + Style.RESET_ALL)
        return {}

def pn_scan(ip, mac=None, vendor=None, port_range=None):
    if port_range is None:
        port_range = CONFIG['scan']['default_port_range']
    
    print(Fore.YELLOW + f"\n[+] Starting forced -Pn TCP scan on {ip}..." + Style.RESET_ALL)
    nm = nmap.PortScanner()
    try:
        def do_scan():
            return nm.scan(ip, port_range, arguments="-Pn -T4")
        
        animated_task("Running forced TCP scan", do_scan)
        
        if ip in nm.all_hosts() and 'tcp' in nm[ip]:
            print(f"\n{Fore.GREEN}Nmap forced TCP scan report for {ip}{Style.RESET_ALL}")
            for port in sorted(nm[ip]['tcp']):
                state = nm[ip]['tcp'][port]['state']
                service = nm[ip]['tcp'][port]['name']
                print(f"Port {port}/tcp: {state}\tService: {service}")
            record_scan_result(ip, mac, vendor, "forced_tcp", "tcp", nm[ip]['tcp'])
            
            if ask_yes_no("Would you like to run service version detection?", "n"):
                version_scan(ip, mac, vendor)
            
            return nm[ip]['tcp']
        else:
            print(Fore.YELLOW + "[!] Host still not responding" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] -Pn TCP scan error: {e}" + Style.RESET_ALL)
    return {}

def udp_scan(ip, mac=None, vendor=None, port_range=None):
    if port_range is None:
        port_range = ask_input("Enter UDP port range", "1-1000")
    
    print(Fore.YELLOW + f"\n[+] Starting UDP scan on {ip} (ports {port_range})..." + Style.RESET_ALL)
    nm = nmap.PortScanner()
    try:
        def do_scan():
            return nm.scan(ip, port_range, arguments="-sU -T4")
        
        animated_task("Running UDP scan", do_scan)
        
        if ip in nm.all_hosts() and 'udp' in nm[ip]:
            print(f"\n{Fore.GREEN}Nmap UDP scan report for {ip}{Style.RESET_ALL}")
            for port in sorted(nm[ip]['udp']):
                state = nm[ip]['udp'][port]['state']
                service = nm[ip]['udp'][port]['name']
                print(f"Port {port}/udp: {state}\tService: {service}")
            record_scan_result(ip, mac, vendor, "udp", "udp", nm[ip]['udp'])
            
            if ask_yes_no("Would you like to attempt version detection on UDP ports?", "n"):
                print(Fore.YELLOW + "[*] Note: UDP version detection is slow and unreliable" + Style.RESET_ALL)
                
        print(f"\n{Fore.YELLOW}UDP scan completed.{Style.RESET_ALL}")
    except Exception as e:
        print(Fore.RED + f"[!] UDP scan error: {e}" + Style.RESET_ALL)
    return {}

def version_scan(ip, mac=None, vendor=None):
    print(Fore.YELLOW + f"\n[+] Starting version scan (-sV) on {ip}..." + Style.RESET_ALL)
    nm = nmap.PortScanner()
    try:
        def do_scan():
            return nm.scan(ip, arguments="-sV -T4")
        
        animated_task("Running version scan", do_scan)
        
        if ip in nm.all_hosts() and 'tcp' in nm[ip]:
            print(f"\n{Fore.GREEN}Version scan results for {ip}:{Style.RESET_ALL}")
            for port in sorted(nm[ip]['tcp']):
                state = nm[ip]['tcp'][port]['state']
                service = nm[ip]['tcp'][port]['name']
                product = nm[ip]['tcp'][port].get('product', '')
                version = nm[ip]['tcp'][port].get('version', '')
                extrainfo = nm[ip]['tcp'][port].get('extrainfo', '')
                
                info_str = f"{product} {version} {extrainfo}".strip()
                print(f"Port {port}/tcp: {state}\tService: {service}\t{info_str}")
            
            record_scan_result(ip, mac, vendor, "version", "tcp", nm[ip]['tcp'])
            
            if ask_yes_no("Would you like to run vulnerability scan on detected services?", "n"):
                vuln_scan(ip, mac, vendor)
                
            return nm[ip]['tcp']
    except Exception as e:
        print(Fore.RED + f"[!] Version scan error: {e}" + Style.RESET_ALL)
    return {}

def vuln_scan(ip, mac=None, vendor=None):
    print(Fore.YELLOW + f"\n[+] Starting vulnerability scan on {ip}..." + Style.RESET_ALL)
    print(Fore.RED + "[!] This may take several minutes..." + Style.RESET_ALL)
    
    if not ask_yes_no("Continue with vulnerability scan?", "y"):
        return {}
    
    nm = nmap.PortScanner()
    try:
        def do_scan():
            scripts = "vuln,http-vuln-*,ssl-*,ftp-anon,banner"
            return nm.scan(ip, arguments=f"-sV --script={scripts} -T4")
        
        animated_task("Running vulnerability scan", do_scan)
        
        vulns_found = []
        if ip in nm.all_hosts() and 'tcp' in nm[ip]:
            print(f"\n{Fore.GREEN}Vulnerability scan results for {ip}:{Style.RESET_ALL}")
            for port in sorted(nm[ip]['tcp']):
                state = nm[ip]['tcp'][port]['state']
                service = nm[ip]['tcp'][port]['name']
                print(f"\nPort {port}/tcp: {state}\tService: {service}")
                
                if 'script' in nm[ip]['tcp'][port]:
                    for script, output in nm[ip]['tcp'][port]['script'].items():
                        if output and output.strip():
                            if 'VULNERABLE' in output or 'CVE' in output:
                                print(Fore.RED + f"  [CRITICAL] {script}: {output[:100]}" + Style.RESET_ALL)
                                vulns_found.append({'port': port, 'script': script, 'output': output})
                            elif 'vuln' in script.lower():
                                print(Fore.YELLOW + f"  [VULN] {script}: {output[:100]}" + Style.RESET_ALL)
                                vulns_found.append({'port': port, 'script': script, 'output': output})
                            else:
                                print(f"  [Info] {script}: {output[:100]}")
            
            record_scan_result(ip, mac, vendor, "vulnerability", "tcp", nm[ip]['tcp'])
            
            if vulns_found:
                print(Fore.RED + f"\n[!] {len(vulns_found)} potential vulnerabilities found!" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "\n[+] No obvious vulnerabilities detected" + Style.RESET_ALL)
                
            return nm[ip]['tcp']
    except Exception as e:
        print(Fore.RED + f"[!] Vulnerability scan error: {e}" + Style.RESET_ALL)
    return {}

def os_fingerprint(ip, mac=None, vendor=None):
    print(Fore.YELLOW + f"\n[+] Starting OS fingerprinting on {ip}..." + Style.RESET_ALL)
    
    if not ask_yes_no("OS fingerprinting requires root/admin. Continue?", "y"):
        return None
    
    nm = nmap.PortScanner()
    try:
        def do_scan():
            return nm.scan(ip, arguments="-O --osscan-guess -T4")
        
        animated_task("Running OS detection", do_scan)
        
        os_info = None
        if ip in nm.all_hosts():
            if 'osmatch' in nm[ip] and nm[ip]['osmatch']:
                match = nm[ip]['osmatch'][0]
                os_info = match.get('name', 'Unknown')
                accuracy = match.get('accuracy', '0')
                print(f"\n{Fore.GREEN}OS Detection Results:{Style.RESET_ALL}")
                print(f"OS: {os_info}")
                print(f"Accuracy: {accuracy}%")
                
                if 'osclass' in match and match['osclass']:
                    for osc in match['osclass']:
                        print(f"Type: {osc.get('type', 'Unknown')}")
                        print(f"Vendor: {osc.get('vendor', 'Unknown')}")
                        print(f"Family: {osc.get('osfamily', 'Unknown')}")
            else:
                print(Fore.YELLOW + "[!] Could not determine OS" + Style.RESET_ALL)
            
            if ip in device_results:
                device_results[ip]['os'] = os_info
            
            return os_info
    except Exception as e:
        print(Fore.RED + f"[!] OS fingerprint error: {e}" + Style.RESET_ALL)
    return None

def stealth_scan(ip, mac=None, vendor=None):
    print(Fore.YELLOW + f"\n[+] Starting stealth scan on {ip}..." + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Using fragmentation, decoys, and timing obfuscation" + Style.RESET_ALL)
    
    if not ask_yes_no("Stealth scan requires root/admin. Continue?", "y"):
        return {}
    
    port_range = ask_input("Enter port range", "1-1024")
    
    nm = nmap.PortScanner()
    try:
        args = "-sS -f -T2 --randomize-hosts --spoof-mac 0"
        
        def do_scan():
            return nm.scan(ip, port_range, arguments=args)
        
        animated_task("Running stealth scan", do_scan)
        
        if ip in nm.all_hosts() and 'tcp' in nm[ip]:
            print(f"\n{Fore.GREEN}Stealth scan results for {ip}:{Style.RESET_ALL}")
            for port in sorted(nm[ip]['tcp']):
                state = nm[ip]['tcp'][port]['state']
                service = nm[ip]['tcp'][port]['name']
                print(f"Port {port}/tcp: {state}\tService: {service}")
            record_scan_result(ip, mac, vendor, "stealth", "tcp", nm[ip]['tcp'])
            
            if ask_yes_no("Would you like to run version detection on discovered ports?", "n"):
                version_scan(ip, mac, vendor)
                
            return nm[ip]['tcp']
    except Exception as e:
        print(Fore.RED + f"[!] Stealth scan error: {e}" + Style.RESET_ALL)
    return {}

# ============================================================================
# ENUMERATION MODULE
# ============================================================================

def grab_banner(ip, port, timeout=3):
    banners = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        probes = [b"\r\n", b"HEAD / HTTP/1.0\r\n\r\n", b"HELP\r\n", b"VERSION\r\n", b"\x00"]
        
        for probe in probes:
            try:
                sock.send(probe)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner and len(banner) > 3:
                    banners['banner'] = banner
                    break
            except:
                continue
                
        if not banners:
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    banners['banner'] = banner
            except:
                pass
                
    except:
        pass
    finally:
        sock.close()
    
    return banners.get('banner', '')

def banner_grab_scan(ip):
    print(Fore.YELLOW + f"\n[+] Banner Grabbing for {ip}" + Style.RESET_ALL)
    
    custom_ports = ask_input("Enter specific ports (comma-separated) or press Enter for common ports", "")
    
    if custom_ports:
        try:
            ports = [int(p.strip()) for p in custom_ports.split(",")]
        except:
            print(Fore.RED + "[!] Invalid port format" + Style.RESET_ALL)
            return {}
    else:
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    print(Fore.CYAN + f"[*] Grabbing banners from {len(ports)} ports..." + Style.RESET_ALL)
    
    results = {}
    for port in ports:
        banner = grab_banner(ip, port)
        if banner:
            results[port] = banner
            print(f"{Fore.GREEN}Port {port}: {banner[:80]}...{Style.RESET_ALL}")
    
    if not results:
        print(Fore.YELLOW + "[!] No banners retrieved" + Style.RESET_ALL)
    
    if results and ask_yes_no("Save banner results to device record?", "y"):
        if ip not in device_results:
            device_results[ip] = {"ip": ip, "banners": results}
        else:
            device_results[ip]['banners'] = results
    
    return results

def detect_web_tech(ip, port=None):
    if port is None:
        port = int(ask_input("Enter web port", "80"))
    
    print(Fore.YELLOW + f"\n[+] Detecting web technologies on {ip}:{port}..." + Style.RESET_ALL)
    
    tech_info = {}
    try:
        url = f"http://{ip}:{port}"
        response = requests.head(url, timeout=5, allow_redirects=True, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        headers = response.headers
        
        tech_info['server'] = headers.get('Server', 'Unknown')
        tech_info['x-powered-by'] = headers.get('X-Powered-By', 'Unknown')
        
        try:
            body_response = requests.get(url, timeout=5, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            body = body_response.text.lower()
            
            if 'wp-content' in body or 'wordpress' in body:
                tech_info['cms'] = 'WordPress'
            elif 'drupal' in body:
                tech_info['cms'] = 'Drupal'
            elif 'joomla' in body:
                tech_info['cms'] = 'Joomla'
            elif 'django' in body:
                tech_info['framework'] = 'Django'
            elif 'laravel' in body:
                tech_info['framework'] = 'Laravel'
            elif 'react' in body:
                tech_info['framework'] = 'React'
                
        except:
            pass
            
        print(f"\n{Fore.GREEN}Web Technology Detection ({ip}:{port}):{Style.RESET_ALL}")
        for key, value in tech_info.items():
            print(f"  {key}: {value}")
            
        if ask_yes_no("Would you like to run directory brute force on this web server?", "n"):
            dir_buster(ip, port)
            
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not detect web tech: {e}" + Style.RESET_ALL)
    
    return tech_info

# ============================================================================
# SMB ENUMERATION MODULE
# ============================================================================

def smb_enum(ip):
    if not IMPOCKET_AVAILABLE:
        print(Fore.RED + "[!] Impacket not installed. Run: pip install impacket" + Style.RESET_ALL)
        return {}
    
    print(Fore.YELLOW + f"\n[+] SMB Enumeration for {ip}" + Style.RESET_ALL)
    
    if not ask_yes_no("Attempt null session authentication?", "y"):
        return {}
    
    results = {
        'shares': [],
        'os_info': {},
        'null_session': False
    }
    
    try:
        conn = SMBConnection(ip, ip, timeout=3)
        try:
            conn.login('', '')
            results['null_session'] = True
            print(Fore.GREEN + "[+] Null session successful!" + Style.RESET_ALL)
        except:
            print(Fore.YELLOW + "[!] Null session failed" + Style.RESET_ALL)
            if ask_yes_no("Try guest authentication?", "n"):
                try:
                    conn.login('guest', '')
                    print(Fore.GREEN + "[+] Guest login successful!" + Style.RESET_ALL)
                except:
                    print(Fore.RED + "[!] Guest login failed" + Style.RESET_ALL)
                    return results
        
        if ask_yes_no("Enumerate SMB shares?", "y"):
            try:
                shares = conn.listShares()
                print(f"\n{Fore.GREEN}SMB Shares:{Style.RESET_ALL}")
                for share in shares:
                    share_name = share['shi1_netname'][:-1]
                    remark = share['shi1_remark'][:-1] if share['shi1_remark'] else ''
                    
                    results['shares'].append({
                        'name': share_name,
                        'remark': remark
                    })
                    print(f"  \\\\{ip}\\{share_name} - {remark}")
                    
                    if share_name not in ['IPC$', 'ADMIN$', 'C$'] and ask_yes_no(f"List contents of {share_name}?", "n"):
                        try:
                            files = conn.listPath(share_name, '*')
                            print(f"    Contents ({len(files)} items):")
                            for f in files[:10]:
                                print(f"      {f.get_longname()}")
                        except Exception as e:
                            print(f"    [!] Cannot list: {e}")
                            
            except Exception as e:
                print(Fore.YELLOW + f"[!] Could not list shares: {e}" + Style.RESET_ALL)
        
        if ask_yes_no("Retrieve server information?", "y"):
            try:
                results['os_info'] = {
                    'os': conn.getServerOS(),
                    'domain': conn.getServerDomain(),
                    'name': conn.getServerName()
                }
                print(f"\n{Fore.GREEN}Server Info:{Style.RESET_ALL}")
                print(f"  OS: {results['os_info']['os']}")
                print(f"  Domain: {results['os_info']['domain']}")
                print(f"  Name: {results['os_info']['name']}")
            except:
                pass
        
        conn.logoff()
        
    except Exception as e:
        print(Fore.RED + f"[!] SMB enumeration error: {e}" + Style.RESET_ALL)
        results['error'] = str(e)
    
    return results

# ============================================================================
# SNMP ENUMERATION MODULE
# ============================================================================

def snmp_enum(ip, community=None):
    if not SNMP_AVAILABLE:
        print(Fore.RED + "[!] PySNMP not installed. Run: pip install pysnmp" + Style.RESET_ALL)
        return {}
    
    print(Fore.YELLOW + f"\n[+] SNMP Enumeration for {ip}" + Style.RESET_ALL)
    
    # Use wordlist for communities if available
    if community:
        communities = [community]
    else:
        # Try to load from wordlist
        communities = load_wordlist_for_attack('snmp_communities')
        if not communities:
            custom = ask_input("Enter community string(s), comma-separated", "public")
            communities = [c.strip() for c in custom.split(",")]
    
    results = {}
    
    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
    }
    
    for comm in communities:
        print(f"  Trying community: {comm}")
        comm_results = {}
        
        for name, oid in oids.items():
            try:
                errorIndication, errorStatus, errorIndex, varBinds = next(
                    getCmd(SnmpEngine(),
                           CommunityData(comm),
                           UdpTransportTarget((ip, 161), timeout=2, retries=1),
                           ContextData(),
                           ObjectType(ObjectIdentity(oid)))
                )
                
                if not errorIndication and not errorStatus:
                    for varBind in varBinds:
                        value = str(varBind[1])
                        if value and value != 'No Such Object':
                            comm_results[name] = value
            except:
                pass
        
        if comm_results:
            results[comm] = comm_results
            print(Fore.GREEN + f"  [+] Success with community '{comm}'" + Style.RESET_ALL)
            
            print(f"\n{Fore.GREEN}SNMP Information ({comm}):{Style.RESET_ALL}")
            for key, value in comm_results.items():
                print(f"  {key}: {value[:100]}")
            
            if ask_yes_no("Perform extended OID walk (may be slow)?", "n"):
                print(Fore.YELLOW + "[*] Extended walk not implemented in this version" + Style.RESET_ALL)
    
    if not results:
        print(Fore.YELLOW + "[!] SNMP enumeration failed" + Style.RESET_ALL)
    
    return results

# ============================================================================
# WEB SCANNING MODULE
# ============================================================================

def dir_buster(ip, port=None, wordlist=None):
    if port is None:
        port = int(ask_input("Enter web port", "80"))
    
    # Use wordlist management system
    if wordlist is None:
        wordlist = select_wordlist_for_attack('directories', CONFIG.get('wordlists', {}).get('directories'))
        if not wordlist:
            print(Fore.RED + "[!] No wordlist selected" + Style.RESET_ALL)
            return []
    
    if not os.path.exists(wordlist):
        print(Fore.RED + f"[!] Wordlist not found: {wordlist}" + Style.RESET_ALL)
        return []
    
    extensions_input = ask_input("Enter extensions to test (comma-separated)", "php,asp,html,txt")
    extensions = [''] + [f".{e.strip()}" for e in extensions_input.split(",")]
    
    print(Fore.YELLOW + f"\n[+] Directory Brute Force: http://{ip}:{port}/" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Wordlist: {os.path.basename(wordlist)}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Extensions: {extensions}" + Style.RESET_ALL)
    
    if not ask_yes_no("Start brute force? This may take time.", "y"):
        return []
    
    found = []
    
    with open(wordlist, 'r') as f:
        directories = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Testing {len(directories)} directories with {len(extensions)} extensions...")
    
    def check_path(directory):
        results = []
        for ext in extensions:
            url = f"http://{ip}:{port}/{directory}{ext}"
            try:
                response = requests.head(url, timeout=3, allow_redirects=False, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response.status_code in [200, 201]:
                    results.append({'url': url, 'status': response.status_code, 'type': 'OK'})
                    print(Fore.GREEN + f"  [+] Found: {url} ({response.status_code})" + Style.RESET_ALL)
                elif response.status_code in [301, 302]:
                    results.append({'url': url, 'status': response.status_code, 'type': 'REDIRECT'})
                    print(Fore.CYAN + f"  [→] Redirect: {url}" + Style.RESET_ALL)
                elif response.status_code == 401:
                    results.append({'url': url, 'status': response.status_code, 'type': 'AUTH_REQUIRED'})
                    print(Fore.YELLOW + f"  [!] Auth Required: {url}" + Style.RESET_ALL)
                elif response.status_code == 403:
                    results.append({'url': url, 'status': response.status_code, 'type': 'FORBIDDEN'})
                    print(Fore.MAGENTA + f"  [-] Forbidden: {url}" + Style.RESET_ALL)
            except:
                pass
        return results
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_path, d) for d in directories]
        for future in futures:
            try:
                result = future.result()
                if result:
                    found.extend(result)
            except:
                pass
    
    print(f"\n{Fore.GREEN}[+] Found {len(found)} results.{Style.RESET_ALL}")
    
    if found and ask_yes_no("Save directory brute force results?", "y"):
        filename = f"dirbuster_{ip}_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for item in found:
                f.write(f"{item['url']} ({item['status']}) - {item['type']}\n")
        print(Fore.GREEN + f"[+] Saved to {filename}" + Style.RESET_ALL)
    
    return found

# ============================================================================
# BRUTE FORCE MODULE
# ============================================================================

def ssh_bruteforce(ip, port=None):
    if port is None:
        port = int(ask_input("Enter SSH port", "22"))
    
    print(Fore.YELLOW + f"\n[+] SSH Brute Force: {ip}:{port}" + Style.RESET_ALL)
    print(Fore.RED + "[!] Only use on systems you own or have permission to test!" + Style.RESET_ALL)
    
    if not ask_yes_no("Do you have authorization to brute force this target?", "n"):
        print(Fore.YELLOW + "[!] Cancelled." + Style.RESET_ALL)
        return []
    
    # Load users from wordlist or specific input
    username = ask_input("Enter specific username or press Enter for wordlist", "")
    if username:
        users = [username]
    else:
        users = load_wordlist_for_attack('ssh_users')
        if not users:
            users = load_wordlist_for_attack('users')
        if not users:
            users = ['root', 'admin', 'user', 'test']
        print(f"[*] Loaded {len(users)} usernames from wordlist")
    
    # Load passwords
    passwords = load_wordlist_for_attack('passwords')
    if not passwords:
        passwords = ['password', '123456', 'admin', 'root']
    print(f"[*] Loaded {len(passwords)} passwords from wordlist")
    
    max_attempts = int(ask_input("Max attempts (0 for all combinations)", "50"))
    if max_attempts > 0:
        passwords = passwords[:max_attempts]
    
    if not ask_yes_no(f"Start brute forcing with {len(users)} users and {len(passwords)} passwords?", "y"):
        return []
    
    valid_creds = []
    
    def try_login(user, pwd):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=user, password=pwd, 
                       timeout=CONFIG['bruteforce']['timeout'], 
                       banner_timeout=5, auth_timeout=5)
            ssh.close()
            return (user, pwd)
        except paramiko.AuthenticationException:
            return None
        except:
            return None
    
    count = 0
    total = len(users) * len(passwords)
    
    with ThreadPoolExecutor(max_workers=CONFIG['bruteforce']['max_threads']) as executor:
        futures = []
        for user in users:
            for pwd in passwords:
                futures.append(executor.submit(try_login, user, pwd))
        
        for future in futures:
            count += 1
            if count % 10 == 0:
                print(f"  Progress: {count}/{total}", end='\r')
            result = future.result()
            if result:
                valid_creds.append(result)
                print(Fore.GREEN + f"\n  [+] SUCCESS: {result[0]}:{result[1]}" + Style.RESET_ALL)
                
                if not ask_yes_no("Continue scanning for more credentials?", "n"):
                    break
    
    if valid_creds:
        print(Fore.GREEN + f"\n[+] Found {len(valid_creds)} valid credential(s)!" + Style.RESET_ALL)
        if DB_CONNECTION:
            host_record = DB_CONNECTION.get_host_by_ip(ip)
            if host_record:
                for cred in valid_creds:
                    DB_CONNECTION.save_credential(host_record[0], 'ssh', port, cred[0], cred[1])
    else:
        print(Fore.YELLOW + "\n[!] No valid credentials found" + Style.RESET_ALL)
    
    return valid_creds

def ftp_bruteforce(ip, port=None):
    if port is None:
        port = int(ask_input("Enter FTP port", "21"))
    
    print(Fore.YELLOW + f"\n[+] FTP Brute Force: {ip}:{port}" + Style.RESET_ALL)
    print(Fore.RED + "[!] Only use on systems you own or have permission to test!" + Style.RESET_ALL)
    
    if not ask_yes_no("Do you have authorization?", "n"):
        return []
    
    # Load from wordlists
    users = load_wordlist_for_attack('ftp_users')
    if not users:
        users = load_wordlist_for_attack('users')
    if not users:
        users = ['ftp', 'anonymous', 'admin', 'root'][:10]
    
    passwords = load_wordlist_for_attack('passwords')
    if not passwords:
        passwords = ['password', '123456', 'admin', 'root'][:20]
    
    valid_creds = []
    
    def try_login(user, pwd):
        try:
            ftp = ftplib.FTP(ip, timeout=CONFIG['bruteforce']['timeout'])
            ftp.login(user, pwd)
            ftp.quit()
            return (user, pwd)
        except:
            return None
    
    if not ask_yes_no(f"Start brute forcing with {len(users)} users and {len(passwords)} passwords?", "y"):
        return []
    
    with ThreadPoolExecutor(max_workers=CONFIG['bruteforce']['max_threads']) as executor:
        futures = []
        for user in users:
            for pwd in passwords:
                futures.append(executor.submit(try_login, user, pwd))
        
        for future in futures:
            result = future.result()
            if result:
                valid_creds.append(result)
                print(Fore.GREEN + f"  [+] SUCCESS: {result[0]}:{result[1]}" + Style.RESET_ALL)
                if not ask_yes_no("Continue?", "n"):
                    break
    
    return valid_creds

def telnet_bruteforce(ip, port=None):
    if port is None:
        port = int(ask_input("Enter Telnet port", "23"))
    
    print(Fore.YELLOW + f"\n[+] Telnet Brute Force: {ip}:{port}" + Style.RESET_ALL)
    print(Fore.RED + "[!] Warning: Telnet is plaintext and insecure!" + Style.RESET_ALL)
    
    if not ask_yes_no("Do you have authorization?", "n"):
        return []
    
    # Load from wordlists
    users = load_wordlist_for_attack('telnet_users')
    if not users:
        users = load_wordlist_for_attack('users')
    if not users:
        users = ['root', 'admin', 'user'][:5]
    
    passwords = load_wordlist_for_attack('passwords')
    if not passwords:
        passwords = ['password', '123456', 'admin'][:10]
    
    valid_creds = []
    
    if not ask_yes_no("Start brute force (will be slow)?", "y"):
        return []
    
    for user in users:
        for pwd in passwords:
            try:
                tn = telnetlib.Telnet(ip, port, timeout=5)
                tn.read_until(b"login: ", timeout=3)
                tn.write(user.encode('ascii') + b"\n")
                tn.read_until(b"Password: ", timeout=3)
                tn.write(pwd.encode('ascii') + b"\n")
                
                response = tn.read_until(b"$", timeout=3)
                if b"$" in response or b"#" in response or b">" in response:
                    valid_creds.append((user, pwd))
                    print(Fore.GREEN + f"  [+] SUCCESS: {user}:{pwd}" + Style.RESET_ALL)
                    tn.close()
                    if not ask_yes_no("Continue?", "n"):
                        return valid_creds
                    break
                tn.close()
            except:
                pass
    
    return valid_creds

# ============================================================================
# EXTERNAL API MODULE
# ============================================================================

def shodan_lookup(ip):
    api_key = CONFIG.get('api_keys', {}).get('shodan', '')
    if not api_key:
        print(Fore.YELLOW + "[!] No Shodan API key configured in config.yaml" + Style.RESET_ALL)
        return None
    
    print(Fore.YELLOW + f"\n[+] Querying Shodan for {ip}..." + Style.RESET_ALL)
    
    if not ask_yes_no("This will make an external API call. Continue?", "y"):
        return None
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            result = {
                'ports': data.get('ports', []),
                'vulns': data.get('vulns', []),
                'tags': data.get('tags', []),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'os': data.get('os', 'Unknown'),
                'country': data.get('country_name', 'Unknown')
            }
            
            print(f"\n{Fore.GREEN}Shodan Results:{Style.RESET_ALL}")
            print(f"  Organization: {result['org']}")
            print(f"  ISP: {result['isp']}")
            print(f"  OS: {result['os']}")
            print(f"  Open Ports: {result['ports']}")
            
            if result['vulns']:
                print(Fore.RED + f"  [!] Vulnerabilities: {len(result['vulns'])}" + Style.RESET_ALL)
                for vuln in result['vulns'][:5]:
                    print(f"    - {vuln}")
            
            if result['ports'] and ask_yes_no("Scan discovered ports with Nmap?", "n"):
                ports_str = ",".join(str(p) for p in result['ports'])
                port_scan(ip, port_range=ports_str)
            
            return result
        else:
            print(Fore.YELLOW + f"[!] Shodan API error: {response.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Shodan lookup error: {e}" + Style.RESET_ALL)
    
    return None

def virustotal_lookup(ip):
    api_key = CONFIG.get('api_keys', {}).get('virustotal', '')
    if not api_key:
        print(Fore.YELLOW + "[!] No VirusTotal API key configured" + Style.RESET_ALL)
        return None
    
    print(Fore.YELLOW + f"\n[+] Querying VirusTotal for {ip}..." + Style.RESET_ALL)
    
    if not ask_yes_no("This will make an external API call. Continue?", "y"):
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attrs = data['data']['attributes']
            
            result = {
                'reputation': attrs.get('reputation', 0),
                'malicious': attrs['last_analysis_stats'].get('malicious', 0),
                'suspicious': attrs['last_analysis_stats'].get('suspicious', 0),
                'country': attrs.get('country', 'Unknown')
            }
            
            print(f"\n{Fore.GREEN}VirusTotal Results:{Style.RESET_ALL}")
            print(f"  Reputation Score: {result['reputation']}")
            print(f"  Malicious: {result['malicious']}")
            print(f"  Suspicious: {result['suspicious']}")
            print(f"  Country: {result['country']}")
            
            if result['malicious'] > 0:
                print(Fore.RED + f"  [!] IP flagged as malicious!" + Style.RESET_ALL)
            
            return result
        else:
            print(Fore.YELLOW + f"[!] VirusTotal API error: {response.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] VirusTotal lookup error: {e}" + Style.RESET_ALL)
    
    return None

# ============================================================================
# TOPOLOGY & VISUALIZATION
# ============================================================================

def build_topology(devices=None):
    if not GRAPH_AVAILABLE:
        print(Fore.RED + "[!] Install networkx and matplotlib: pip install networkx matplotlib" + Style.RESET_ALL)
        return None
    
    if devices is None:
        if not device_results:
            print(Fore.YELLOW + "[!] No devices in memory. Run discovery first." + Style.RESET_ALL)
            return None
        devices = [{"ip": k, **v} for k, v in device_results.items()]
    
    print(Fore.YELLOW + "\n[+] Building network topology..." + Style.RESET_ALL)
    
    if not ask_yes_no(f"Create topology map for {len(devices)} devices?", "y"):
        return None
    
    G = nx.Graph()
    
    for device in devices:
        label = f"{device['ip']}\n{device.get('vendor', 'Unknown')[:15]}"
        G.add_node(device['ip'], 
                  mac=device.get('mac', ''), 
                  vendor=device.get('vendor', 'Unknown'),
                  label=label)
    
    for i, d1 in enumerate(devices):
        for d2 in devices[i+1:]:
            if d1['ip'].rsplit('.', 1)[0] == d2['ip'].rsplit('.', 1)[0]:
                G.add_edge(d1['ip'], d2['ip'])
    
    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, k=2, iterations=50)
    
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=3000, alpha=0.8)
    nx.draw_networkx_edges(G, pos, width=2, alpha=0.5)
    nx.draw_networkx_labels(G, pos, 
                           labels={n: G.nodes[n].get('label', n) for n in G.nodes()},
                           font_size=8)
    
    plt.title("Network Topology", fontsize=16)
    plt.axis('off')
    
    filename = f"topology_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    plt.savefig(filename, dpi=150, bbox_inches='tight')
    print(Fore.GREEN + f"[+] Topology saved to {filename}" + Style.RESET_ALL)
    plt.close()
    
    if ask_yes_no("Open topology image now?", "n"):
        try:
            os.startfile(filename)
        except:
            try:
                os.system(f"xdg-open {filename}")
            except:
                pass
    
    return G

# ============================================================================
# REPORTING MODULE
# ============================================================================

def export_results(results=None, format=None, filename=None):
    if results is None:
        results = list(device_results.values())
    
    if not results:
        print(Fore.YELLOW + "[!] No results to export." + Style.RESET_ALL)
        return None
    
    if format is None:
        format = ask_input("Export format (json/csv/html)", "json")
    
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"kenumerator_report_{timestamp}.{format}"
    
    if format == "json":
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, default=str)
    
    elif format == "csv":
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "IP", "MAC", "Vendor", "OS", "Scan Type", "Protocol",
                "Port", "State", "Service", "Product", "Version", "Timestamp"
            ])

            for device in results:
                for scan_item in device.get("scans", []):
                    ports = scan_item.get("ports", {})
                    for port, data in ports.items():
                        if isinstance(data, dict):
                            writer.writerow([
                                device.get("ip"),
                                device.get("mac"),
                                device.get("vendor"),
                                device.get("os", ""),
                                scan_item.get("type"),
                                scan_item.get("protocol"),
                                port,
                                data.get("state", ""),
                                data.get("name", ""),
                                data.get("product", ""),
                                data.get("version", ""),
                                scan_item.get("timestamp")
                            ])
    
    elif format == "html":
        generate_html_report(results, filename)
    
    print(Fore.GREEN + f"[+] Report exported: {filename}" + Style.RESET_ALL)
    
    if ask_yes_no("Open report now?", "n"):
        try:
            os.startfile(filename)
        except:
            try:
                os.system(f"xdg-open {filename}")
            except:
                pass
    
    return filename

def generate_html_report(results, filename):
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>KEnumerator Pro Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
            h1 {{ color: #00d4ff; }}
            h2 {{ color: #ff6b6b; border-bottom: 2px solid #ff6b6b; padding-bottom: 5px; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
            th, td {{ border: 1px solid #444; padding: 10px; text-align: left; }}
            th {{ background: #16213e; color: #00d4ff; }}
            tr:nth-child(even) {{ background: #0f3460; }}
            .open {{ color: #00ff88; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>KEnumerator Pro - Network Scan Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Total Hosts:</strong> {total_hosts}</p>
        {content}
    </body>
    </html>
    """
    
    content = ""
    for device in results:
        content += f"<h2>Host: {device.get('ip', 'Unknown')}</h2>"
        content += f"<p>MAC: {device.get('mac', 'N/A')} | Vendor: {device.get('vendor', 'Unknown')} | OS: {device.get('os', 'Unknown')}</p>"
        
        for scan in device.get('scans', []):
            content += f"<h3>Scan: {scan.get('type', 'Unknown')}</h3>"
            content += "<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>"
            
            for port, data in scan.get('ports', {}).items():
                if isinstance(data, dict):
                    content += f"<tr>"
                    content += f"<td>{port}</td>"
                    content += f"<td>{data.get('state', 'unknown')}</td>"
                    content += f"<td>{data.get('name', 'unknown')}</td>"
                    content += f"<td>{data.get('product', '')} {data.get('version', '')}</td>"
                    content += f"</tr>"
            
            content += "</table>"
    
    html = html_template.format(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_hosts=len(results),
        content=content
    )
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

def view_discovered_devices():
    if not device_results:
        print(Fore.YELLOW + "[!] No devices discovered yet." + Style.RESET_ALL)
        return
    
    print(f"\n{Fore.CYAN}Discovered Devices:{Style.RESET_ALL}")
    print("-" * 80)
    
    for i, (ip, data) in enumerate(device_results.items(), 1):
        print(f"\n{Fore.GREEN}{i}. {ip}{Style.RESET_ALL}")
        print(f"   MAC: {data.get('mac', 'N/A')}")
        print(f"   Vendor: {data.get('vendor', 'Unknown')}")
        print(f"   OS: {data.get('os', 'Unknown')}")
        
        if data.get('scans'):
            print(f"   Scans performed: {len(data['scans'])}")
            for scan in data['scans']:
                print(f"     - {scan['type']} ({scan['protocol']}) at {scan['timestamp']}")
        
        if ask_yes_no(f"Perform actions on {ip}?", "n"):
            device_actions_menu(data)

def device_actions_menu(device):
    ip = device['ip']
    
    while True:
        print(f"\n{Fore.CYAN}Actions for {ip}:{Style.RESET_ALL}")
        print("1. TCP Port Scan")
        print("2. UDP Port Scan")
        print("3. Service Version Detection")
        print("4. OS Fingerprinting")
        print("5. Vulnerability Scan")
        print("6. Banner Grabbing")
        print("7. SMB Enumeration")
        print("8. SNMP Enumeration")
        print("9. Web Directory Brute Force")
        print("10. SSH Brute Force")
        print("11. FTP Brute Force")
        print("12. External API Lookup")
        print("0. Back to device list")
        
        choice = ask_input("Select action", "0")
        
        if choice == "0":
            break
        elif choice == "1":
            port_scan(ip, device.get('mac'), device.get('vendor'))
        elif choice == "2":
            udp_scan(ip, device.get('mac'), device.get('vendor'))
        elif choice == "3":
            version_scan(ip, device.get('mac'), device.get('vendor'))
        elif choice == "4":
            os_fingerprint(ip, device.get('mac'), device.get('vendor'))
        elif choice == "5":
            vuln_scan(ip, device.get('mac'), device.get('vendor'))
        elif choice == "6":
            banner_grab_scan(ip)
        elif choice == "7":
            smb_enum(ip)
        elif choice == "8":
            snmp_enum(ip)
        elif choice == "9":
            detect_web_tech(ip)
        elif choice == "10":
            ssh_bruteforce(ip)
        elif choice == "11":
            ftp_bruteforce(ip)
        elif choice == "12":
            shodan_lookup(ip)
            virustotal_lookup(ip)
        
        pause_continue()

# ============================================================================
# LIVE SCANNING
# ============================================================================

def live_scan(subnet):
    seen = {}
    counter = 1
    
    print(Fore.CYAN + "\nS.No\tIP Address\t\tMAC Address\t\tVendor" + Style.RESET_ALL)
    print(Fore.YELLOW + "-" * 90 + Style.RESET_ALL)

    try:
        while True:
            print(Fore.CYAN + f"\n[*] Scanning subnet {subnet}... (Press Ctrl+C to stop)" + Style.RESET_ALL)
            results = animated_task("Scanning", arp_scan, subnet)

            for client in results:
                key = (client['ip'], client['mac'])
                if key not in seen:
                    seen[key] = {
                        "serial": counter,
                        "ip": client['ip'],
                        "mac": client['mac'],
                        "vendor": client['vendor'],
                        "hostname": client.get('hostname', 'Unknown')
                    }

                    print(
                        f"{Fore.GREEN}{counter:<6}{Style.RESET_ALL}"
                        f"{Fore.CYAN}{client['ip']:<20}{Style.RESET_ALL}"
                        f"{Fore.MAGENTA}{client['mac']:<20}{Style.RESET_ALL}"
                        f"{Fore.YELLOW}{client['vendor'][:25]}{Style.RESET_ALL}"
                    )
                    
                    device_results[client['ip']] = {
                        "ip": client['ip'],
                        "mac": client['mac'],
                        "vendor": client['vendor'],
                        "hostname": client.get('hostname', 'Unknown'),
                        "scans": []
                    }
                    
                    counter += 1

            print(Fore.CYAN + f"\n[*] {len(seen)} unique device(s) discovered so far." + Style.RESET_ALL)
            
            choice = ask_input(
                "\nEnter S.No to select device, 'scan' to run port scan,\n" +
                "'enum' for enumeration, 'all' for threaded scan,\n" +
                "'save' to save to DB, or press Enter to continue discovery",
                ""
            ).strip().lower()

            if choice == "save":
                if DB_CONNECTION:
                    scan_id = DB_CONNECTION.save_scan("live_discovery", subnet, len(seen))
                    for device in seen.values():
                        DB_CONNECTION.save_host(scan_id, device['ip'], device['mac'], device['vendor'])
                    print(Fore.GREEN + "[+] Saved to database" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "[!] Database not available" + Style.RESET_ALL)
                    
            elif choice == "scan":
                if not seen:
                    print(Fore.YELLOW + "[!] No devices yet" + Style.RESET_ALL)
                    continue
                    
                target_num = ask_input("Enter S.No to scan", "1")
                try:
                    target_num = int(target_num)
                    target = None
                    for k, v in seen.items():
                        if v["serial"] == target_num:
                            target = v
                            break
                    
                    if target:
                        port_scan(target["ip"], target["mac"], target["vendor"])
                    else:
                        print(Fore.RED + "[!] Invalid S.No" + Style.RESET_ALL)
                except:
                    pass
                    
            elif choice == "enum":
                target_num = ask_input("Enter S.No for enumeration", "1")
                try:
                    target_num = int(target_num)
                    target = None
                    for k, v in seen.items():
                        if v["serial"] == target_num:
                            target = v
                            break
                    
                    if target:
                        device_actions_menu(target)
                    else:
                        print(Fore.RED + "[!] Invalid S.No" + Style.RESET_ALL)
                except:
                    pass
                    
            elif choice == "all":
                if not seen:
                    print(Fore.YELLOW + "[!] No devices discovered yet." + Style.RESET_ALL)
                    continue

                scan_choice = ask_input(
                    "Scan type: tcp/udp/version/vuln/os/banner/stealth",
                    "tcp"
                ).strip().lower()

                if scan_choice in ["tcp", "udp", "version", "vuln", "os", "banner", "stealth"]:
                    targets = list(seen.values())
                    
                    if ask_yes_no(f"Run {scan_choice} scan on {len(targets)} devices?", "y"):
                        threaded_scan(targets, scan_choice)
                else:
                    print(Fore.RED + "[!] Invalid scan type" + Style.RESET_ALL)

            elif choice.isdigit():
                try:
                    choice_num = int(choice)
                    if choice_num in [v["serial"] for v in seen.values()]:
                        target = [v for v in seen.values() if v["serial"] == choice_num][0]
                        device_actions_menu(target)
                    else:
                        print(Fore.RED + "[!] Invalid S.No" + Style.RESET_ALL)
                except:
                    pass

            time.sleep(1)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Live scan stopped." + Style.RESET_ALL)
        
        if seen and ask_yes_no("Save discovered devices to database?", "y"):
            if DB_CONNECTION:
                scan_id = DB_CONNECTION.save_scan("live_discovery", subnet, len(seen))
                for device in seen.values():
                    DB_CONNECTION.save_host(scan_id, device['ip'], device['mac'], device['vendor'])
                print(Fore.GREEN + "[+] Saved to database" + Style.RESET_ALL)
        
        if seen and ask_yes_no("Export discovered devices?", "n"):
            export_results([device_results[k[0]] for k in seen.keys()])

def threaded_scan(targets, scan_type="tcp"):
    scan_map = {
        "tcp": lambda t: port_scan(t["ip"], t.get("mac"), t.get("vendor")),
        "udp": lambda t: udp_scan(t["ip"], t.get("mac"), t.get("vendor")),
        "version": lambda t: version_scan(t["ip"], t.get("mac"), t.get("vendor")),
        "vuln": lambda t: vuln_scan(t["ip"], t.get("mac"), t.get("vendor")),
        "os": lambda t: os_fingerprint(t["ip"], t.get("mac"), t.get("vendor")),
        "banner": lambda t: banner_grab_scan(t["ip"]),
        "stealth": lambda t: stealth_scan(t["ip"], t.get("mac"), t.get("vendor"))
    }

    scan_func = scan_map.get(scan_type)
    if not scan_func:
        print(Fore.RED + "[!] Invalid scan type." + Style.RESET_ALL)
        return

    print(Fore.YELLOW + f"\n[+] Starting threaded {scan_type.upper()} scan for {len(targets)} device(s)..." + Style.RESET_ALL)

    with ThreadPoolExecutor(max_workers=CONFIG['scan']['threads']) as executor:
        futures = {executor.submit(scan_func, target): target for target in targets}
        
        completed = 0
        for future in futures:
            target = futures[future]
            try:
                future.result()
                completed += 1
                print(f"  Progress: {completed}/{len(targets)} - Completed {target['ip']}")
            except Exception as e:
                print(Fore.RED + f"  [!] Error on {target['ip']}: {e}" + Style.RESET_ALL)

    print(Fore.GREEN + f"\n[+] Threaded {scan_type.upper()} scan completed." + Style.RESET_ALL)

# ============================================================================
# MAIN
# ============================================================================

def main():
    global CONFIG, DB_CONNECTION
    
    banner()
    
    # Initialize wordlist system
    init_wordlist_system()
    
    CONFIG = load_config()
    
    try:
        DB_CONNECTION = ScanDatabase(CONFIG['output']['db_path'])
        print(Fore.GREEN + f"[+] Database ready: {CONFIG['output']['db_path']}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Database not available: {e}" + Style.RESET_ALL)
    
    subnet = get_local_subnet()
    if subnet:
        print(Fore.GREEN + f"[+] Detected subnet: {subnet}" + Style.RESET_ALL)

    while True:
        print_menu()
        choice = ask_input("Select option", "0")
        
        if choice == "0":
            print(Fore.GREEN + "\n[+] Goodbye!" + Style.RESET_ALL)
            if DB_CONNECTION:
                DB_CONNECTION.close()
            break
        
        elif choice == "1":
            target_subnet = ask_input("Enter subnet to scan", subnet or "192.168.1.0/24")
            
            if ask_yes_no(f"Scan subnet {target_subnet}?", "y"):
                devices = arp_scan(target_subnet)
                if devices:
                    print(Fore.GREEN + f"\n[+] Found {len(devices)} devices" + Style.RESET_ALL)
                    
                    print(f"\n{Fore.CYAN}What would you like to do?{Style.RESET_ALL}")
                    print("1. View device details")
                    print("2. Run port scan on all devices")
                    print("3. Save to database")
                    print("4. Export results")
                    print("5. Return to menu")
                    
                    next_action = ask_input("Select", "1")
                    
                    if next_action == "1":
                        for d in devices:
                            print(f"\n  IP: {d['ip']}")
                            print(f"  MAC: {d['mac']}")
                            print(f"  Vendor: {d['vendor']}")
                            print(f"  Hostname: {d.get('hostname', 'Unknown')}")
                            if ask_yes_no(f"Scan {d['ip']}?", "n"):
                                port_scan(d['ip'], d['mac'], d['vendor'])
                    
                    elif next_action == "2":
                        if ask_yes_no(f"Port scan all {len(devices)} devices?", "n"):
                            threaded_scan(devices, "tcp")
                    
                    elif next_action == "3":
                        if DB_CONNECTION:
                            scan_id = DB_CONNECTION.save_scan("arp_discovery", target_subnet, len(devices))
                            for d in devices:
                                DB_CONNECTION.save_host(scan_id, d['ip'], d['mac'], d['vendor'])
                            print(Fore.GREEN + "[+] Saved to database" + Style.RESET_ALL)
                    
                    elif next_action == "4":
                        for d in devices:
                            device_results[d['ip']] = d
                        export_results()
        
        elif choice == "2":
            target_subnet = ask_input("Enter subnet", subnet or "192.168.1.0/24")
            live_scan(target_subnet)
        
        elif choice == "3":
            target = ask_input("Enter target IP")
            if target:
                port_range = ask_input("Port range", CONFIG['scan']['default_port_range'])
                port_scan(target, port_range=port_range)
        
        elif choice == "4":
            target = ask_input("Enter target IP")
            if target:
                udp_scan(target)
        
        elif choice == "5":
            target = ask_input("Enter target IP")
            if target:
                if ask_yes_no("Full port scan (1-65535) will take time. Continue?", "y"):
                    port_scan(target, port_range="1-65535")
        
        elif choice == "6":
            target = ask_input("Enter target IP")
            if target:
                stealth_scan(target)
        
        elif choice == "7":
            target = ask_input("Enter target IP")
            if target:
                os_fingerprint(target)
        
        elif choice == "8":
            target = ask_input("Enter target IP")
            if target:
                version_scan(target)
        
        elif choice == "9":
            target = ask_input("Enter target IP")
            if target:
                banner_grab_scan(target)
        
        elif choice == "10":
            target = ask_input("Enter target IP")
            if target:
                smb_enum(target)
        
        elif choice == "11":
            target = ask_input("Enter target IP")
            if target:
                community = ask_input("Community string(s)", "public")
                snmp_enum(target, community)
        
        elif choice == "12":
            target = ask_input("Enter target IP")
            if target:
                dir_buster(target)
        
        elif choice == "13":
            target = ask_input("Enter target IP")
            if target:
                detect_web_tech(target)
        
        elif choice == "14":
            target = ask_input("Enter target IP")
            if target:
                vuln_scan(target)
        
        elif choice == "15":
            target = ask_input("Enter target IP")
            if target:
                ssh_bruteforce(target)
        
        elif choice == "16":
            target = ask_input("Enter target IP")
            if target:
                ftp_bruteforce(target)
        
        elif choice == "17":
            target = ask_input("Enter target IP")
            if target:
                telnet_bruteforce(target)
        
        elif choice == "18":
            target = ask_input("Enter IP to lookup")
            if target:
                shodan_lookup(target)
        
        elif choice == "19":
            target = ask_input("Enter IP to lookup")
            if target:
                virustotal_lookup(target)
        
        elif choice == "20":
            wordlist_management_menu()
        
        elif choice == "21":
            view_discovered_devices()
        
        elif choice == "22":
            build_topology()
        
        elif choice == "23":
            export_results()
        
        elif choice == "24":
            if DB_CONNECTION:
                history = DB_CONNECTION.get_scan_history()
                print(f"\n{Fore.CYAN}Scan History:{Style.RESET_ALL}")
                for scan in history[:20]:
                    print(f"  ID: {scan[0]} | {scan[1]} | {scan[2]} | {scan[3]} hosts | {scan[4]}")
            else:
                print(Fore.YELLOW + "[!] Database not available" + Style.RESET_ALL)
        
        else:
            print(Fore.RED + "[!] Invalid option" + Style.RESET_ALL)
        
        pause_continue()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Interrupted by user" + Style.RESET_ALL)
        if DB_CONNECTION:
            DB_CONNECTION.close()
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[!] Fatal error: {e}" + Style.RESET_ALL)
        if DB_CONNECTION:
            DB_CONNECTION.close()
        sys.exit(1)
