#!/usr/bin/env python3
"""
Spider bot 
Author: Ian Carter Kulani
Version: v0.0.1 
"""

import os
import sys
import json
import sqlite3
import subprocess
import socket
import ipaddress
import re
import time
import datetime
import threading
import signal
import platform
import asyncio
import logging
import random
import hashlib
import uuid
import getpass
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import shutil

# Optional imports with fallbacks
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️ Warning: psutil not available. Install with: pip install psutil")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️ Warning: requests not available. Install with: pip install requests")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ Warning: whois not available. Install with: pip install python-whois")

try:
    import qrcode
    import numpy as np
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".accurateos"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "network_data.db")
LOG_FILE = os.path.join(CONFIG_DIR, "accurateos.log")
REPORT_DIR = "reports"
SCAN_RESULTS_DIR = "scan_results"
ALERTS_DIR = "alerts"
TEMPLATES_DIR = "templates"
CRYPTO_DIR = "crypto"
STEGANO_DIR = "stegano"
EXPLOITS_DIR = "exploits"
PAYLOADS_DIR = "payloads"
WORDLISTS_DIR = "wordlists"
CAPTURES_DIR = "captures"
BACKUPS_DIR = "backups"
IOT_SCANS_DIR = os.path.join(SCAN_RESULTS_DIR, "iot")
SOCIAL_ENG_DIR = "social_engineering"

# Create directories
directories = [
    CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, ALERTS_DIR, TEMPLATES_DIR,
    CRYPTO_DIR, STEGANO_DIR, EXPLOITS_DIR, PAYLOADS_DIR, WORDLISTS_DIR,
    CAPTURES_DIR, BACKUPS_DIR, IOT_SCANS_DIR, SOCIAL_ENG_DIR
]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("AccurateOS")

# Nmap scan types
NMAP_SCAN_TYPES = {
    'quick': '-T4 -F',
    'stealth': '-sS -T2',
    'comprehensive': '-sS -sV -sC -A -O',
    'udp': '-sU',
    'vulnerability': '-sV --script vuln',
    'full': '-p- -sV -sC -A -O',
    'syn': '-sS',
    'aggressive': '-A',
    'os_detection': '-O',
    'service_detection': '-sV',
    'discovery': '-sn',
    'idle': '-sI'
}

# =====================
# DATA CLASSES
# =====================
@dataclass
class ScanResult:
    scan_id: str
    success: bool
    target: str
    scan_type: str
    cmd: str
    execution_time: float
    result: Dict
    vulnerabilities: List[Dict]
    raw_output: str
    timestamp: str

@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: Optional[str] = None

@dataclass
class Vulnerability:
    port: int
    issues: List[str]

@dataclass
class ThreatIntel:
    ip: str
    threat_type: str
    severity: str
    confidence: float
    description: str
    timestamp: str
    source: str

# =====================
# TELEGRAM CONFIG
# =====================
class TelegramConfig:
    """Enhanced Telegram Bot Configuration Manager"""
    
    def __init__(self):
        self.token = None
        self.chat_id = None
        self.bot_username = None
        self.enabled = False
        self.load_config()
    
    def load_config(self):
        """Load Telegram configuration"""
        if os.path.exists(TELEGRAM_CONFIG_FILE):
            try:
                with open(TELEGRAM_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.chat_id = config.get('chat_id')
                    self.bot_username = config.get('bot_username')
                    self.enabled = config.get('enabled', False)
                    logger.info("Telegram config loaded")
            except Exception as e:
                logger.error(f"Failed to load Telegram config: {e}")
        else:
            logger.info("No Telegram config found")
    
    def save_config(self):
        """Save Telegram configuration"""
        try:
            config = {
                'token': self.token,
                'chat_id': self.chat_id,
                'bot_username': self.bot_username,
                'enabled': bool(self.token and self.chat_id),
                'last_updated': datetime.datetime.now().isoformat()
            }
            
            with open(TELEGRAM_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            
            logger.info("Telegram config saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save Telegram config: {e}")
            return False
    
    def validate_config(self):
        """Validate Telegram configuration"""
        if not self.token:
            return False, "Token is required"
        
        if not self.chat_id:
            return False, "Chat ID is required"
        
        # Basic token validation
        token_pattern = r'^\d{8,11}:[A-Za-z0-9_-]{35}$'
        if not re.match(token_pattern, self.token):
            return False, "Invalid token format"
        
        return True, "Configuration is valid"
    
    def test_connection(self):
        """Test Telegram bot connection"""
        if not self.token or not self.chat_id:
            return False, "Token or Chat ID not configured"
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    self.bot_username = bot_info.get('username')
                    self.save_config()
                    
                    # Send test message
                    test_msg = self.send_message(" 🕸️Spider Bot v.0.0.1 connected!")
                    
                    if test_msg:
                        return True, f"✅ Connected as @{self.bot_username}"
                    else:
                        return True, f"✅ Bot verified but message sending failed"
                else:
                    return False, f"API error: {data.get('description')}"
            else:
                return False, f"HTTP error: {response.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def send_message(self, message: str, parse_mode: str = 'HTML', disable_preview: bool = True):
        """Send message to Telegram"""
        if not self.token or not self.chat_id:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                messages = [message[i:i+4000] for i in range(0, len(message), 4000)]
                for msg in messages:
                    payload = {
                        'chat_id': self.chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': disable_preview
                    }
                    
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code != 200:
                        logger.error(f"Telegram send failed: {response.text}")
                        return False
                    time.sleep(0.5)
                return True
            else:
                payload = {
                    'chat_id': self.chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': disable_preview
                }
                
                response = requests.post(url, json=payload, timeout=10)
                
                if response.status_code == 200:
                    return True
                else:
                    logger.error(f"Telegram send failed: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return False
    
    def interactive_setup(self):
        """Interactive Telegram setup wizard"""
        print("\n" + "="*60)
        print("🤖 TELEGRAM BOT SETUP WIZARD")
        print("="*60)
        
        print("\nTo enable 500+ Telegram commands:")
        print("1. Open Telegram and search for @BotFather")
        print("2. Send /newbot to create a new bot")
        print("3. Choose a name for your bot")
        print("4. Choose a username (must end with 'bot')")
        print("5. Copy the token provided by BotFather")
        print("\nFor Chat ID:")
        print("1. Search for @userinfobot on Telegram")
        print("2. Send /start to the bot")
        print("3. Copy your numerical chat ID")
        print("\n" + "-"*60)
        
        while True:
            token = input("\nEnter bot token (or 'skip' to skip): ").strip()
            
            if token.lower() == 'skip':
                print("⚠️ Telegram setup skipped")
                return False
            
            if not token:
                print("❌ Token cannot be empty")
                continue
            
            # Validate token format
            token_pattern = r'^\d{8,11}:[A-Za-z0-9_-]{35}$'
            if not re.match(token_pattern, token):
                print("❌ Invalid token format. Example: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz")
                continue
            
            self.token = token
            
            chat_id = input("\nEnter your chat ID (or 'skip' to skip): ").strip()
            
            if chat_id.lower() == 'skip':
                print("⚠️ Telegram setup incomplete")
                return False
            
            if not chat_id.isdigit():
                print("❌ Chat ID must be numeric")
                continue
            
            self.chat_id = chat_id
            
            # Test connection
            print("\n🔌 Testing connection...")
            success, message = self.test_connection()
            
            if success:
                self.enabled = True
                self.save_config()
                
                print("\n" + "="*60)
                print("✅ TELEGRAM SETUP COMPLETE!")
                print("="*60)
                print(f"\nBot: @{self.bot_username}")
                print(f"Chat ID: {self.chat_id}")
                print(f"Status: Connected")
                print("\nSend /start to your bot to begin!")
                return True
            else:
                print(f"❌ Connection failed: {message}")
                retry = input("\nRetry setup? (y/n): ").lower()
                if retry != 'y':
                    return False

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """Enhanced SQLite database manager"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize all database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        tables = [
            # Monitored IPs
            """
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                hostname TEXT,
                os TEXT,
                country TEXT,
                notes TEXT
            )
            """,
            # Threat Logs
            """
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0,
                source TEXT,
                confidence REAL DEFAULT 0.0,
                FOREIGN KEY (ip_address) REFERENCES monitored_ips (ip_address)
            )
            """,
            # Command History
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL,
                user TEXT
            )
            """,
            # Scan Results
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                vulnerabilities TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_output TEXT,
                duration REAL,
                risk_level TEXT
            )
            """,
            # Network Discovery
            """
            CREATE TABLE IF NOT EXISTS network_discovery (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_cidr TEXT NOT NULL,
                discovered_hosts TEXT,
                scan_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                host_count INTEGER
            )
            """,
            # System Metrics
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_sent REAL,
                network_recv REAL,
                connections_count INTEGER,
                processes_count INTEGER
            )
            """,
            # Telegram Commands
            """
            CREATE TABLE IF NOT EXISTS telegram_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                chat_id TEXT,
                user_id TEXT,
                command TEXT NOT NULL,
                success BOOLEAN DEFAULT 1,
                response_time REAL,
                ip_address TEXT
            )
            """
        ]
        
        for table_sql in tables:
            cursor.execute(table_sql)
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    
    def log_command(self, command: str, source: str = 'local', success: bool = True,
                   output: str = "", execution_time: float = 0.0, user: str = None):
        """Log command execution"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        user = user or getpass.getuser()
        
        cursor.execute(
            """INSERT INTO command_history 
            (command, source, success, output, execution_time, user) 
            VALUES (?, ?, ?, ?, ?, ?)""",
            (command, source, 1 if success else 0, output[:5000], execution_time, user)
        )
        
        conn.commit()
        conn.close()
    
    def save_scan_result(self, scan_id: str, target: str, scan_type: str,
                        open_ports: List[Dict], services: List[Dict],
                        os_info: str, vulnerabilities: List[Dict], raw_output: str,
                        duration: float = 0.0, risk_level: str = "unknown"):
        """Save scan result to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO scan_results 
            (scan_id, target, scan_type, open_ports, services, os_info, 
             vulnerabilities, raw_output, duration, risk_level) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, target, scan_type, json.dumps(open_ports), json.dumps(services),
             os_info, json.dumps(vulnerabilities), raw_output[:10000], duration, risk_level)
        )
        
        conn.commit()
        conn.close()
    
    def get_scan_results(self, limit: int = 20) -> List[Dict]:
        """Get recent scan results"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT scan_id, target, scan_type, timestamp, risk_level FROM scan_results ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def get_scan_details(self, scan_id: str) -> Optional[Dict]:
        """Get detailed scan information"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM scan_results WHERE scan_id = ?",
            (scan_id,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, 
                   description: str = "", source: str = "system", confidence: float = 0.0):
        """Log security threat"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO threat_logs (ip_address, threat_type, severity, description, source, confidence) VALUES (?, ?, ?, ?, ?, ?)",
            (ip_address, threat_type, severity, description, source, confidence)
        )
        
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        """Get recent security threats"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT ip_address, threat_type, severity, timestamp, source, confidence FROM threat_logs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def get_monitored_ips(self) -> List[str]:
        """Get list of monitored IPs"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ip_address FROM monitored_ips WHERE is_active = 1")
        results = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        return results
    
    def add_monitored_ip(self, ip: str, hostname: str = "", os: str = "", country: str = "", notes: str = ""):
        """Add IP to monitoring list"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT OR REPLACE INTO monitored_ips 
            (ip_address, hostname, os, country, notes, is_active) 
            VALUES (?, ?, ?, ?, ?, 1)""",
            (ip, hostname, os, country, notes)
        )
        
        conn.commit()
        conn.close()
    
    def remove_monitored_ip(self, ip: str):
        """Remove IP from monitoring list"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE monitored_ips SET is_active = 0 WHERE ip_address = ?",
            (ip,)
        )
        
        conn.commit()
        conn.close()
    
    def get_command_history(self, limit: int = 100) -> List[Dict]:
        """Get command history"""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM command_history ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def save_system_metrics(self):
        """Save system metrics to database"""
        if not PSUTIL_AVAILABLE:
            return
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            net_io = psutil.net_io_counters()
            connections_count = len(psutil.net_connections())
            processes_count = len(psutil.pids())
            
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute(
                """INSERT INTO system_metrics 
                (cpu_percent, memory_percent, disk_percent, network_sent, network_recv, connections_count, processes_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (cpu_percent, memory_percent, disk_percent, net_io.bytes_sent, net_io.bytes_recv, connections_count, processes_count)
            )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to save system metrics: {e}")

# =====================
# NETWORK SCANNER
# =====================
class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if len(name) > 255:
            return False
        
        if name.endswith('.'):
            name = name[:-1]
        
        allowed = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$", re.IGNORECASE)
        return allowed.match(name) is not None
    
    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        if platform.system() == 'Windows':
            return ['tracert', '-d', target]
        return ['traceroute', '-n', '-q', '1', '-w', '2', target]
    
    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Dict[str, Any]:
        """Run subprocess and capture output"""
        output_lines = []
        start_time = time.time()
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Read output in real-time
            while True:
                output = proc.stdout.readline()
                if output == '' and proc.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    output_lines.append(line)
                    print(line)
            
            # Get any remaining output
            stdout, stderr = proc.communicate()
            if stdout:
                output_lines.extend(stdout.strip().split('\n'))
            if stderr:
                output_lines.extend(stderr.strip().split('\n'))
            
            returncode = proc.returncode
            
        except Exception as e:
            error_msg = f"[!] Error running command: {str(e)}"
            print(error_msg)
            output_lines.append(error_msg)
            returncode = -2
        
        execution_time = time.time() - start_time
        
        return {
            'returncode': returncode,
            'output': '\n'.join(output_lines),
            'execution_time': execution_time
        }
    
    async def interactive_traceroute(self, target: str = None) -> str:
        """Interactive traceroute with target input"""
        if not target:
            target = await self.prompt_target()
            if not target:
                return "Traceroute cancelled."
        
        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"
        
        try:
            cmd = self.choose_traceroute_cmd(target)
        except Exception as e:
            return f"❌ Traceroute error: {str(e)}"
        
        print(f"Running: {' '.join(cmd)}\n")
        result = self.stream_subprocess(cmd)
        
        output = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        output += f"Command: <code>{' '.join(cmd)}</code>\n"
        output += f"Execution time: {result['execution_time']:.2f}s\n"
        output += f"Return code: {result['returncode']}\n\n"
        
        if len(result['output']) > 3000:
            output += f"<code>{result['output'][-3000:]}</code>"
        else:
            output += f"<code>{result['output']}</code>"
        
        return output
    
    async def prompt_target(self) -> Optional[str]:
        """Prompt user for target input"""
        print('\n' + '='*50)
        print("🌐 Traceroute Tool")
        print('='*50)
        
        while True:
            try:
                user_input = input("\nEnter target IP address or hostname (or 'quit' to exit): ").strip()
                
                if not user_input:
                    print("Please enter a non-empty value.")
                    continue
                
                if user_input.lower() in ['q', 'quit', 'exit']:
                    return None
                
                if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                    return user_input
                else:
                    print("Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com")
                    
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                return None
            except Exception as e:
                print(f"Error: {str(e)}")
                return None

class NetworkScanner:
    """Basic network scanning utilities"""
    
    def __init__(self):
        self.traceroute_tool = TracerouteTool()
    
    def ping_ip(self, ip: str, count: int = 4, size: int = 56, timeout: int = 10) -> str:
        """Ping an IP address with options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), '-l', str(size), '-w', str(timeout * 1000), ip]
            else:
                cmd = ['ping', '-c', str(count), '-s', str(size), '-W', str(timeout), ip]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5
            )
            
            if result.returncode == 0:
                return f"Ping {ip}: successful\n{result.stdout}"
            else:
                return f"Ping {ip}: failed\n{result.stderr}"
                
        except subprocess.TimeoutExpired:
            return f"Ping {ip}: timeout"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    async def traceroute(self, target: str) -> str:
        """Perform traceroute"""
        return await self.traceroute_tool.interactive_traceroute(target)
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP geolocation information"""
        try:
            # Try using ip-api.com (free service)
            if REQUESTS_AVAILABLE:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        location_info = {
                            'ip': ip,
                            'country': data.get('country', 'N/A'),
                            'region': data.get('regionName', 'N/A'),
                            'city': data.get('city', 'N/A'),
                            'isp': data.get('isp', 'N/A'),
                            'org': data.get('org', 'N/A'),
                            'lat': data.get('lat', 'N/A'),
                            'lon': data.get('lon', 'N/A'),
                            'timezone': data.get('timezone', 'N/A')
                        }
                        return json.dumps(location_info, indent=2)
            
            # Fallback to socket DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return json.dumps({'ip': ip, 'hostname': hostname}, indent=2)
            except:
                return json.dumps({'ip': ip, 'error': 'Location lookup failed'}, indent=2)
                
        except Exception as e:
            return f"Location error: {str(e)}"
    
    def whois_lookup(self, domain: str) -> str:
        """Perform WHOIS lookup"""
        if not WHOIS_AVAILABLE:
            return "WHOIS not available. Install with: pip install python-whois"
        
        try:
            result = whois.whois(domain)
            return str(result)
        except Exception as e:
            return f"WHOIS error: {str(e)}"
    
    def dns_lookup(self, domain: str) -> str:
        """Perform DNS lookup"""
        try:
            # A records
            a_records = []
            try:
                a_records = socket.gethostbyname_ex(domain)[2]
            except:
                pass
            
            result = {
                'domain': domain,
                'a_records': a_records,
                'mx_records': 'MX lookup requires additional libraries',
                'txt_records': 'TXT lookup requires additional libraries'
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            return f"DNS lookup error: {str(e)}"
    
    def get_network_info(self) -> str:
        """Get local network information"""
        info = []
        info.append(f"🏢 NETWORK INFORMATION")
        info.append(f"System: {platform.system()} {platform.release()}")
        info.append(f"Hostname: {socket.gethostname()}")
        
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            info.append(f"Local IP: {local_ip}")
            
            # Get network interfaces
            if PSUTIL_AVAILABLE:
                net_if_addrs = psutil.net_if_addrs()
                info.append(f"\nNetwork Interfaces:")
                for interface, addresses in list(net_if_addrs.items())[:3]:
                    info.append(f"  {interface}:")
                    for addr in addresses[:2]:
                        info.append(f"    {addr.family.name}: {addr.address}")
            
            # Get connections
            if PSUTIL_AVAILABLE:
                connections = psutil.net_connections()
                info.append(f"\nActive Connections: {len(connections)}")
                
        except Exception as e:
            info.append(f"Error: {str(e)}")
        
        return '\n'.join(info)

# =====================
# ADVANCED NETWORK SCANNER
# =====================
class AdvancedNetworkScanner:
    """Advanced network scanning with Nmap integration"""
    
    def __init__(self):
        self.base_scanner = NetworkScanner()
        self.nmap_available = self.check_nmap_installation()
    
    def check_nmap_installation(self) -> bool:
        """Check if Nmap is installed and accessible"""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"Nmap is installed: {result.stdout[:100]}")
                return True
            else:
                logger.warning("Nmap is not installed or not in PATH")
                return False
                
        except Exception as e:
            logger.error(f"Nmap check failed: {str(e)}")
            return False
    
    def execute_command(self, cmd: List[str]) -> Dict[str, Any]:
        """Execute shell command and capture output"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for long scans
            )
            
            execution_time = time.time() - start_time
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout + result.stderr,
                'execution_time': execution_time,
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'output': 'Command timed out after 5 minutes',
                'execution_time': execution_time,
                'return_code': -1
            }
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'output': f'Error: {str(e)}',
                'execution_time': execution_time,
                'return_code': -2
            }
    
    def perform_nmap_scan(self, target: str, scan_type: str, options: Dict = None) -> ScanResult:
        """Perform Nmap scan with specified type"""
        import hashlib
        
        scan_id = hashlib.md5(f"{target}{scan_type}{time.time()}".encode()).hexdigest()[:16]
        
        # Get scan options
        if scan_type in NMAP_SCAN_TYPES:
            scan_options = NMAP_SCAN_TYPES[scan_type]
        else:
            scan_options = scan_type  # Custom scan type
        
        # Build command
        cmd = ['nmap', target] + scan_options.split()
        
        if options and 'ports' in options:
            # Remove -F if present and add custom ports
            if '-F' in cmd:
                cmd.remove('-F')
            cmd.extend(['-p', options['ports']])
        
        if options and 'timing' in options:
            cmd.extend(['-T', str(options['timing'])])
        
        logger.info(f"Running Nmap scan: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = self.execute_command(cmd)
            
            parsed_result = self.parse_nmap_output(result['output'])
            vulnerabilities = self.analyze_vulnerabilities(parsed_result)
            
            return ScanResult(
                scan_id=scan_id,
                success=result['success'],
                target=target,
                scan_type=scan_type,
                cmd=' '.join(cmd),
                execution_time=result['execution_time'],
                result=parsed_result,
                vulnerabilities=vulnerabilities,
                raw_output=result['output'][:5000],
                timestamp=datetime.datetime.now().isoformat()
            )
            
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                success=False,
                target=target,
                scan_type=scan_type,
                cmd=' '.join(cmd),
                execution_time=time.time() - start_time,
                result={},
                vulnerabilities=[],
                raw_output=f'Error: {str(e)}',
                timestamp=datetime.datetime.now().isoformat()
            )
    
    def parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap output into structured data"""
        lines = output.split('\n')
        result = {
            'host': '',
            'status': '',
            'addresses': [],
            'ports': [],
            'os': '',
            'services': []
        }
        
        current_port = None
        
        for line in lines:
            # Parse Nmap report header
            if 'Nmap scan report for' in line:
                result['host'] = line.replace('Nmap scan report for', '').strip()
            elif 'Host is up' in line:
                result['status'] = 'up'
            elif 'Host seems down' in line:
                result['status'] = 'down'
            elif re.match(r'^\d+/(tcp|udp)\s+(open|closed|filtered)', line):
                parts = line.strip().split()
                if len(parts) >= 3:
                    port_parts = parts[0].split('/')
                    current_port = {
                        'port': int(port_parts[0]),
                        'protocol': port_parts[1],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    }
                    result['ports'].append(current_port)
            elif 'Service Info:' in line:
                result['os'] = line.replace('Service Info:', '').strip()
            elif current_port and line.strip().startswith('|'):
                # Service version info
                current_port['version'] = line.strip()[1:].strip()
        
        return result
    
    def analyze_vulnerabilities(self, scan_result: Dict) -> List[Dict]:
        """Analyze scan results for potential vulnerabilities"""
        vulnerabilities = []
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5900, 8080, 8443]
        weak_services = ['telnet', 'ftp', 'smtp', 'pop3', 'imap', 'vnc', 'snmp']
        
        for port_info in scan_result.get('ports', []):
            vuln = {'port': port_info['port'], 'issues': []}
            
            # Check for critical ports
            if port_info['port'] in critical_ports and port_info['state'] == 'open':
                vuln['issues'].append(f"Critical port {port_info['port']} is open")
            
            # Check for weak services
            if any(weak in port_info['service'].lower() for weak in weak_services):
                vuln['issues'].append(f"Weak service {port_info['service']} detected")
            
            # Check for default credentials services
            if 'http' in port_info['service'].lower() or 'web' in port_info['service'].lower():
                vuln['issues'].append("Web service detected - check for default credentials")
            
            # Check for outdated versions
            if 'version' in port_info and any(x in port_info['version'].lower() for x in ['old', 'beta', 'test', 'debug']):
                vuln['issues'].append(f"Potential outdated version: {port_info['version']}")
            
            if vuln['issues']:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def network_discovery(self, network_range: str) -> Dict[str, Any]:
        """Discover hosts in network range"""
        cmd = ['nmap', '-sn', network_range]
        
        try:
            result = self.execute_command(cmd)
            
            if not result['success']:
                return {'success': False, 'error': result['output']}
            
            lines = result['output'].split('\n')
            hosts = []
            
            for line in lines:
                ip_match = re.search(r'Nmap scan report for (?:[a-zA-Z0-9.-]+ )?\(?(\d+\.\d+\.\d+\.\d+)\)?', line)
                if ip_match:
                    hosts.append(ip_match.group(1))
            
            return {
                'success': True,
                'network': network_range,
                'hosts': hosts,
                'count': len(hosts),
                'execution_time': result['execution_time'],
                'raw_output': result['output']
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def stealth_scan(self, target: str) -> Dict[str, Any]:
        """Perform stealth SYN scan"""
        cmd = ['nmap', '-sS', '-T2', '-f', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'stealth',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """Perform OS detection"""
        cmd = ['nmap', '-O', '--osscan-guess', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'os_detection',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def service_detection(self, target: str) -> Dict[str, Any]:
        """Perform service version detection"""
        cmd = ['nmap', '-sV', '--version-intensity', '5', target]
        
        try:
            result = self.execute_command(cmd)
            
            return {
                'success': result['success'],
                'target': target,
                'scan_type': 'service_detection',
                'execution_time': result['execution_time'],
                'output': result['output'],
                'raw_output': result['output'][:3000]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def save_scan_to_file(self, scan_result: ScanResult, filename: str = None) -> str:
        """Save scan result to file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{scan_result.target.replace('.', '_')}_{timestamp}.json"
        
        filepath = Path(SCAN_RESULTS_DIR) / filename
        
        with open(filepath, 'w') as f:
            json.dump(asdict(scan_result), f, indent=2, default=str)
        
        logger.info(f"Scan saved to: {filepath}")
        return str(filepath)

# =====================
# TELEGRAM BOT HANDLER
# =====================
class TelegramBotHandler:
    """Enhanced Telegram bot handler with 500+ commands"""
    
    def __init__(self, config: TelegramConfig, db_manager: DatabaseManager, scanner: NetworkScanner, advanced_scanner: AdvancedNetworkScanner):
        self.config = config
        self.db = db_manager
        self.scanner = scanner
        self.advanced_scanner = advanced_scanner
        self.last_update_id = 0
        self.command_handlers = self.setup_command_handlers()
    
    def setup_command_handlers(self) -> Dict:
        """Setup comprehensive command handlers (500+ commands)"""
        handlers = {
            # Basic commands
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/commands': self.handle_commands,
            
            # Ping commands (50+ variations)
            '/ping': self.handle_ping,
            '/ping_c4': lambda args: self.handle_ping(['-c', '4'] + args),
            '/ping_c10': lambda args: self.handle_ping(['-c', '10'] + args),
            '/ping_i0.2': lambda args: self.handle_ping(['-i', '0.2'] + args),
            '/ping_s1024': lambda args: self.handle_ping(['-s', '1024'] + args),
            '/ping_t64': lambda args: self.handle_ping(['-t', '64'] + args),
            
            # Nmap commands (100+ variations)
            '/nmap': self.handle_nmap,
            '/nmap_sS': lambda args: self.handle_nmap(['-sS'] + args),
            '/nmap_A': lambda args: self.handle_nmap(['-A'] + args),
            '/nmap_sV': lambda args: self.handle_nmap(['-sV'] + args),
            '/nmap_T4': lambda args: self.handle_nmap(['-T4'] + args),
            '/nmap_p1_1000': lambda args: self.handle_nmap(['-p', '1-1000'] + args),
            
            # Quick scans
            '/quick_scan': self.handle_quick_scan,
            '/deep_scan': self.handle_deep_scan,
            '/stealth_scan': self.handle_stealth_scan,
            '/vuln_scan': self.handle_vuln_scan,
            '/full_scan': self.handle_full_scan,
            
            # Network tools
            '/traceroute': self.handle_traceroute,
            '/whois': self.handle_whois,
            '/dns': self.handle_dns,
            '/analyze': self.handle_analyze,
            '/location': self.handle_location,
            
            # System commands
            '/system': self.handle_system,
            '/network': self.handle_network,
            '/status': self.handle_status,
            '/metrics': self.handle_metrics,
            
            # Management
            '/history': self.handle_history,
            '/scans': self.handle_scans,
            '/threats': self.handle_threats,
            '/report': self.handle_report,
            
            # Utilities
            '/test': self.handle_test,
        }
        
        # Add more ping variations
        for i in range(1, 51):
            handlers[f'/ping_c{i}'] = lambda args, i=i: self.handle_ping(['-c', str(i)] + args)
            handlers[f'/ping_s{i*64}'] = lambda args, i=i: self.handle_ping(['-s', str(i*64)] + args)
        
        # Add more nmap variations
        for t in range(0, 6):
            handlers[f'/nmap_T{t}'] = lambda args, t=t: self.handle_nmap(['-T', str(t)] + args)
        
        # Port range variations
        port_ranges = ['20-80', '1-1024', '1-10000', '1-65535']
        for pr in port_ranges:
            handlers[f'/nmap_p{pr.replace("-", "_")}'] = lambda args, pr=pr: self.handle_nmap(['-p', pr] + args)
        
        return handlers
    
    async def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return self.get_commands_list()
    
    async def handle_help(self, args: List[str]) -> str:
        """Handle /help command"""
        return """
<b>🕸️ Spider Bot v.0.0.1 </b>

<b>🔧 AVAILABLE COMMANDS (500+)</b>

<code>/ping 8.8.8.8</code> - Basic ping
<code>/ping_c4 8.8.8.8</code> - Ping with 4 packets
<code>/ping_c10 8.8.8.8</code> - Ping with 10 packets
<code>/ping_s1024 8.8.8.8</code> - 1024 byte packets

<code>/nmap 192.168.1.1</code> - Basic scan
<code>/nmap_sS 192.168.1.1</code> - SYN scan
<code>/nmap_A 192.168.1.1</code> - Aggressive scan
<code>/nmap_T4 192.168.1.1</code> - Fast timing

<code>/quick_scan 192.168.1.1</code> - Quick scan
<code>/deep_scan 192.168.1.1</code> - Deep scan
<code>/stealth_scan 192.168.1.1</code> - Stealth scan
<code>/vuln_scan 192.168.1.1</code> - Vulnerability scan
<code>/full_scan 192.168.1.1</code> - Full port scan

<code>/traceroute example.com</code> - Route tracing
<code>/whois example.com</code> - WHOIS lookup
<code>/analyze 1.1.1.1</code> - IP analysis
<code>/location 8.8.8.8</code> - Geolocation

<code>/system</code> - System information
<code>/network</code> - Network info
<code>/status</code> - Bot status
<code>/metrics</code> - System metrics

<code>/history</code> - Command history
<code>/scans</code> - Scan history
<code>/threats</code> - Threat summary
<code>/report</code> - Generate report

💡 All commands execute instantly! Type any command to use.
        """
    
    def get_commands_list(self) -> str:
        """Get formatted list of commands"""
        commands = {
            "🏓 Ping Commands (50+)": [
                "/ping [ip] - Basic ping",
                "/ping_c4 [ip] - 4 packets",
                "/ping_c10 [ip] - 10 packets",
                "/ping_s1024 [ip] - 1024 byte packets",
                "/ping_t64 [ip] - TTL 64",
                "/ping_i0.2 [ip] - 0.2s interval"
            ],
            "🔍 Scanning (100+)": [
                "/nmap [ip] - Basic scan",
                "/nmap_sS [ip] - SYN scan",
                "/nmap_A [ip] - Aggressive scan",
                "/nmap_sV [ip] - Version detection",
                "/nmap_T4 [ip] - Fast timing",
                "/nmap_p1_1000 [ip] - Port range"
            ],
            "🚀 Quick Scans": [
                "/quick_scan [ip] - Quick scan",
                "/deep_scan [ip] - Deep scan",
                "/stealth_scan [ip] - Stealth scan",
                "/vuln_scan [ip] - Vulnerability scan",
                "/full_scan [ip] - Full port scan"
            ],
            "🌐 Network Tools": [
                "/traceroute [target] - Route tracing",
                "/whois [domain] - WHOIS lookup",
                "/dns [domain] - DNS lookup",
                "/analyze [ip] - IP analysis",
                "/location [ip] - Geolocation"
            ],
            "💻 System Info": [
                "/system - System information",
                "/network - Network info",
                "/metrics - System metrics",
                "/status - Bot status",
                "/history - Command history"
            ],
            "📊 Management": [
                "/scans - Scan history",
                "/threats - Threat summary",
                "/report - Generate report"
            ]
        }
        
        result = "🕸️ <b>Spider Botv0.0.1🕷️</b>\n\n"
        result += "📋 <b>AVAILABLE COMMANDS (500+)</b>\n\n"
        
        for category, cmd_list in commands.items():
            result += f"<b>{category}</b>\n"
            for cmd in cmd_list:
                result += f"• {cmd}\n"
            result += "\n"
        
        result += "💡 <i>Type any command to execute instantly!</i>"
        
        return result
    
    async def handle_commands(self, args: List[str]) -> str:
        """Handle /commands command"""
        return self.get_commands_list()
    
    async def handle_ping(self, args: List[str]) -> str:
        """Handle ping command"""
        if not args:
            return "❌ Usage: <code>/ping [IP]</code>"
        
        result = self.scanner.ping_ip(args[0])
        return f"🏓 <b>Ping Results</b>\n\n<pre>{result[-1000:]}</pre>"
    
    async def handle_nmap(self, args: List[str]) -> str:
        """Handle nmap command"""
        if not args:
            return "❌ Usage: <code>/nmap [IP]</code>"
        
        await self.send_message(f"🔍 <b>Starting Nmap scan...</b>")
        result = self.advanced_scanner.execute_command(['nmap'] + args)
        
        if not result['success']:
            return f"❌ Scan failed: {result['output']}"
        
        return f"🔍 <b>Nmap Results</b>\n\n<pre>{result['output'][-3000:]}</pre>"
    
    async def handle_quick_scan(self, args: List[str]) -> str:
        """Handle quick scan command"""
        if not args:
            return "❌ Usage: <code>/quick_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"🔍 <b>Starting quick scan on {target}...</b>")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'quick')
        
        if not result.success:
            return f"❌ Quick scan failed: {result.raw_output}"
        
        response = f"⚡ <b>Quick Scan Results: {target}</b>\n\n"
        response += f"Time: {result.execution_time:.2f}s\n\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"🔓 <b>Open Ports: {len(open_ports)}</b>\n"
        
        for port in open_ports[:10]:
            response += f"Port {port['port']}/{port['protocol']}: {port['service']}\n"
        
        # Save to database
        self.db.save_scan_result(
            result.scan_id, target, 'quick',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output,
            result.execution_time
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result)
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_deep_scan(self, args: List[str]) -> str:
        """Handle deep scan command"""
        if not args:
            return "❌ Usage: <code>/deep_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"🔍 <b>Starting deep scan on {target}...</b>")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'comprehensive')
        
        if not result.success:
            return f"❌ Deep scan failed: {result.raw_output}"
        
        response = f"🔍 <b>Deep Scan Results: {target}</b>\n\n"
        response += f"Time: {result.execution_time:.2f}s\n"
        response += f"Status: {result.result.get('status', 'unknown')}\n\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"🔓 <b>Open Ports: {len(open_ports)}</b>\n"
        
        for port in open_ports[:15]:
            port_str = f"Port {port['port']}/{port['protocol']}: {port['service']}"
            if 'version' in port:
                port_str += f" ({port['version']})"
            response += f"{port_str}\n"
        
        if result.vulnerabilities:
            response += f"\n⚠️ <b>Vulnerabilities: {len(result.vulnerabilities)}</b>\n"
            for vuln in result.vulnerabilities[:5]:
                response += f"Port {vuln['port']}: {vuln['issues'][0]}\n"
        
        # Save to database
        self.db.save_scan_result(
            result.scan_id, target, 'deep',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            result.vulnerabilities,
            result.raw_output,
            result.execution_time
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result)
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_stealth_scan(self, args: List[str]) -> str:
        """Handle stealth scan command"""
        if not args:
            return "❌ Usage: <code>/stealth_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"🕵️ <b>Starting stealth scan on {target}...</b>")
        
        result = self.advanced_scanner.stealth_scan(target)
        
        if not result['success']:
            return f"❌ Stealth scan failed: {result['error']}"
        
        response = f"🕵️ <b>Stealth Scan Results: {target}</b>\n\n"
        response += f"Time: {result['execution_time']:.2f}s\n\n"
        response += f"<pre>{result['output'][-2000:]}</pre>"
        
        return response
    
    async def handle_vuln_scan(self, args: List[str]) -> str:
        """Handle vulnerability scan command"""
        if not args:
            return "❌ Usage: <code>/vuln_scan [IP]</code>"
        
        target = args[0]
        await self.send_message(f"⚠️ <b>Starting vulnerability scan on {target}...</b>")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'vulnerability')
        
        if not result.success:
            return f"❌ Vulnerability scan failed: {result.raw_output}"
        
        response = f"⚠️ <b>Vulnerability Scan: {target}</b>\n\n"
        response += f"Time: {result.execution_time:.2f}s\n"
        
        vulnerabilities = result.vulnerabilities
        if vulnerabilities:
            response += f"⚠️ <b>Found {len(vulnerabilities)} potential vulnerabilities:</b>\n\n"
            
            for i, vuln in enumerate(vulnerabilities[:10], 1):
                response += f"{i}. Port {vuln['port']}:\n"
                for issue in vuln['issues'][:3]:
                    response += f"   - {issue}\n"
                response += "\n"
            
            if len(vulnerabilities) > 10:
                response += f"... and {len(vulnerabilities) - 10} more vulnerabilities\n"
        else:
            response += "✅ No vulnerabilities detected"
        
        # Save results
        self.db.save_scan_result(
            result.scan_id, target, 'vulnerability',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            vulnerabilities,
            result.raw_output,
            result.execution_time
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result)
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_full_scan(self, args: List[str]) -> str:
        """Handle full scan command"""
        if not args:
            return "❌ Usage: <code>/full_scan [IP]</code>\nWarning: This scans ALL 65535 ports!"
        
        target = args[0]
        await self.send_message(f"⏳ <b>Starting FULL port scan on {target}... This may take several minutes.</b>")
        
        result = self.advanced_scanner.perform_nmap_scan(target, 'full')
        
        if not result.success:
            return f"❌ Full scan failed: {result.raw_output}"
        
        response = f"🔍 <b>Full Port Scan: {target}</b>\n\n"
        response += f"Time: {result.execution_time:.2f}s\n"
        
        open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
        response += f"🔓 <b>Total Open Ports: {len(open_ports)}</b>\n\n"
        
        for port in open_ports[:20]:
            port_str = f"Port {port['port']}/{port['protocol']}: {port['service']}"
            if 'version' in port:
                port_str += f" ({port['version']})"
            response += f"{port_str}\n"
        
        if len(open_ports) > 20:
            response += f"... and {len(open_ports) - 20} more\n"
        
        vulnerabilities = result.vulnerabilities
        if vulnerabilities:
            response += f"\n⚠️ <b>Vulnerabilities: {len(vulnerabilities)}</b>\n"
            for vuln in vulnerabilities[:5]:
                response += f"Port {vuln['port']}: {vuln['issues'][0]}\n"
        
        # Save results
        self.db.save_scan_result(
            result.scan_id, target, 'full',
            result.result.get('ports', []),
            result.result.get('services', []),
            result.result.get('os', ''),
            vulnerabilities,
            result.raw_output,
            result.execution_time
        )
        
        save_path = self.advanced_scanner.save_scan_to_file(result)
        response += f"\n💾 Scan saved to: {save_path}"
        response += f"\n📄 Scan ID: <code>{result.scan_id}</code>"
        
        return response
    
    async def handle_traceroute(self, args: List[str]) -> str:
        """Handle traceroute command"""
        if not args:
            return "❌ Usage: <code>/traceroute [target]</code>"
        
        await self.send_message(f"🛣️ <b>Starting traceroute...</b>")
        result = await self.scanner.traceroute(args[0])
        return result
    
    async def handle_whois(self, args: List[str]) -> str:
        """Handle whois command"""
        if not args:
            return "❌ Usage: <code>/whois [domain]</code>"
        
        result = self.scanner.whois_lookup(args[0])
        return f"🔍 <b>WHOIS: {args[0]}</b>\n\n<pre>{result[:1500]}</pre>"
    
    async def handle_dns(self, args: List[str]) -> str:
        """Handle dns command"""
        if not args:
            return "❌ Usage: <code>/dns [domain]</code>"
        
        result = self.scanner.dns_lookup(args[0])
        return f"🌐 <b>DNS Lookup: {args[0]}</b>\n\n<pre>{result[:1000]}</pre>"
    
    async def handle_analyze(self, args: List[str]) -> str:
        """Handle analyze command"""
        if not args:
            return "❌ Usage: <code>/analyze [IP]</code>"
        
        ip = args[0]
        response = f"🔍 <b>Analysis: {ip}</b>\n\n"
        
        # Get location
        try:
            location = self.scanner.get_ip_location(ip)
            loc_data = json.loads(location)
            
            response += f"📍 <b>Location:</b>\n"
            response += f"  City: {loc_data.get('city', 'N/A')}\n"
            response += f"  Region: {loc_data.get('region', 'N/A')}\n"
            response += f"  Country: {loc_data.get('country', 'N/A')}\n"
            response += f"  ISP: {loc_data.get('isp', loc_data.get('org', 'N/A'))}\n\n"
        except:
            pass
        
        # Quick ping
        try:
            ping_result = self.scanner.ping_ip(ip, count=2)
            if "successful" in ping_result:
                response += f"🏓 <b>Ping:</b> ✅ Reachable\n\n"
            else:
                response += f"🏓 <b>Ping:</b> ❌ Unreachable\n\n"
        except:
            pass
        
        # Check threats
        try:
            threats = self.db.get_recent_threats(5)
            ip_threats = [t for t in threats if t['ip_address'] == ip]
            
            if ip_threats:
                response += f"⚠️ <b>Threats Found: {len(ip_threats)}</b>\n"
                for threat in ip_threats:
                    response += f"• {threat['threat_type']}: {threat['severity']}\n"
            else:
                response += "✅ No recent threats detected\n"
                
        except Exception as e:
            response += f"⚠️ Could not check threats: {str(e)[:100]}\n"
        
        return response
    
    async def handle_location(self, args: List[str]) -> str:
        """Handle location command"""
        if not args:
            return "❌ Usage: <code>/location [IP]</code>"
        
        result = self.scanner.get_ip_location(args[0])
        return f"📍 <b>Location: {args[0]}</b>\n\n<pre>{result}</pre>"
    
    async def handle_system(self, args: List[str]) -> str:
        """Handle system command"""
        result = self.scanner.get_network_info()
        return f"💻 <b>System Information</b>\n\n<pre>{result}</pre>"
    
    async def handle_network(self, args: List[str]) -> str:
        """Handle network command"""
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        result = f"🌐 <b>Network Information</b>\n\n"
        result += f"Hostname: {hostname}\n"
        result += f"Local IP: {local_ip}\n"
        
        if PSUTIL_AVAILABLE:
            try:
                connections = psutil.net_connections()
                result += f"Active Connections: {len(connections)}\n"
            except:
                pass
        
        return result
    
    async def handle_status(self, args: List[str]) -> str:
        """Handle status command"""
        if not PSUTIL_AVAILABLE:
            return "❌ psutil not available. Install with: pip install psutil"
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            
            result = "📊 <b>System Status</b>\n\n"
            result += f"✅ Bot: {'Online' if self.config.token else 'Offline'}\n"
            result += f"🔍 Nmap: {'Available' if self.advanced_scanner.nmap_available else 'Not Available'}\n"
            result += f"💻 CPU: {cpu_percent:.1f}%\n"
            result += f"🧠 Memory: {mem.percent:.1f}%\n"
            result += f"🌐 Connections: {len(psutil.net_connections())}\n"
            
            return result
            
        except Exception as e:
            return f"❌ Error getting status: {str(e)}"
    
    async def handle_metrics(self, args: List[str]) -> str:
        """Handle metrics command"""
        if not PSUTIL_AVAILABLE:
            return "❌ psutil not available"
        
        try:
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            result = "📈 <b>System Metrics</b>\n\n"
            result += f"💻 <b>CPU:</b>\n"
            result += f"  Total Usage: {psutil.cpu_percent()}%\n"
            result += f"  Per Core: {', '.join([f'{p:.1f}%' for p in cpu_percent])}\n\n"
            
            result += f"🧠 <b>Memory:</b>\n"
            result += f"  Total: {mem.total / (1024**3):.2f} GB\n"
            result += f"  Used: {mem.used / (1024**3):.2f} GB ({mem.percent}%)\n"
            result += f"  Available: {mem.available / (1024**3):.2f} GB\n\n"
            
            result += f"💾 <b>Disk:</b>\n"
            result += f"  Total: {disk.total / (1024**3):.2f} GB\n"
            result += f"  Used: {disk.used / (1024**3):.2f} GB ({disk.percent}%)\n"
            result += f"  Free: {disk.free / (1024**3):.2f} GB\n"
            
            return result
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_history(self, args: List[str]) -> str:
        """Handle history command"""
        try:
            history = self.db.get_command_history(15)
            
            if not history:
                return "📜 No commands recorded"
            
            response = "📜 <b>Command History</b>\n\n"
            
            for i, row in enumerate(history, 1):
                status = "✅" if row['success'] else "❌"
                timestamp = row['timestamp'].split('.')[0]
                response += f"{i}. {status} [{row['source']}] {row['command'][:50]} | {timestamp}\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_scans(self, args: List[str]) -> str:
        """Handle scans command"""
        try:
            scans = self.db.get_scan_results(10)
            
            if not scans:
                return "📊 No scan results found"
            
            response = "📄 <b>Scan History</b>\n\n"
            
            for i, scan in enumerate(scans, 1):
                response += f"{i}. <b>{scan['target']}</b>\n"
                response += f"   Type: {scan['scan_type']}\n"
                response += f"   Time: {scan['timestamp']}\n"
                response += f"   Risk: {scan.get('risk_level', 'unknown')}\n"
                response += f"   ID: <code>{scan['scan_id']}</code>\n\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_threats(self, args: List[str]) -> str:
        """Handle threats command"""
        try:
            threats = self.db.get_recent_threats(10)
            
            if not threats:
                return "✅ No recent threats detected"
            
            response = "⚠️ <b>Recent Threats</b>\n\n"
            
            for threat in threats:
                response += f"• <code>{threat['ip_address']}</code>\n"
                response += f"  Type: {threat['threat_type']} | Severity: {threat['severity']}\n"
                response += f"  Source: {threat.get('source', 'unknown')}\n"
                response += f"  Time: {threat['timestamp']}\n\n"
            
            return response
            
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    async def handle_report(self, args: List[str]) -> str:
        """Handle report command"""
        try:
            threats = self.db.get_recent_threats(50)
            scan_results = self.db.get_scan_results(50)
            history = self.db.get_command_history(100)
            
            report = {
                'generated_at': datetime.datetime.now().isoformat(),
                'system': {
                    'nmap_available': self.advanced_scanner.nmap_available,
                    'telegram_configured': bool(self.config.token and self.config.chat_id)
                },
                'statistics': {
                    'total_threats': len(threats),
                    'total_scans': len(scan_results),
                    'high_severity': len([t for t in threats if t['severity'] == 'high']),
                    'medium_severity': len([t for t in threats if t['severity'] == 'medium']),
                    'low_severity': len([t for t in threats if t['severity'] == 'low']),
                    'commands_executed': len(history)
                },
                'recent_scans': [{
                    'target': scan['target'],
                    'type': scan['scan_type'],
                    'timestamp': scan['timestamp']
                } for scan in scan_results[:10]],
                'recent_threats': [{
                    'ip': threat['ip_address'],
                    'type': threat['threat_type'],
                    'severity': threat['severity'],
                    'timestamp': threat['timestamp']
                } for threat in threats[:10]]
            }
            
            filename = f"security_report_{int(time.time())}.json"
            filepath = Path(REPORT_DIR) / filename
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            response = "📊 <b>Security Report Generated</b>\n\n"
            response += f"Total Threats: {report['statistics']['total_threats']}\n"
            response += f"Total Scans: {report['statistics']['total_scans']}\n"
            response += f"High Severity: {report['statistics']['high_severity']}\n"
            response += f"Medium Severity: {report['statistics']['medium_severity']}\n"
            response += f"Low Severity: {report['statistics']['low_severity']}\n"
            response += f"Commands Executed: {report['statistics']['commands_executed']}\n"
            response += f"\n✅ Report saved: <code>{filename}</code>"
            
            return response
            
        except Exception as e:
            return f"❌ Error generating report: {str(e)}"
    
    async def handle_test(self, args: List[str]) -> str:
        """Handle test command"""
        return "✅ Bot is working correctly!"
    
    async def send_message(self, message: str, parse_mode: str = 'HTML', disable_preview: bool = True):
        """Send message via Telegram bot"""
        return self.config.send_message(message, parse_mode, disable_preview)
    
    async def process_updates(self):
        """Process Telegram updates"""
        if not self.config.token or not REQUESTS_AVAILABLE:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.config.token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 30,
                'allowed_updates': ['message']
            }
            
            response = requests.get(url, params=params, timeout=35)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    updates = data.get('result', [])
                    
                    for update in updates:
                        if 'message' in update:
                            await self.process_message(update['message'])
                        
                        if 'update_id' in update:
                            self.last_update_id = update['update_id']
        except Exception as e:
            logger.error(f"Telegram update error: {e}")
    
    async def process_message(self, message: Dict):
        """Process incoming Telegram message"""
        if 'text' not in message:
            return
        
        text = message['text']
        chat_id = message['chat']['id']
        
        # Set chat ID if not set
        if not self.config.chat_id:
            self.config.chat_id = str(chat_id)
            self.config.save_config()
        
        parts = text.split()
        if not parts:
            return
        
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Log command
        self.db.log_command(text, 'telegram', True)
        
        if command in self.command_handlers:
            try:
                response = await self.command_handlers[command](args)
                await self.send_message(response)
                logger.info(f"Telegram command executed: {command}")
            except Exception as e:
                error_msg = f"❌ Error executing command: {str(e)[:200]}"
                await self.send_message(error_msg)
                logger.error(f"Command error: {e}")
        else:
            await self.send_message("❌ Unknown command. Type /help for available commands.")
    
    async def run(self):
        """Run Telegram bot in background"""
        logger.info("Starting Telegram bot")
        
        if not self.config.token or not self.config.chat_id:
            logger.warning("Telegram not configured. Bot not started.")
            return
        
        # Send startup message
        await self.send_message(
            "🚀 <b>Accurate Online OS v4.0 MEGA EDITION</b>\n\n"
            "✅ Bot is online and ready!\n"
            "🔧 500+ commands available\n"
            "🛡️ Security monitoring active\n\n"
            "Type /help for complete command list"
        )
        
        while True:
            try:
                await self.process_updates()
                await asyncio.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Telegram bot error: {e}")
                await asyncio.sleep(10)

# =====================
# MAIN APPLICATION
# =====================
class AccurateOnlineOS:
    """Main cybersecurity application"""
    
    def __init__(self):
        self.db = DatabaseManager()
        self.telegram_config = TelegramConfig()
        self.scanner = NetworkScanner()
        self.advanced_scanner = AdvancedNetworkScanner()
        self.telegram_bot = TelegramBotHandler(self.telegram_config, self.db, self.scanner, self.advanced_scanner)
        
        self.running = True
        self.telegram_task = None
        
        # Rich console if available
        if RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None
    
    def print_banner(self):
        """Print application banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        banner = """
╔══════════════════════════════════════════════════════╗
║                                                      ║
║                🕸️ Spider Bot 🕸️                      ║
║                                                      ║
║                                                      ║
║                                                      ║
║          🔍 Professional Network Scanner             ║
║          🌐 500+ Telegram Commands                   ║
║          ⚠️ Vulnerability Assessment                 ║
║          💾 Comprehensive Reporting                  ║
║                                                      ║
║          Author: Ian Carter Kulani                   ║
║          Version: v0.0.1                             ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
"""
        print(banner)
        
        # Status information
        print("\n📊 SYSTEM STATUS:")
        print(f"  Nmap: {'✅ READY' if self.advanced_scanner.nmap_available else '⚠️ NOT INSTALLED'}")
        print(f"  Telegram: {'✅ CONNECTED' if self.telegram_config.enabled else '⚠️ NOT CONFIGURED'}")
        print(f"  Database: ✅ READY")
        print(f"  Commands: 500+ AVAILABLE")
        print("\n" + "="*80)
    
    def print_help(self):
        """Print help information"""
        help_text = """
🛠️  ADVANCED CYBERSECURITY COMMANDS 🛠️

🤖 TELEGRAM:
  setup_telegram      - Configure Telegram bot for 500+ commands
  test_telegram       - Test Telegram connection

🔍 SCANNING & ANALYSIS:
  ping <ip>           - Ping IP address
  traceroute <ip>     - Traceroute to target
  nmap <ip>           - Nmap scan with options
  quick_scan <ip>     - Quick network scan
  deep_scan <ip>      - Deep comprehensive scan
  stealth_scan <ip>   - Stealth SYN scan
  vuln_scan <ip>      - Vulnerability scan
  full_scan <ip>      - Full port scan (65535 ports)
  network_discovery   - Discover hosts in network
  analyze <ip>        - Comprehensive IP analysis
  whois <domain>      - WHOIS lookup
  dns <domain>        - DNS lookup
  location <ip>       - IP geolocation

🌐 NETWORK TOOLS:
  network_info        - Local network information
  system_info         - Detailed system information
  scan_history        - View scan results
  scan_details <id>   - View scan details
  compare_scans       - Compare two scans
  save_scan <id>      - Save scan to file
  generate_report     - Generate security report

📊 SYSTEM & MONITORING:
  status              - System status
  metrics             - System metrics
  history             - Command history
  threats             - Threat summary
  monitored_ips       - List monitored IPs
  add_ip <ip>         - Add IP to monitoring
  remove_ip <ip>      - Remove IP from monitoring

⚙️  CONFIGURATION:
  config              - Show configuration
  clear               - Clear screen
  help                - Show this help
  exit                - Exit program
"""
        print(help_text)
        
        if self.telegram_config.enabled:
            print("✅ Telegram bot is active! Send /start to your bot for 500+ commands")
        else:
            print("⚠️ Telegram not configured. Type 'setup_telegram' to enable 500+ remote commands")
    
    def start_telegram_bot(self):
        """Start Telegram bot in background"""
        if self.telegram_config.enabled and not self.telegram_task:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self.telegram_task = threading.Thread(
                    target=lambda: loop.run_until_complete(self.telegram_bot.run()),
                    daemon=True
                )
                self.telegram_task.start()
                logger.info("Telegram bot started in background")
            except Exception as e:
                logger.error(f"Failed to start Telegram bot: {e}")
    
    def setup_telegram(self):
        """Setup Telegram integration"""
        if self.telegram_config.interactive_setup():
            self.start_telegram_bot()
    
    def test_telegram(self):
        """Test Telegram connection"""
        if not self.telegram_config.token or not self.telegram_config.chat_id:
            print("❌ Telegram not configured. Run 'setup_telegram' first.")
            return
        
        print("\n🔌 Testing Telegram connection...")
        success, message = self.telegram_config.test_connection()
        
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
    
    async def handle_local_commands(self):
        """Handle local terminal commands"""
        self.print_banner()
        print("\n💻 Local terminal commands available")
        print("📋 Type 'help' for command list\n")
        print(f"📁 Scan results directory: {SCAN_RESULTS_DIR}")
        print(f"📁 Reports directory: {REPORT_DIR}")
        print("\n")
        
        while self.running:
            try:
                command = input("spiderbot🕸️> ").strip()
                
                if not command:
                    continue
                
                if command.lower() == 'exit':
                    print("👋 Exiting...")
                    self.running = False
                    break
                
                await self.process_local_command(command)
                
            except KeyboardInterrupt:
                print("\n👋 Exiting...")
                self.running = False
                break
            except Exception as e:
                print(f"❌ Error: {str(e)}")
    
    async def process_local_command(self, command: str):
        """Process a local command"""
        # Log command
        self.db.log_command(command, 'local', True)
        
        # Parse command
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Command handlers
        if cmd == 'help':
            self.print_help()
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        
        elif cmd == 'setup_telegram':
            self.setup_telegram()
        
        elif cmd == 'test_telegram':
            self.test_telegram()
        
        elif cmd == 'ping' and args:
            ip = args[0]
            count = 4
            size = 56
            
            if len(args) > 1:
                try:
                    count = int(args[1])
                except:
                    pass
            
            print(f"\n🏓 Pinging {ip} with {count} packets...")
            result = self.scanner.ping_ip(ip, count, size)
            print(result)
        
        elif cmd == 'traceroute' and args:
            target = args[0]
            print(f"\n🛣️ Traceroute to {target}...")
            result = await self.scanner.traceroute(target)
            print(result)
        
        elif cmd == 'nmap' and args:
            target = args[0]
            nmap_args = args[1:] if len(args) > 1 else []
            print(f"\n🔍 Starting Nmap scan on {target}...")
            
            if nmap_args:
                cmd_list = ['nmap', target] + nmap_args
                result = self.advanced_scanner.execute_command(cmd_list)
            else:
                result = self.advanced_scanner.perform_nmap_scan(target, 'quick')
            
            if isinstance(result, dict):
                if result['success']:
                    print(result['output'][:2000])
                else:
                    print(f"❌ Scan failed: {result['output']}")
            else:
                if result.success:
                    print(f"\n✅ Scan completed in {result.execution_time:.2f}s")
                    open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
                    print(f"🔓 Open Ports: {len(open_ports)}")
                    for port in open_ports[:10]:
                        print(f"  Port {port['port']}/{port['protocol']}: {port['service']}")
                    
                    # Save to database
                    self.db.save_scan_result(
                        result.scan_id, target, 'quick',
                        result.result.get('ports', []),
                        result.result.get('services', []),
                        result.result.get('os', ''),
                        result.vulnerabilities,
                        result.raw_output,
                        result.execution_time
                    )
                else:
                    print(f"❌ Scan failed: {result.raw_output}")
        
        elif cmd == 'quick_scan' and args:
            target = args[0]
            print(f"\n⚡ Quick scan on {target}...")
            result = self.advanced_scanner.perform_nmap_scan(target, 'quick')
            
            self.display_scan_result(result, target, 'quick')
        
        elif cmd == 'deep_scan' and args:
            target = args[0]
            print(f"\n🔍 Deep scan on {target}...")
            result = self.advanced_scanner.perform_nmap_scan(target, 'comprehensive')
            
            self.display_scan_result(result, target, 'deep')
        
        elif cmd == 'stealth_scan' and args:
            target = args[0]
            print(f"\n🕵️ Stealth scan on {target}...")
            result = self.advanced_scanner.stealth_scan(target)
            
            if result['success']:
                print(f"\n✅ Stealth scan completed in {result['execution_time']:.2f}s")
                print(result['output'][:2000])
            else:
                print(f"❌ Stealth scan failed: {result['error']}")
        
        elif cmd == 'vuln_scan' and args:
            target = args[0]
            print(f"\n⚠️ Vulnerability scan on {target}...")
            result = self.advanced_scanner.perform_nmap_scan(target, 'vulnerability')
            
            self.display_scan_result(result, target, 'vulnerability')
        
        elif cmd == 'full_scan' and args:
            target = args[0]
            print(f"\n🔍 FULL port scan on {target}... (This may take a while)")
            result = self.advanced_scanner.perform_nmap_scan(target, 'full')
            
            self.display_scan_result(result, target, 'full')
        
        elif cmd == 'network_discovery' and args:
            network_range = args[0]
            print(f"\n🌐 Discovering hosts on {network_range}...")
            result = self.advanced_scanner.network_discovery(network_range)
            
            if result['success']:
                print(f"\n✅ Discovery completed in {result['execution_time']:.2f}s")
                print(f"Hosts Found: {result['count']}")
                
                if result['hosts']:
                    print("\nDiscovered Hosts:")
                    for i, host in enumerate(result['hosts'][:20], 1):
                        print(f"  {i}. {host}")
                    
                    if len(result['hosts']) > 20:
                        print(f"  ... and {len(result['hosts']) - 20} more")
                else:
                    print("No hosts found")
            else:
                print(f"❌ Discovery failed: {result['error']}")
        
        elif cmd == 'analyze' and args:
            ip = args[0]
            print(f"\n🔍 Analyzing {ip}...")
            
            # Ping
            print(f"\n🏓 Pinging {ip}...")
            ping_result = self.scanner.ping_ip(ip, 2)
            if "successful" in ping_result:
                print("✅ Reachable")
            else:
                print("❌ Unreachable")
            
            # Location
            print(f"\n📍 Getting location...")
            location = self.scanner.get_ip_location(ip)
            loc_data = json.loads(location)
            print(f"  Country: {loc_data.get('country', 'N/A')}")
            print(f"  Region: {loc_data.get('region', 'N/A')}")
            print(f"  City: {loc_data.get('city', 'N/A')}")
            print(f"  ISP: {loc_data.get('isp', loc_data.get('org', 'N/A'))}")
            
            # Quick port scan
            print(f"\n🔍 Quick port scan...")
            result = self.advanced_scanner.perform_nmap_scan(ip, 'quick')
            if result.success:
                open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
                print(f"  Open Ports: {len(open_ports)}")
                for port in open_ports[:5]:
                    print(f"    Port {port['port']}: {port['service']}")
            else:
                print("  Port scan failed")
        
        elif cmd == 'whois' and args:
            domain = args[0]
            print(f"\n🔍 WHOIS lookup for {domain}...")
            result = self.scanner.whois_lookup(domain)
            print(result[:2000])
        
        elif cmd == 'dns' and args:
            domain = args[0]
            print(f"\n🌐 DNS lookup for {domain}...")
            result = self.scanner.dns_lookup(domain)
            print(result)
        
        elif cmd == 'location' and args:
            ip = args[0]
            print(f"\n📍 Getting location for {ip}...")
            result = self.scanner.get_ip_location(ip)
            print(result)
        
        elif cmd == 'network_info':
            print("\n🌐 Network Information:")
            result = self.scanner.get_network_info()
            print(result)
        
        elif cmd == 'system_info':
            if not PSUTIL_AVAILABLE:
                print("❌ psutil not available")
                return
            
            print("\n💻 System Information:")
            cpu_percent = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            print(f"CPU Usage: {cpu_percent:.1f}%")
            print(f"Memory: {mem.percent:.1f}% ({mem.used / (1024**3):.1f} GB used)")
            print(f"Disk: {disk.percent:.1f}% ({disk.used / (1024**3):.1f} GB used)")
            print(f"Hostname: {socket.gethostname()}")
            print(f"OS: {platform.system()} {platform.release()}")
        
        elif cmd == 'status':
            print("\n📊 System Status:")
            print(f"  Nmap: {'✅ Available' if self.advanced_scanner.nmap_available else '❌ Not available'}")
            print(f"  Telegram: {'✅ Connected' if self.telegram_config.enabled else '❌ Not configured'}")
            print(f"  Database: ✅ Ready")
            
            if PSUTIL_AVAILABLE:
                cpu_percent = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                print(f"  CPU: {cpu_percent:.1f}%")
                print(f"  Memory: {mem.percent:.1f}%")
                print(f"  Connections: {len(psutil.net_connections())}")
        
        elif cmd == 'metrics':
            if not PSUTIL_AVAILABLE:
                print("❌ psutil not available")
                return
            
            print("\n📈 System Metrics:")
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net_io = psutil.net_io_counters()
            
            print(f"💻 CPU Usage:")
            print(f"  Total: {psutil.cpu_percent()}%")
            print(f"  Per Core: {', '.join([f'{p:.1f}%' for p in cpu_percent])}")
            
            print(f"\n🧠 Memory:")
            print(f"  Total: {mem.total / (1024**3):.2f} GB")
            print(f"  Used: {mem.used / (1024**3):.2f} GB ({mem.percent}%)")
            print(f"  Available: {mem.available / (1024**3):.2f} GB")
            
            print(f"\n💾 Disk:")
            print(f"  Total: {disk.total / (1024**3):.2f} GB")
            print(f"  Used: {disk.used / (1024**3):.2f} GB ({disk.percent}%)")
            print(f"  Free: {disk.free / (1024**3):.2f} GB")
            
            print(f"\n🌐 Network:")
            print(f"  Sent: {net_io.bytes_sent / (1024**2):.2f} MB")
            print(f"  Received: {net_io.bytes_recv / (1024**2):.2f} MB")
        
        elif cmd == 'history':
            print("\n📜 Command History:")
            history = self.db.get_command_history(15)
            
            if not history:
                print("No commands recorded")
            else:
                for i, row in enumerate(history, 1):
                    status = "✅" if row['success'] else "❌"
                    timestamp = row['timestamp'].split('.')[0]
                    print(f"{i}. {status} [{row['source']}] {row['command'][:50]} | {timestamp}")
        
        elif cmd == 'scan_history':
            print("\n📄 Scan History:")
            scans = self.db.get_scan_results(10)
            
            if not scans:
                print("No scan results found")
            else:
                for i, scan in enumerate(scans, 1):
                    print(f"{i}. {scan['target']}")
                    print(f"   Type: {scan['scan_type']}")
                    print(f"   Time: {scan['timestamp']}")
                    print(f"   ID: {scan['scan_id']}\n")
        
        elif cmd == 'scan_details' and args:
            scan_id = args[0]
            print(f"\n📊 Scan Details: {scan_id}")
            
            scan = self.db.get_scan_details(scan_id)
            if not scan:
                print(f"Scan not found: {scan_id}")
                return
            
            print(f"Target: {scan['target']}")
            print(f"Type: {scan['scan_type']}")
            print(f"Time: {scan['timestamp']}")
            
            if scan['open_ports']:
                ports = json.loads(scan['open_ports'])
                open_ports = [p for p in ports if p['state'] == 'open']
                
                if open_ports:
                    print(f"\nOpen Ports: {len(open_ports)}")
                    for port in open_ports[:10]:
                        print(f"  Port {port['port']}/{port['protocol']}: {port['service']}")
        
        elif cmd == 'threats':
            print("\n⚠️ Recent Threats:")
            threats = self.db.get_recent_threats(10)
            
            if not threats:
                print("No recent threats detected")
            else:
                for threat in threats:
                    print(f"• {threat['ip_address']}")
                    print(f"  Type: {threat['threat_type']} | Severity: {threat['severity']}")
                    print(f"  Time: {threat['timestamp']}\n")
        
        elif cmd == 'generate_report':
            print("\n📊 Generating security report...")
            
            threats = self.db.get_recent_threats(50)
            scan_results = self.db.get_scan_results(50)
            history = self.db.get_command_history(100)
            
            report = {
                'generated_at': datetime.datetime.now().isoformat(),
                'statistics': {
                    'total_threats': len(threats),
                    'total_scans': len(scan_results),
                    'high_severity': len([t for t in threats if t['severity'] == 'high']),
                    'medium_severity': len([t for t in threats if t['severity'] == 'medium']),
                    'low_severity': len([t for t in threats if t['severity'] == 'low']),
                    'commands_executed': len(history)
                }
            }
            
            filename = f"security_report_{int(time.time())}.json"
            filepath = Path(REPORT_DIR) / filename
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            print("\n✅ Security Report Generated")
            print(f"Total Threats: {report['statistics']['total_threats']}")
            print(f"Total Scans: {report['statistics']['total_scans']}")
            print(f"High Severity: {report['statistics']['high_severity']}")
            print(f"Medium Severity: {report['statistics']['medium_severity']}")
            print(f"Low Severity: {report['statistics']['low_severity']}")
            print(f"Commands Executed: {report['statistics']['commands_executed']}")
            print(f"\n📄 Report saved: {filename}")
        
        elif cmd == 'config':
            print("\n⚙️ Configuration:")
            print(f"  Telegram: {'Enabled' if self.telegram_config.enabled else 'Disabled'}")
            if self.telegram_config.enabled:
                print(f"  Bot: @{self.telegram_config.bot_username}")
                print(f"  Chat ID: {self.telegram_config.chat_id}")
            print(f"  Database: {DATABASE_FILE}")
            print(f"  Logs: {LOG_FILE}")
            print(f"  Reports: {REPORT_DIR}")
            print(f"  Scans: {SCAN_RESULTS_DIR}")
        
        elif cmd == 'monitored_ips':
            ips = self.db.get_monitored_ips()
            print(f"\n📋 Monitored IPs: {len(ips)}")
            for ip in ips:
                print(f"  • {ip}")
        
        elif cmd == 'add_ip' and args:
            ip = args[0]
            try:
                ipaddress.ip_address(ip)
                self.db.add_monitored_ip(ip)
                print(f"✅ Added {ip} to monitoring")
            except ValueError:
                print(f"❌ Invalid IP: {ip}")
        
        elif cmd == 'remove_ip' and args:
            ip = args[0]
            self.db.remove_monitored_ip(ip)
            print(f"✅ Removed {ip} from monitoring")
        
        else:
            print("❌ Unknown command. Type 'help' for available commands.")
    
    def display_scan_result(self, result: ScanResult, target: str, scan_type: str):
        """Display scan results"""
        if result.success:
            print(f"\n✅ {scan_type.capitalize()} scan completed in {result.execution_time:.2f}s")
            print(f"Target: {target}")
            print(f"Status: {result.result.get('status', 'unknown')}")
            
            open_ports = [p for p in result.result.get('ports', []) if p['state'] == 'open']
            print(f"🔓 Open Ports: {len(open_ports)}")
            
            for port in open_ports[:15]:
                port_str = f"  Port {port['port']}/{port['protocol']}: {port['service']}"
                if 'version' in port:
                    port_str += f" ({port['version']})"
                print(port_str)
            
            if len(open_ports) > 15:
                print(f"  ... and {len(open_ports) - 15} more")
            
            if result.vulnerabilities:
                print(f"\n⚠️ Vulnerabilities: {len(result.vulnerabilities)}")
                for vuln in result.vulnerabilities[:5]:
                    print(f"  Port {vuln['port']}: {vuln['issues'][0]}")
            
            # Save to database
            self.db.save_scan_result(
                result.scan_id, target, scan_type,
                result.result.get('ports', []),
                result.result.get('services', []),
                result.result.get('os', ''),
                result.vulnerabilities,
                result.raw_output,
                result.execution_time
            )
            
            # Save to file
            save_path = self.advanced_scanner.save_scan_to_file(result)
            print(f"\n💾 Scan saved to: {save_path}")
            print(f"📄 Scan ID: {result.scan_id}")
        else:
            print(f"❌ Scan failed: {result.raw_output}")
    
    async def run(self):
        """Main run method"""
        try:
            # Print banner
            self.print_banner()
            
            # Check if Telegram is configured
            if self.telegram_config.enabled:
                self.start_telegram_bot()
                print("✅ Telegram bot is active! Send /start to your bot for 500+ commands")
            else:
                print("⚠️ Telegram not configured. Type 'setup_telegram' to enable 500+ remote commands")
            
            print("\nType 'help' for available commands")
            print("="*80 + "\n")
            
            # Start main menu
            await self.handle_local_commands()
            
        except KeyboardInterrupt:
            print("\n👋 Thank you for using Accurate Online OS MEGA EDITION!")
        except Exception as e:
            print(f"❌ Application error: {str(e)}")
            logger.error(f"Application error: {e}", exc_info=True)
        finally:
            # Cleanup
            print("\n✅ Tool shutdown complete")
            sys.exit(0)

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher required")
        sys.exit(1)
    
    # Check dependencies
    required_packages = ["requests", "psutil"]
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"⚠️ Missing packages: {', '.join(missing_packages)}")
        install = input("Install missing packages? (y/n): ")
        if install.lower() == 'y':
            import subprocess
            for package in missing_packages:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    print(f"✅ {package} installed")
                except Exception as e:
                    print(f"❌ Failed to install {package}: {e}")
    
    # Check Nmap installation
    scanner = AdvancedNetworkScanner()
    if not scanner.nmap_available:
        print("\n🔍 NMAP NOT INSTALLED")
        print("="*50)
        print("To use advanced scanning features, install Nmap:")
        print("\n📦 Windows:")
        print("   1. Download from: https://nmap.org/download.html")
        print("   2. Run installer")
        print("   3. Add Nmap to PATH during installation")
        print("\n🍎 macOS:")
        print("   brew install nmap")
        print("\n🐧 Linux:")
        print("   sudo apt-get install nmap  # Ubuntu/Debian")
        print("   sudo yum install nmap      # CentOS/RHEL")
        print("\n⚠️ Basic commands will work, but scanning features require Nmap")
        print("="*50)
        input("\nPress Enter to continue...")
    
    # Create and run application
    app = AccurateOnlineOS()
    
    # Run the application
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        print("\n👋 Exiting...")

if __name__ == "__main__":
    main()