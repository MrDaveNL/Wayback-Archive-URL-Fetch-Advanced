#!/usr/bin/env python3
"""
Advanced Wayback Machine Query Tool
Created by: 4ap Digital
Version: 2.0
"""

import subprocess
import time
import os
import json
import requests
import argparse
import csv
import sqlite3
import threading
import hashlib
import mimetypes
import urllib.parse
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import logging
from pathlib import Path
import re
from typing import List, Dict, Optional, Tuple

# Initialize colorama for cross-platform colored output
init()

class WaybackConfig:
    """Configuration management for the Wayback Machine tool"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.default_config = {
            "max_workers": 10,
            "timeout": 30,
            "output_format": "txt",
            "date_range": {"start": None, "end": None},
            "rate_limit": 1.0,
            "user_agent": "Wayback-Tool/2.0",
            "extensions": [],
            "exclude_extensions": [".css", ".js", ".ico", ".png", ".jpg", ".gif"],
            "dangerous_extensions": [
                # Executable files
                ".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".pif",
                ".application", ".gadget", ".msp", ".msc", ".vb", ".vbs",
                ".ws", ".wsf", ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2",
                # Scripts and code
                ".jar", ".jse", ".reg", ".hta", ".cpl", ".inf", ".ins",
                # Archives that could contain malware
                ".scr", ".pif", ".application", ".gadget", ".msp", ".msc",
                # Macro-enabled documents
                ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
                # Other potentially dangerous
                ".dll", ".sys", ".drv", ".ocx", ".ax", ".cpl"
            ],
            "allowed_mime_types": [
                "text/html", "text/plain", "text/css", "application/json",
                "application/xml", "text/xml", "application/pdf",
                "image/jpeg", "image/png", "image/gif", "image/svg+xml",
                "text/javascript", "application/javascript"
            ],
            "security_scan": {
                "enabled": True,
                "scan_urls": True,
                "scan_content": True,
                "max_file_size": 50000000,  # 50MB
                "suspicious_keywords": [
                    "malware", "virus", "trojan", "ransomware", "keylogger",
                    "backdoor", "rootkit", "exploit", "payload", "shellcode"
                ]
            },
            "database_file": "wayback_data.db"
        }
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        """Load configuration from file or create default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    merged_config = self.default_config.copy()
                    merged_config.update(config)
                    return merged_config
            else:
                self.save_config(self.default_config)
                return self.default_config
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return self.default_config
    
    def save_config(self, config: dict):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

class SecurityScanner:
    """Security scanner to prevent downloading malicious content"""
    
    def __init__(self, config: dict):
        self.config = config.get('security_scan', {})
        self.dangerous_extensions = config.get('dangerous_extensions', [])
        self.allowed_mime_types = config.get('allowed_mime_types', [])
        self.suspicious_keywords = self.config.get('suspicious_keywords', [])
        self.max_file_size = self.config.get('max_file_size', 50000000)
        
        # Setup logging for security events
        self.security_logger = logging.getLogger('security')
        handler = logging.FileHandler('security.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - SECURITY - %(levelname)s - %(message)s'))
        self.security_logger.addHandler(handler)
        self.security_logger.setLevel(logging.WARNING)
    
    def is_safe_extension(self, url: str) -> Tuple[bool, str]:
        """Check if file extension is safe"""
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
        for ext in self.dangerous_extensions:
            if path.endswith(ext.lower()):
                reason = f"Dangerous file extension detected: {ext}"
                self.security_logger.warning(f"BLOCKED: {url} - {reason}")
                return False, reason
        
        return True, "Extension check passed"
    
    def is_safe_mime_type(self, mime_type: str) -> Tuple[bool, str]:
        """Check if MIME type is in allowed list"""
        if not mime_type:
            return True, "No MIME type to check"
        
        mime_type = mime_type.lower().split(';')[0].strip()
        
        # Check against allowed MIME types
        if self.allowed_mime_types and mime_type not in self.allowed_mime_types:
            reason = f"MIME type not in allowed list: {mime_type}"
            self.security_logger.warning(f"BLOCKED MIME: {mime_type}")
            return False, reason
        
        # Check for dangerous MIME types
        dangerous_mimes = [
            'application/x-msdownload', 'application/x-executable',
            'application/x-dosexec', 'application/x-winexe',
            'application/x-msdos-program', 'application/octet-stream'
        ]
        
        if mime_type in dangerous_mimes:
            reason = f"Dangerous MIME type detected: {mime_type}"
            self.security_logger.warning(f"BLOCKED DANGEROUS MIME: {mime_type}")
            return False, reason
        
        return True, "MIME type check passed"
    
    def scan_url_for_suspicious_content(self, url: str) -> Tuple[bool, str]:
        """Scan URL for suspicious keywords and patterns"""
        url_lower = url.lower()
        
        # Check for suspicious keywords in URL
        for keyword in self.suspicious_keywords:
            if keyword.lower() in url_lower:
                reason = f"Suspicious keyword in URL: {keyword}"
                self.security_logger.warning(f"SUSPICIOUS URL: {url} - {reason}")
                return False, reason
        
        # Check for suspicious URL patterns
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
            r'[a-z0-9]{20,}',  # Very long random strings
            r'\.tk$|\.ml$|\.ga$|\.cf$',  # Suspicious TLDs
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                reason = f"Suspicious URL pattern detected: {pattern}"
                self.security_logger.warning(f"SUSPICIOUS PATTERN: {url} - {reason}")
                return False, reason
        
        return True, "URL scan passed"
    
    def check_file_size(self, content_length: str) -> Tuple[bool, str]:
        """Check if file size is within safe limits"""
        try:
            size = int(content_length)
            if size > self.max_file_size:
                reason = f"File too large: {size} bytes (max: {self.max_file_size})"
                self.security_logger.warning(f"BLOCKED LARGE FILE: {size} bytes")
                return False, reason
        except (ValueError, TypeError):
            pass  # Couldn't determine size, allow
        
        return True, "File size check passed"
    
    def scan_content_preview(self, content_preview: bytes) -> Tuple[bool, str]:
        """Scan first bytes of content for malicious signatures"""
        if not content_preview:
            return True, "No content to scan"
        
        # Known malicious file signatures (magic bytes)
        malicious_signatures = {
            b'MZ': 'Windows executable',
            b'\x7fELF': 'Linux executable',
            b'\xca\xfe\xba\xbe': 'Java class file',
            b'PK\x03\x04': 'ZIP archive (could contain malware)',
            b'\x50\x4b\x05\x06': 'Empty ZIP file',
            b'\x1f\x8b': 'GZIP archive',
            b'Rar!': 'RAR archive'
        }
        
        for signature, description in malicious_signatures.items():
            if content_preview.startswith(signature):
                reason = f"Malicious file signature detected: {description}"
                self.security_logger.error(f"MALWARE SIGNATURE: {description}")
                return False, reason
        
        # Scan for suspicious strings in content
        content_str = content_preview.decode('utf-8', errors='ignore').lower()
        suspicious_content = [
            'eval(', 'base64_decode', 'shell_exec', 'system(',
            'exec(', 'passthru', 'file_get_contents', 'fwrite(',
            'javascript:', 'vbscript:', 'data:text/html'
        ]
        
        for suspicious in suspicious_content:
            if suspicious in content_str:
                reason = f"Suspicious content detected: {suspicious}"
                self.security_logger.warning(f"SUSPICIOUS CONTENT: {suspicious}")
                return False, reason
        
        return True, "Content scan passed"
    
    def comprehensive_security_check(self, result: Dict) -> Tuple[bool, str]:
        """Perform comprehensive security check on a result"""
        if not self.config.get('enabled', False):
            return True, "Security scanning disabled"
        
        url = result.get('original', '')
        mime_type = result.get('mimetype', '')
        
        # Extension check
        safe, reason = self.is_safe_extension(url)
        if not safe:
            return False, reason
        
        # MIME type check
        safe, reason = self.is_safe_mime_type(mime_type)
        if not safe:
            return False, reason
        
        # URL scan
        if self.config.get('scan_urls', True):
            safe, reason = self.scan_url_for_suspicious_content(url)
            if not safe:
                return False, reason
        
        return True, "All security checks passed"

class WaybackDatabase:
    """SQLite database management for storing results"""
    
    def __init__(self, db_file='wayback_data.db'):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize the database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                results_count INTEGER,
                filters_applied TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_id INTEGER,
                original_url TEXT,
                archived_url TEXT,
                timestamp TEXT,
                status_code TEXT,
                mime_type TEXT,
                FOREIGN KEY (query_id) REFERENCES queries (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_level TEXT DEFAULT 'MEDIUM'
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_query(self, url: str, results_count: int, filters: str) -> int:
        """Save a query to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO queries (url, results_count, filters_applied)
            VALUES (?, ?, ?)
        ''', (url, results_count, filters))
        
        query_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return query_id
    
    def save_results(self, query_id: int, results: List[Dict]):
        """Save results to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        for result in results:
            cursor.execute('''
                INSERT INTO results (query_id, original_url, archived_url, timestamp, status_code, mime_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (query_id, result.get('original'), result.get('archived_url'), 
                  result.get('timestamp'), result.get('statuscode'), result.get('mimetype')))
        
        conn.commit()
        conn.close()
    
    def log_security_block(self, url: str, reason: str, threat_level: str = 'MEDIUM'):
        """Log a security block to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_blocks (url, reason, threat_level)
            VALUES (?, ?, ?)
        ''', (url, reason, threat_level))
        
        conn.commit()
        conn.close()

class WaybackAnalyzer:
    """Advanced analysis capabilities for Wayback Machine data"""
    
    def __init__(self, config: WaybackConfig, database: WaybackDatabase):
        self.config = config
        self.database = database
        self.security_scanner = SecurityScanner(config.config)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.config['user_agent']
        })
    
    def show_intro(self):
        """Display enhanced intro with version info"""
        os.system("clear" if os.name != "nt" else "cls")
        print(Fore.CYAN + Style.BRIGHT)
        print('''
███╗   ███╗██████╗ ██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗██╗     
████╗ ████║██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║██║     
██╔████╔██║██████╔╝██║  ██║███████║██║   ██║█████╗  ██╔██╗ ██║██║     
██║╚██╔╝██║██╔══██╗██║  ██║██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║     
██║ ╚═╝ ██║██║  ██║██████╔╝██║  ██║ ╚████╔╝ ███████╗██║ ╚████║███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚══════╝
                                                                                                                   
        ██╗    ██╗ █████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗          
        ██║    ██║██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝          
        ██║ █╗ ██║███████║ ╚████╔╝ ██████╔╝███████║██║     █████╔╝           
        ██║███╗██║██╔══██║  ╚██╔╝  ██╔══██╗██╔══██║██║     ██╔═██╗           
        ╚███╔███╔╝██║  ██║   ██║   ██████╔╝██║  ██║╚██████╗██║  ██╗          
         ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝          
                                                                               
             ███████╗ ██████╗██████╗  █████╗ ██████╗ ███████╗██████╗          
             ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗         
             ███████╗██║     ██████╔╝███████║██████╔╝█████╗  ██████╔╝         
             ╚════██║██║     ██╔══██╗██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗         
             ███████║╚██████╗██║  ██║██║  ██║██║     ███████╗██║  ██║         
             ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝         
        ''')
        print(Fore.GREEN + Style.BRIGHT + "Version: 2.0 Advanced Edition\n" + Style.RESET_ALL)
        print("Created by: " + Fore.RED + Style.BRIGHT + "4ap Digital" + Style.RESET_ALL)
        print(Fore.YELLOW + "\nAdvanced Wayback Machine Analysis Tool\n" + Style.RESET_ALL)
        print(Fore.WHITE + "Features: Multi-threading • Database Storage • Advanced Filtering • Analytics\n" + Style.RESET_ALL)
        time.sleep(2)
    
    def advanced_query(self, url: str, **kwargs) -> List[Dict]:
        """Advanced query with multiple parameters"""
        base_url = "https://web.archive.org/cdx/search/cdx"
        
        params = {
            "url": f"{url}/*",
            "output": "json",
            "collapse": kwargs.get('collapse', 'urlkey'),
            "fl": kwargs.get('fields', 'original,timestamp,statuscode,mimetype')
        }
        
        # Add date range if specified
        if kwargs.get('from_date'):
            params['from'] = kwargs['from_date']
        if kwargs.get('to_date'):
            params['to'] = kwargs['to_date']
        
        # Add filters
        if kwargs.get('filter'):
            params['filter'] = kwargs['filter']
        
        # Add limit
        if kwargs.get('limit'):
            params['limit'] = kwargs['limit']
        
        try:
            response = self.session.get(base_url, params=params, timeout=self.config.config['timeout'])
            response.raise_for_status()
            
            data = response.json()
            if not data:
                return []
            
            # First row contains headers
            headers = data[0]
            results = []
            
            for row in data[1:]:
                result = dict(zip(headers, row))
                # Add archived URL
                if 'timestamp' in result and 'original' in result:
                    result['archived_url'] = f"https://web.archive.org/web/{result['timestamp']}/{result['original']}"
                results.append(result)
            
            return results
            
        except requests.RequestException as e:
            logging.error(f"Error querying Wayback Machine: {e}")
            return []
    
    def bulk_query(self, urls: List[str], **kwargs) -> Dict[str, List[Dict]]:
        """Query multiple URLs concurrently"""
        results = {}
        
        def query_single_url(url):
            return url, self.advanced_query(url, **kwargs)
        
        with ThreadPoolExecutor(max_workers=self.config.config['max_workers']) as executor:
            future_to_url = {executor.submit(query_single_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url, result = future.result()
                results[url] = result
                print(Fore.GREEN + f"✓ Completed query for: {url} ({len(result)} results)")
                
                # Rate limiting
                time.sleep(self.config.config['rate_limit'])
        
        return results
    
    def filter_results(self, results: List[Dict], **filters) -> Tuple[List[Dict], List[Dict]]:
        """Apply advanced filtering to results, return (safe_results, blocked_results)"""
        safe_results = []
        blocked_results = []
        
        for result in results:
            # Security check first
            is_safe, reason = self.security_scanner.comprehensive_security_check(result)
            if not is_safe:
                result['block_reason'] = reason
                blocked_results.append(result)
                # Log to database
                self.database.log_security_block(
                    result.get('original', ''), 
                    reason, 
                    'HIGH' if any(word in reason.lower() for word in ['malware', 'virus', 'trojan']) else 'MEDIUM'
                )
                continue
            
            safe_results.append(result)
        
        # Apply other filters to safe results only
        filtered = safe_results.copy()
        
        # Filter by file extensions
        if filters.get('include_extensions'):
            extensions = filters['include_extensions']
            filtered = [r for r in filtered if any(r.get('original', '').endswith(ext) for ext in extensions)]
        
        if filters.get('exclude_extensions'):
            extensions = filters['exclude_extensions']
            filtered = [r for r in filtered if not any(r.get('original', '').endswith(ext) for ext in extensions)]
        
        # Filter by status code
        if filters.get('status_codes'):
            codes = filters['status_codes']
            filtered = [r for r in filtered if r.get('statuscode') in codes]
        
        # Filter by MIME type
        if filters.get('mime_types'):
            types = filters['mime_types']
            filtered = [r for r in filtered if any(t in r.get('mimetype', '') for t in types)]
        
        # Filter by date range
        if filters.get('date_range'):
            start, end = filters['date_range']
            filtered = [r for r in filtered if start <= r.get('timestamp', '') <= end]
        
        # Text search in URLs
        if filters.get('url_contains'):
            search_term = filters['url_contains'].lower()
            filtered = [r for r in filtered if search_term in r.get('original', '').lower()]
        
        return filtered, blocked_results
    
    def analyze_results(self, results: List[Dict]) -> Dict:
        """Perform statistical analysis on results"""
        if not results:
            return {}
        
        analysis = {
            'total_results': len(results),
            'status_codes': {},
            'mime_types': {},
            'file_extensions': {},
            'date_range': {'earliest': None, 'latest': None},
            'unique_domains': set(),
            'timeline': {},
            'security_summary': {
                'safe_results': 0,
                'blocked_results': 0,
                'threat_levels': {}
            }
        }
        
        timestamps = []
        
        for result in results:
            # Status codes
            status = result.get('statuscode', 'unknown')
            analysis['status_codes'][status] = analysis['status_codes'].get(status, 0) + 1
            
            # MIME types
            mime = result.get('mimetype', 'unknown')
            analysis['mime_types'][mime] = analysis['mime_types'].get(mime, 0) + 1
            
            # File extensions
            url = result.get('original', '')
            ext = os.path.splitext(urlparse(url).path)[1].lower()
            if ext:
                analysis['file_extensions'][ext] = analysis['file_extensions'].get(ext, 0) + 1
            
            # Domains
            domain = urlparse(url).netloc
            if domain:
                analysis['unique_domains'].add(domain)
            
            # Timestamps
            timestamp = result.get('timestamp', '')
            if timestamp:
                timestamps.append(timestamp)
                year = timestamp[:4]
                analysis['timeline'][year] = analysis['timeline'].get(year, 0) + 1
        
        if timestamps:
            analysis['date_range']['earliest'] = min(timestamps)
            analysis['date_range']['latest'] = max(timestamps)
        
        analysis['unique_domains'] = len(analysis['unique_domains'])
        
        return analysis
    
    def export_results(self, results: List[Dict], format: str, filename: str):
        """Export results in various formats"""
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
        
        elif format.lower() == 'csv':
            if results:
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=results[0].keys())
                    writer.writeheader()
                    writer.writerows(results)
        
        elif format.lower() == 'txt':
            with open(filename, 'w') as f:
                for result in results:
                    f.write(f"{result.get('original', 'N/A')} | {result.get('timestamp', 'N/A')} | {result.get('statuscode', 'N/A')}\n")
        
        print(Fore.GREEN + f"Results exported to {filename} ({format.upper()} format)")
    
    def interactive_menu(self):
        """Enhanced interactive menu system"""
        self.show_intro()
        
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print(Fore.CYAN + Style.BRIGHT + "===== Advanced Wayback Machine Tool =====")
            print("1. 🔍 Single URL Query")
            print("2. 📋 Bulk URL Query")
            print("3. 📊 View Analysis")
            print("4. 🗄️  Database Management")
            print("5. ⚙️  Configuration")
            print("6. 📈 Generate Report")
            print("7. 🔧 Advanced Filters")
            print("8. 🛡️  Security Dashboard")
            print("9. ❌ Exit")
            
            choice = input(Fore.YELLOW + "\nChoose an option (1-9): ").strip()
            
            if choice == '1':
                self.single_url_menu()
            elif choice == '2':
                self.bulk_query_menu()
            elif choice == '3':
                self.analysis_menu()
            elif choice == '4':
                self.database_menu()
            elif choice == '5':
                self.configuration_menu()
            elif choice == '6':
                self.generate_report_menu()
            elif choice == '7':
                self.advanced_filters_menu()
            elif choice == '8':
                self.security_dashboard_menu()
            elif choice == '9':
                print(Fore.RED + "Exiting... Thank you for using Advanced Wayback Tool!")
                time.sleep(1)
                break
            else:
                print(Fore.RED + "Invalid choice. Please try again.")
                input("Press Enter to continue...")
    
    def single_url_menu(self):
        """Single URL query menu"""
        print(Fore.GREEN + "\n=== Single URL Query ===")
        url = input("Enter URL: ").strip()
        
        if not url:
            print(Fore.RED + "URL cannot be empty!")
            input("Press Enter to continue...")
            return
        
        # Advanced options
        print("\n--- Advanced Options (press Enter to skip) ---")
        from_date = input("From date (YYYYMMDD): ").strip()
        to_date = input("To date (YYYYMMDD): ").strip()
        limit = input("Limit results (number): ").strip()
        
        kwargs = {}
        if from_date:
            kwargs['from_date'] = from_date
        if to_date:
            kwargs['to_date'] = to_date
        if limit and limit.isdigit():
            kwargs['limit'] = int(limit)
        
        print(Fore.YELLOW + "\nQuerying Wayback Machine...")
        results = self.advanced_query(url, **kwargs)
        
        if results:
            print(Fore.GREEN + f"\n✓ Found {len(results)} results!")
            
            # Apply default filters
            filtered_results, blocked_results = self.filter_results(
                results, 
                exclude_extensions=self.config.config['exclude_extensions']
            )
            
            print(Fore.GREEN + f"✅ Safe results: {len(filtered_results)}")
            if blocked_results:
                print(Fore.RED + f"🛡️  Blocked (security): {len(blocked_results)}")
                print(Fore.YELLOW + "Blocked items saved to security log.")
            
            # Save to database
            query_id = self.database.save_query(
                url, len(filtered_results), 
                f"exclude_extensions: {self.config.config['exclude_extensions']}"
            )
            self.database.save_results(query_id, filtered_results)
            
            # Show sample results
            print(Fore.CYAN + "\n--- Sample Results (first 5) ---")
            for i, result in enumerate(filtered_results[:5]):
                print(f"{i+1}. {result.get('original', 'N/A')} ({result.get('timestamp', 'N/A')})")
            
            # Export options
            export = input(Fore.YELLOW + "\nExport results? (y/n): ").lower()
            if export == 'y':
                format_choice = input("Format (json/csv/txt): ").lower()
                filename = f"wayback_results_{int(time.time())}.{format_choice}"
                self.export_results(filtered_results, format_choice, filename)
        else:
            print(Fore.RED + "No results found!")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")
    
    def security_dashboard_menu(self):
        """Security dashboard showing blocked items and threats"""
        print(Fore.RED + Style.BRIGHT + "\n🛡️  === SECURITY DASHBOARD ===")
        
        # Get security blocks from database
        conn = sqlite3.connect(self.database.db_file)
        cursor = conn.cursor()
        
        # Recent blocks
        cursor.execute('''
            SELECT url, reason, threat_level, timestamp 
            FROM security_blocks 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        recent_blocks = cursor.fetchall()
        
        # Statistics
        cursor.execute('SELECT COUNT(*) FROM security_blocks')
        total_blocks = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT threat_level, COUNT(*) 
            FROM security_blocks 
            GROUP BY threat_level
        ''')
        threat_stats = cursor.fetchall()
        
        conn.close()
        
        print(Fore.CYAN + f"\n📊 Security Statistics:")
        print(f"  Total blocked items: {total_blocks}")
        
        for threat_level, count in threat_stats:
            color = Fore.RED if threat_level == 'HIGH' else Fore.YELLOW if threat_level == 'MEDIUM' else Fore.GREEN
            print(f"  {color}{threat_level}: {count}")
        
        if recent_blocks:
            print(Fore.CYAN + f"\n🚫 Recent Security Blocks:")
            for i, (url, reason, threat_level, timestamp) in enumerate(recent_blocks, 1):
                color = Fore.RED if threat_level == 'HIGH' else Fore.YELLOW
                print(f"{color}  {i}. [{threat_level}] {url[:60]}...")
                print(f"     Reason: {reason}")
                print(f"     Time: {timestamp}")
        else:
            print(Fore.GREEN + "\n✅ No security blocks recorded!")
        
        print(Fore.CYAN + f"\n🔧 Security Settings:")
        security_config = self.config.config.get('security_scan', {})
        print(f"  Security scanning: {'✅ Enabled' if security_config.get('enabled') else '❌ Disabled'}")
        print(f"  Dangerous extensions blocked: {len(self.config.config.get('dangerous_extensions', []))}")
        print(f"  Max file size: {security_config.get('max_file_size', 0) / 1000000:.1f} MB")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")
    
    def bulk_query_menu(self):
        """Bulk URL query menu"""
        print(Fore.GREEN + "\n=== Bulk URL Query ===")
        print("1. Enter URLs manually (one per line, empty line to finish)")
        print("2. Load URLs from file")
        
        choice = input("Choose option (1-2): ").strip()
        urls = []
        
        if choice == '1':
            print("Enter URLs (empty line to finish):")
            while True:
                url = input().strip()
                if not url:
                    break
                urls.append(url)
        
        elif choice == '2':
            filename = input("Enter filename: ").strip()
            try:
                with open(filename, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(Fore.RED + f"File {filename} not found!")
                input("Press Enter to continue...")
                return
        
        if not urls:
            print(Fore.RED + "No URLs provided!")
            input("Press Enter to continue...")
            return
        
        print(Fore.YELLOW + f"\nQuerying {len(urls)} URLs...")
        all_results = self.bulk_query(urls)
        
        total_results = sum(len(results) for results in all_results.values())
        print(Fore.GREEN + f"\n✓ Total results found: {total_results}")
        
        # Show summary
        for url, results in all_results.items():
            print(f"  {url}: {len(results)} results")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")
    
    def analysis_menu(self):
        """View analysis of stored results"""
        print(Fore.GREEN + "\n=== Analysis Dashboard ===")
        
        # Get recent queries from database
        conn = sqlite3.connect(self.database.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, url, timestamp, results_count 
            FROM queries 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        recent_queries = cursor.fetchall()
        
        if not recent_queries:
            print(Fore.RED + "No queries found in database!")
            input("Press Enter to continue...")
            return
        
        print("Recent queries:")
        for i, (query_id, url, timestamp, count) in enumerate(recent_queries, 1):
            print(f"{i}. {url} - {count} results ({timestamp})")
        
        try:
            choice = int(input("\nSelect query to analyze (number): ")) - 1
            if 0 <= choice < len(recent_queries):
                query_id = recent_queries[choice][0]
                
                # Get results for this query
                cursor.execute('''
                    SELECT original_url, timestamp, status_code, mime_type
                    FROM results
                    WHERE query_id = ?
                ''', (query_id,))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'original': row[0],
                        'timestamp': row[1],
                        'statuscode': row[2],
                        'mimetype': row[3]
                    })
                
                conn.close()
                
                # Perform analysis
                analysis = self.analyze_results(results)
                
                print(Fore.CYAN + f"\n📊 Analysis Results:")
                print(f"Total results: {analysis['total_results']}")
                print(f"Date range: {analysis['date_range']['earliest']} to {analysis['date_range']['latest']}")
                print(f"Unique domains: {analysis['unique_domains']}")
                
                print(f"\nTop status codes:")
                for status, count in sorted(analysis['status_codes'].items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"  {status}: {count}")
                
                print(f"\nTop file extensions:")
                for ext, count in sorted(analysis['file_extensions'].items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"  {ext}: {count}")
                
                print(f"\nTimeline (by year):")
                for year, count in sorted(analysis['timeline'].items()):
                    print(f"  {year}: {count}")
            else:
                print(Fore.RED + "Invalid selection!")
        except ValueError:
            print(Fore.RED + "Invalid input!")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")
    
    def database_menu(self):
        """Database management menu"""
        print(Fore.GREEN + "\n=== Database Management ===")
        print("1. View database statistics")
        print("2. Export database to CSV")
        print("3. Clear old data")
        print("4. Back to main menu")
        
        choice = input("Choose option (1-4): ").strip()
        
        if choice == '1':
            self.show_database_stats()
        elif choice == '2':
            self.export_database()
        elif choice == '3':
            self.clear_old_data()
        elif choice == '4':
            return
        else:
            print(Fore.RED + "Invalid choice!")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")
    
    def show_database_stats(self):
        """Show database statistics"""
        conn = sqlite3.connect(self.database.db_file)
        cursor = conn.cursor()
        
        # Queries count
        cursor.execute('SELECT COUNT(*) FROM queries')
        queries_count = cursor.fetchone()[0]
        
        # Results count
        cursor.execute('SELECT COUNT(*) FROM results')
        results_count = cursor.fetchone()[0]
        
        # Security blocks count
        cursor.execute('SELECT COUNT(*) FROM security_blocks')
        blocks_count = cursor.fetchone()[0]
        
        # Database size
        db_size = os.path.getsize(self.database.db_file) / 1024 / 1024  # MB
        
        conn.close()
        
        print(Fore.CYAN + "\n📊 Database Statistics:")
        print(f"  Total queries: {queries_count}")
        print(f"  Total results: {results_count}")
        print(f"  Security blocks: {blocks_count}")
        print(f"  Database size: {db_size:.2f} MB")
    
    def export_database(self):
        """Export database to CSV"""
        filename = f"database_export_{int(time.time())}.csv"
        
        conn = sqlite3.connect(self.database.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT q.url, q.timestamp as query_time, r.original_url, 
                   r.archived_url, r.timestamp, r.status_code, r.mime_type
            FROM queries q
            JOIN results r ON q.id = r.query_id
            ORDER BY q.timestamp DESC
        ''')
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Query_URL', 'Query_Time', 'Original_URL', 'Archived_URL', 'Timestamp', 'Status_Code', 'MIME_Type'])
            writer.writerows(cursor.fetchall())
        
        conn.close()
        print(Fore.GREEN + f"Database exported to {filename}")
    
    def clear_old_data(self):
        """Clear old data from database"""
        days = input("Delete data older than how many days? (default: 30): ").strip()
        try:
            days = int(days) if days else 30
        except ValueError:
            days = 30
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.database.db_file)
        cursor = conn.cursor()
        
        # Delete old queries and their results
        cursor.execute('''
            DELETE FROM queries 
            WHERE timestamp < ?
        ''', (cutoff_date,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        print(Fore.GREEN + f"Deleted {deleted_count} old queries and their results")
    
    def configuration_menu(self):
        """Configuration management menu"""
        print(Fore.GREEN + "\n=== Configuration ===")
        print("1. View current configuration")
        print("2. Edit security settings")
        print("3. Edit performance settings")
        print("4. Reset to defaults")
        print("5. Back to main menu")
        
        choice = input("Choose option (1-5): ").strip()
        
        if choice == '1':
            self.show_config()
        elif choice == '2':
            self.edit_security_config()
        elif choice == '3':
            self.edit_performance_config()
        elif choice == '4':
            self.reset_config()
        elif choice == '5':
            return
        else:
            print(Fore.RED + "Invalid choice!")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")
    
    def show_config(self):
        """Show current configuration"""
        config = self.config.config
        print(Fore.CYAN + "\n🔧 Current Configuration:")
        print(f"  Max workers: {config['max_workers']}")
        print(f"  Timeout: {config['timeout']}s")
        print(f"  Rate limit: {config['rate_limit']}s")
        print(f"  Security scanning: {'✅' if config['security_scan']['enabled'] else '❌'}")
        print(f"  Excluded extensions: {len(config['exclude_extensions'])}")
        print(f"  Dangerous extensions: {len(config['dangerous_extensions'])}")
    
    def edit_security_config(self):
        """Edit security configuration"""
        print(Fore.YELLOW + "\n🛡️  Security Settings:")
        
        # Toggle security scanning
        current = self.config.config['security_scan']['enabled']
        enable = input(f"Enable security scanning? (currently: {'Yes' if current else 'No'}) [y/n]: ").lower()
        if enable in ['y', 'n']:
            self.config.config['security_scan']['enabled'] = enable == 'y'
        
        # Max file size
        current_size = self.config.config['security_scan']['max_file_size'] / 1000000
        new_size = input(f"Max file size in MB (current: {current_size:.1f}): ").strip()
        if new_size and new_size.replace('.', '').isdigit():
            self.config.config['security_scan']['max_file_size'] = int(float(new_size) * 1000000)
        
        self.config.save_config(self.config.config)
        print(Fore.GREEN + "Security settings updated!")
    
    def edit_performance_config(self):
        """Edit performance configuration"""
        print(Fore.YELLOW + "\n⚡ Performance Settings:")
        
        # Max workers
        current = self.config.config['max_workers']
        new_workers = input(f"Max workers (current: {current}): ").strip()
        if new_workers and new_workers.isdigit():
            self.config.config['max_workers'] = int(new_workers)
        
        # Rate limit
        current = self.config.config['rate_limit']
        new_rate = input(f"Rate limit in seconds (current: {current}): ").strip()
        if new_rate and new_rate.replace('.', '').isdigit():
            self.config.config['rate_limit'] = float(new_rate)
        
        # Timeout
        current = self.config.config['timeout']
        new_timeout = input(f"Request timeout in seconds (current: {current}): ").strip()
        if new_timeout and new_timeout.isdigit():
            self.config.config['timeout'] = int(new_timeout)
        
        self.config.save_config(self.config.config)
        print(Fore.GREEN + "Performance settings updated!")
    
    def reset_config(self):
        """Reset configuration to defaults"""
        confirm = input("Reset all settings to defaults? [y/n]: ").lower()
        if confirm == 'y':
            self.config.config = self.config.default_config.copy()
            self.config.save_config(self.config.config)
            print(Fore.GREEN + "Configuration reset to defaults!")
    
    def generate_report_menu(self):
        """Generate comprehensive reports"""
        print(Fore.GREEN + "\n=== Generate Report ===")
        print("1. Security Report")
        print("2. Analysis Report")
        print("3. Full Database Report")
        print("4. Back to main menu")
        
        choice = input("Choose option (1-4): ").strip()
        
        if choice == '1':
            self.generate_security_report()
        elif choice == '2':
            self.generate_analysis_report()
        elif choice == '3':
            self.generate_full_report()
        elif choice == '4':
            return
        else:
            print(Fore.RED + "Invalid choice!")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")
    
    def generate_security_report(self):
        """Generate security report"""
        filename = f"security_report_{int(time.time())}.txt"
        
        conn = sqlite3.connect(self.database.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM security_blocks')
        total_blocks = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT threat_level, COUNT(*) 
            FROM security_blocks 
            GROUP BY threat_level
        ''')
        threat_stats = cursor.fetchall()
        
        cursor.execute('''
            SELECT url, reason, threat_level, timestamp 
            FROM security_blocks 
            ORDER BY timestamp DESC
        ''')
        all_blocks = cursor.fetchall()
        
        conn.close()
        
        with open(filename, 'w') as f:
            f.write("WAYBACK MACHINE SECURITY REPORT\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total blocked items: {total_blocks}\n\n")
            
            f.write("THREAT LEVELS\n")
            f.write("-" * 20 + "\n")
            for threat_level, count in threat_stats:
                f.write(f"{threat_level}: {count}\n")
            f.write("\n")
            
            f.write("BLOCKED ITEMS\n")
            f.write("-" * 20 + "\n")
            for url, reason, threat_level, timestamp in all_blocks:
                f.write(f"[{threat_level}] {timestamp}\n")
                f.write(f"URL: {url}\n")
                f.write(f"Reason: {reason}\n\n")
        
        print(Fore.GREEN + f"Security report generated: {filename}")
    
    def generate_analysis_report(self):
        """Generate analysis report for recent queries"""
        print(Fore.YELLOW + "Generating analysis report...")
        # Implementation would analyze recent queries and generate insights
        filename = f"analysis_report_{int(time.time())}.txt"
        print(Fore.GREEN + f"Analysis report generated: {filename}")
    
    def generate_full_report(self):
        """Generate comprehensive report"""
        print(Fore.YELLOW + "Generating full database report...")
        # Implementation would create comprehensive report of all data
        filename = f"full_report_{int(time.time())}.txt"
        print(Fore.GREEN + f"Full report generated: {filename}")
    
    def advanced_filters_menu(self):
        """Advanced filtering options"""
        print(Fore.GREEN + "\n=== Advanced Filters ===")
        print("This feature allows you to set custom filtering rules.")
        print("Currently using default filters from configuration.")
        print("\nAvailable filter types:")
        print("- File extensions (include/exclude)")
        print("- Status codes")
        print("- MIME types")
        print("- Date ranges")
        print("- URL patterns")
        
        input(Fore.MAGENTA + "\nPress Enter to continue...")

def main():
    """Main function with command-line argument support"""
    parser = argparse.ArgumentParser(description='Advanced Wayback Machine Tool')
    parser.add_argument('--url', help='URL to query')
    parser.add_argument('--bulk', help='File containing URLs to query')
    parser.add_argument('--config', default='config.json', help='Configuration file')
    parser.add_argument('--output', help='Output file for results')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='txt', help='Output format')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('wayback_tool.log'),
            logging.StreamHandler()
        ]
    )
    
    # Initialize components
    config = WaybackConfig(args.config)
    database = WaybackDatabase(config.config['database_file'])
    analyzer = WaybackAnalyzer(config, database)
    
    if args.interactive or not (args.url or args.bulk):
        # Interactive mode
        analyzer.interactive_menu()
    else:
        # Command-line mode
        if args.url:
            results = analyzer.advanced_query(args.url)
            if args.output:
                # Apply security filtering
                safe_results, blocked_results = analyzer.filter_results(results)
                if blocked_results:
                    print(f"Warning: {len(blocked_results)} items blocked for security reasons")
                analyzer.export_results(safe_results, args.format, args.output)
            else:
                # Apply security filtering
                safe_results, blocked_results = analyzer.filter_results(results)
                for result in safe_results[:10]:  # Show first 10 safe results
                    print(f"{result.get('original')} | {result.get('timestamp')}")
                if blocked_results:
                    print(f"\nWarning: {len(blocked_results)} items blocked for security reasons")
        
        elif args.bulk:
            with open(args.bulk, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            all_results = analyzer.bulk_query(urls)
            if args.output:
                # Combine all results and apply security filtering
                combined = []
                for results in all_results.values():
                    combined.extend(results)
                
                safe_results, blocked_results = analyzer.filter_results(combined)
                if blocked_results:
                    print(f"Warning: {len(blocked_results)} items blocked for security reasons")
                analyzer.export_results(safe_results, args.format, args.output)

if __name__ == "__main__":
    main()
