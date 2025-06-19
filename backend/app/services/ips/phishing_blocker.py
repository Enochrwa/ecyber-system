# Advanced Phishing Detection and Blocking System
# This module provides enterprise-grade phishing detection and prevention

import asyncio
import re
import json
import logging
import hashlib
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import aiohttp
import sqlite3
from pathlib import Path
import dns.resolver
import tldextract
import base64
import ssl
import socket

logger = logging.getLogger(__name__)

@dataclass
class PhishingIndicator:
    """Represents a phishing indicator"""
    id: str
    type: str  # url, domain, ip, email, content_pattern
    value: str
    severity: str  # critical, high, medium, low
    confidence: float
    source: str
    description: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class PhishingDetection:
    """Represents a phishing detection result"""
    id: str
    type: str
    target_url: str
    source_ip: str
    severity: str
    confidence: float
    indicators: List[str]
    timestamp: datetime
    blocked: bool = False
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class AdvancedPhishingBlocker:
    """Advanced phishing detection and blocking system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.indicators: Dict[str, PhishingIndicator] = {}
        self.blocked_domains: Set[str] = set()
        self.blocked_urls: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.whitelist_domains: Set[str] = set()
        self.db_path = self.config.get('phishing_db_path', 'phishing.db')
        self.update_interval = self.config.get('update_interval', 1800)  # 30 minutes
        self.lock = asyncio.Lock()
        
        # Phishing detection patterns
        self.suspicious_patterns = [
            r'(?i)(verify|update|confirm|secure|suspend|urgent|immediate|action\s+required)',
            r'(?i)(click\s+here|act\s+now|limited\s+time|expires\s+soon)',
            r'(?i)(paypal|amazon|microsoft|apple|google|facebook|twitter|instagram)',
            r'(?i)(bank|credit|debit|account|payment|billing|invoice)',
            r'(?i)(login|signin|password|username|credentials)',
            r'(?i)(phishing|scam|fraud|malicious|suspicious)'
        ]
        
        # URL shortener services
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'short.link', 'ow.ly', 't.co',
            'goo.gl', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc'
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            '.stream', '.science', '.racing', '.review'
        }
        
        # Statistics
        self.stats = {
            'total_detections': 0,
            'blocked_attempts': 0,
            'false_positives': 0,
            'detections_by_type': {},
            'last_update': None
        }
        
        # Initialize components
        self._init_database()
        self.update_task = None
        
        # Load default whitelisted domains
        self.whitelist_domains.update([
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org'
        ])
    
    def _init_database(self):
        """Initialize SQLite database for phishing data storage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Indicators table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS phishing_indicators (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    severity TEXT,
                    confidence REAL,
                    source TEXT,
                    description TEXT,
                    created_at TEXT,
                    expires_at TEXT,
                    metadata TEXT
                )
            ''')
            
            # Detections table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS phishing_detections (
                    id TEXT PRIMARY KEY,
                    type TEXT,
                    target_url TEXT,
                    source_ip TEXT,
                    severity TEXT,
                    confidence REAL,
                    indicators TEXT,
                    timestamp TEXT,
                    blocked BOOLEAN,
                    metadata TEXT
                )
            ''')
            
            # Whitelist table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS whitelist (
                    domain TEXT PRIMARY KEY,
                    added_at TEXT,
                    reason TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Phishing database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize phishing database: {e}")
    
    async def start(self):
        """Start the phishing blocker service"""
        await self._load_indicators()
        await self._load_whitelist()
        
        # Start background update task
        self.update_task = asyncio.create_task(self._update_indicators_periodically())
        logger.info("Advanced phishing blocker started")
    
    async def stop(self):
        """Stop the phishing blocker service"""
        if self.update_task:
            self.update_task.cancel()
        logger.info("Advanced phishing blocker stopped")
    
    async def _load_indicators(self):
        """Load phishing indicators from database and external sources"""
        async with self.lock:
            # Load from database
            await self._load_from_database()
            
            # Load from external threat feeds
            await self._load_from_threat_feeds()
            
            logger.info(f"Loaded {len(self.indicators)} phishing indicators")
    
    async def _load_from_database(self):
        """Load indicators from local database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM phishing_indicators')
            rows = cursor.fetchall()
            
            for row in rows:
                (id, type, value, severity, confidence, source, description,
                 created_at, expires_at, metadata) = row
                
                # Check if indicator has expired
                if expires_at:
                    expires_dt = datetime.fromisoformat(expires_at)
                    if datetime.now() > expires_dt:
                        cursor.execute('DELETE FROM phishing_indicators WHERE id = ?', (id,))
                        continue
                
                indicator = PhishingIndicator(
                    id=id,
                    type=type,
                    value=value,
                    severity=severity,
                    confidence=confidence,
                    source=source,
                    description=description,
                    created_at=datetime.fromisoformat(created_at),
                    expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
                    metadata=json.loads(metadata) if metadata else {}
                )
                
                self.indicators[id] = indicator
                
                # Add to appropriate blocking sets
                if type == 'domain':
                    self.blocked_domains.add(value)
                elif type == 'url':
                    self.blocked_urls.add(value)
                elif type == 'ip':
                    self.blocked_ips.add(value)
            
            conn.commit()
            conn.close()
            logger.info(f"Loaded {len(rows)} indicators from database")
        except Exception as e:
            logger.error(f"Failed to load indicators from database: {e}")
    
    async def _load_whitelist(self):
        """Load whitelist from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT domain FROM whitelist')
            rows = cursor.fetchall()
            
            for row in rows:
                self.whitelist_domains.add(row[0])
            
            conn.close()
            logger.info(f"Loaded {len(rows)} whitelisted domains")
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")
    
    async def _load_from_threat_feeds(self):
        """Load indicators from external threat feeds"""
        feeds = self.config.get('threat_feeds', [])
        
        for feed in feeds:
            try:
                await self._load_from_feed(feed)
            except Exception as e:
                logger.error(f"Failed to load from feed {feed}: {e}")
    
    async def _load_from_feed(self, feed: Dict[str, Any]):
        """Load indicators from a specific threat feed"""
        try:
            feed_url = feed.get('url')
            feed_type = feed.get('type', 'json')
            
            async with aiohttp.ClientSession() as session:
                async with session.get(feed_url) as response:
                    if response.status == 200:
                        if feed_type == 'json':
                            data = await response.json()
                            await self._process_json_feed(data, feed.get('source', 'external'))
                        elif feed_type == 'text':
                            text = await response.text()
                            await self._process_text_feed(text, feed.get('source', 'external'))
                        
                        logger.info(f"Loaded indicators from feed: {feed_url}")
        except Exception as e:
            logger.error(f"Failed to load from feed {feed}: {e}")
    
    async def _process_json_feed(self, data: Dict, source: str):
        """Process JSON threat feed"""
        indicators = data.get('indicators', [])
        
        for indicator_data in indicators:
            indicator = PhishingIndicator(
                id=f"{source}_{hashlib.md5(indicator_data['value'].encode()).hexdigest()[:8]}",
                type=indicator_data.get('type', 'domain'),
                value=indicator_data['value'],
                severity=indicator_data.get('severity', 'medium'),
                confidence=indicator_data.get('confidence', 0.8),
                source=source,
                description=indicator_data.get('description', 'External threat feed'),
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=7)  # Default 7 days
            )
            
            self.indicators[indicator.id] = indicator
            await self._save_indicator_to_db(indicator)
    
    async def _process_text_feed(self, text: str, source: str):
        """Process text-based threat feed"""
        lines = text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Determine type based on content
                if self._is_ip_address(line):
                    indicator_type = 'ip'
                elif self._is_url(line):
                    indicator_type = 'url'
                else:
                    indicator_type = 'domain'
                
                indicator = PhishingIndicator(
                    id=f"{source}_{hashlib.md5(line.encode()).hexdigest()[:8]}",
                    type=indicator_type,
                    value=line,
                    severity='medium',
                    confidence=0.7,
                    source=source,
                    description='External threat feed',
                    created_at=datetime.now(),
                    expires_at=datetime.now() + timedelta(days=7)
                )
                
                self.indicators[indicator.id] = indicator
                await self._save_indicator_to_db(indicator)
    
    async def check_url(self, url: str, source_ip: str = None) -> Optional[PhishingDetection]:
        """Check if URL is phishing"""
        try:
            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check whitelist first
            if self._is_whitelisted(domain):
                return None
            
            indicators_found = []
            max_confidence = 0.0
            max_severity = 'low'
            
            # Check against known indicators
            url_lower = url.lower()
            
            # Direct URL match
            if url_lower in self.blocked_urls:
                indicators_found.append('blocked_url')
                max_confidence = max(max_confidence, 0.9)
                max_severity = 'high'
            
            # Domain match
            if domain in self.blocked_domains:
                indicators_found.append('blocked_domain')
                max_confidence = max(max_confidence, 0.8)
                max_severity = 'high'
            
            # IP address check
            try:
                ip = socket.gethostbyname(domain)
                if ip in self.blocked_ips:
                    indicators_found.append('blocked_ip')
                    max_confidence = max(max_confidence, 0.7)
                    max_severity = 'medium'
            except:
                pass
            
            # Suspicious patterns in URL
            for pattern in self.suspicious_patterns:
                if re.search(pattern, url_lower):
                    indicators_found.append(f'suspicious_pattern_{pattern[:20]}')
                    max_confidence = max(max_confidence, 0.6)
                    max_severity = 'medium'
            
            # URL shortener check
            if domain in self.url_shorteners:
                indicators_found.append('url_shortener')
                max_confidence = max(max_confidence, 0.5)
                max_severity = 'medium'
                
                # Try to expand shortened URL
                expanded_url = await self._expand_shortened_url(url)
                if expanded_url and expanded_url != url:
                    expanded_check = await self.check_url(expanded_url, source_ip)
                    if expanded_check:
                        return expanded_check
            
            # Suspicious TLD check
            extracted = tldextract.extract(domain)
            if extracted.suffix in self.suspicious_tlds:
                indicators_found.append('suspicious_tld')
                max_confidence = max(max_confidence, 0.4)
                max_severity = 'medium'
            
            # Domain analysis
            domain_analysis = await self._analyze_domain(domain)
            if domain_analysis['suspicious']:
                indicators_found.extend(domain_analysis['indicators'])
                max_confidence = max(max_confidence, domain_analysis['confidence'])
                max_severity = domain_analysis['severity']
            
            # Content analysis (if enabled)
            if self.config.get('content_analysis_enabled', True):
                content_analysis = await self._analyze_url_content(url)
                if content_analysis['suspicious']:
                    indicators_found.extend(content_analysis['indicators'])
                    max_confidence = max(max_confidence, content_analysis['confidence'])
                    max_severity = content_analysis['severity']
            
            # If any indicators found, create detection
            if indicators_found:
                detection = PhishingDetection(
                    id=hashlib.md5(f"{url}_{datetime.now().isoformat()}".encode()).hexdigest(),
                    type='url_analysis',
                    target_url=url,
                    source_ip=source_ip or 'unknown',
                    severity=max_severity,
                    confidence=max_confidence,
                    indicators=indicators_found,
                    timestamp=datetime.now(),
                    blocked=max_confidence >= self.config.get('block_threshold', 0.7),
                    metadata={
                        'domain': domain,
                        'parsed_url': {
                            'scheme': parsed_url.scheme,
                            'netloc': parsed_url.netloc,
                            'path': parsed_url.path,
                            'query': parsed_url.query
                        }
                    }
                )
                
                await self._log_detection(detection)
                
                # Update statistics
                self.stats['total_detections'] += 1
                if detection.blocked:
                    self.stats['blocked_attempts'] += 1
                
                if detection.type not in self.stats['detections_by_type']:
                    self.stats['detections_by_type'][detection.type] = 0
                self.stats['detections_by_type'][detection.type] += 1
                
                return detection
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking URL {url}: {e}")
            return None
    
    async def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain for suspicious characteristics"""
        suspicious = False
        indicators = []
        confidence = 0.0
        severity = 'low'
        
        try:
            # Domain age check (requires WHOIS, simplified here)
            # In production, integrate with WHOIS API
            
            # Subdomain analysis
            parts = domain.split('.')
            if len(parts) > 3:  # Multiple subdomains
                indicators.append('multiple_subdomains')
                confidence = max(confidence, 0.3)
            
            # Suspicious keywords in domain
            domain_lower = domain.lower()
            suspicious_keywords = [
                'secure', 'verify', 'update', 'confirm', 'account',
                'login', 'signin', 'bank', 'paypal', 'amazon'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in domain_lower:
                    indicators.append(f'suspicious_keyword_{keyword}')
                    confidence = max(confidence, 0.4)
                    severity = 'medium'
            
            # Homograph attack detection
            if self._contains_homograph(domain):
                indicators.append('homograph_attack')
                confidence = max(confidence, 0.8)
                severity = 'high'
            
            # DNS analysis
            dns_analysis = await self._analyze_dns(domain)
            if dns_analysis['suspicious']:
                indicators.extend(dns_analysis['indicators'])
                confidence = max(confidence, dns_analysis['confidence'])
                severity = dns_analysis['severity']
            
            suspicious = len(indicators) > 0
            
        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {e}")
        
        return {
            'suspicious': suspicious,
            'indicators': indicators,
            'confidence': confidence,
            'severity': severity
        }
    
    async def _analyze_dns(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records for suspicious patterns"""
        suspicious = False
        indicators = []
        confidence = 0.0
        severity = 'low'
        
        try:
            # Check for fast-flux DNS (multiple A records)
            a_records = dns.resolver.resolve(domain, 'A')
            if len(a_records) > 5:
                indicators.append('fast_flux_dns')
                confidence = max(confidence, 0.6)
                severity = 'medium'
            
            # Check for suspicious IP ranges
            for record in a_records:
                ip = str(record)
                if self._is_suspicious_ip(ip):
                    indicators.append(f'suspicious_ip_{ip}')
                    confidence = max(confidence, 0.7)
                    severity = 'high'
            
            suspicious = len(indicators) > 0
            
        except Exception as e:
            logger.debug(f"DNS analysis failed for {domain}: {e}")
        
        return {
            'suspicious': suspicious,
            'indicators': indicators,
            'confidence': confidence,
            'severity': severity
        }
    
    async def _analyze_url_content(self, url: str) -> Dict[str, Any]:
        """Analyze URL content for phishing indicators"""
        suspicious = False
        indicators = []
        confidence = 0.0
        severity = 'low'
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for suspicious content patterns
                        for pattern in self.suspicious_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                indicators.append(f'content_pattern_{pattern[:20]}')
                                confidence = max(confidence, 0.5)
                                severity = 'medium'
                        
                        # Check for credential harvesting forms
                        if self._has_credential_forms(content):
                            indicators.append('credential_harvesting_form')
                            confidence = max(confidence, 0.8)
                            severity = 'high'
                        
                        # Check for brand impersonation
                        brand_analysis = self._analyze_brand_impersonation(content)
                        if brand_analysis['suspicious']:
                            indicators.extend(brand_analysis['indicators'])
                            confidence = max(confidence, brand_analysis['confidence'])
                            severity = brand_analysis['severity']
                        
                        suspicious = len(indicators) > 0
        
        except Exception as e:
            logger.debug(f"Content analysis failed for {url}: {e}")
        
        return {
            'suspicious': suspicious,
            'indicators': indicators,
            'confidence': confidence,
            'severity': severity
        }
    
    def _has_credential_forms(self, content: str) -> bool:
        """Check if content has credential harvesting forms"""
        # Look for forms with password fields
        password_pattern = r'<input[^>]*type=["\']password["\'][^>]*>'
        login_pattern = r'<input[^>]*name=["\'](?:username|email|login)["\'][^>]*>'
        
        return bool(re.search(password_pattern, content, re.IGNORECASE) and 
                   re.search(login_pattern, content, re.IGNORECASE))
    
    def _analyze_brand_impersonation(self, content: str) -> Dict[str, Any]:
        """Analyze content for brand impersonation"""
        suspicious = False
        indicators = []
        confidence = 0.0
        severity = 'low'
        
        # Common impersonated brands
        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook']
        
        content_lower = content.lower()
        for brand in brands:
            if brand in content_lower:
                # Check if it's likely impersonation
                if self._is_likely_impersonation(content, brand):
                    indicators.append(f'brand_impersonation_{brand}')
                    confidence = max(confidence, 0.7)
                    severity = 'high'
                    suspicious = True
        
        return {
            'suspicious': suspicious,
            'indicators': indicators,
            'confidence': confidence,
            'severity': severity
        }
    
    def _is_likely_impersonation(self, content: str, brand: str) -> bool:
        """Check if content is likely impersonating a brand"""
        # Simplified check - in production, use more sophisticated analysis
        urgent_words = ['urgent', 'immediate', 'suspend', 'verify', 'update']
        content_lower = content.lower()
        
        return any(word in content_lower for word in urgent_words)
    
    def _contains_homograph(self, domain: str) -> bool:
        """Check for homograph attacks in domain"""
        # Simplified homograph detection
        # In production, use comprehensive Unicode confusable detection
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic lookalikes
        return any(char in domain for char in suspicious_chars)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is in suspicious ranges"""
        # Check against known malicious IP ranges
        # This is simplified - in production, use threat intelligence feeds
        suspicious_ranges = [
            '192.168.',  # Private ranges used maliciously
            '10.',
            '172.16.'
        ]
        
        return any(ip.startswith(range_prefix) for range_prefix in suspicious_ranges)
    
    def _is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted"""
        # Check exact match and parent domains
        domain_parts = domain.split('.')
        
        for i in range(len(domain_parts)):
            check_domain = '.'.join(domain_parts[i:])
            if check_domain in self.whitelist_domains:
                return True
        
        return False
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if value is an IP address"""
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            return False
    
    def _is_url(self, value: str) -> bool:
        """Check if value is a URL"""
        return value.startswith(('http://', 'https://'))
    
    async def _expand_shortened_url(self, url: str) -> Optional[str]:
        """Expand shortened URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, allow_redirects=True, 
                                      timeout=aiohttp.ClientTimeout(total=5)) as response:
                    return str(response.url)
        except Exception as e:
            logger.debug(f"Failed to expand URL {url}: {e}")
            return None
    
    async def _save_indicator_to_db(self, indicator: PhishingIndicator):
        """Save indicator to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO phishing_indicators 
                (id, type, value, severity, confidence, source, description,
                 created_at, expires_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                indicator.id,
                indicator.type,
                indicator.value,
                indicator.severity,
                indicator.confidence,
                indicator.source,
                indicator.description,
                indicator.created_at.isoformat(),
                indicator.expires_at.isoformat() if indicator.expires_at else None,
                json.dumps(indicator.metadata)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save indicator to database: {e}")
    
    async def _log_detection(self, detection: PhishingDetection):
        """Log detection to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO phishing_detections 
                (id, type, target_url, source_ip, severity, confidence,
                 indicators, timestamp, blocked, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection.id,
                detection.type,
                detection.target_url,
                detection.source_ip,
                detection.severity,
                detection.confidence,
                json.dumps(detection.indicators),
                detection.timestamp.isoformat(),
                detection.blocked,
                json.dumps(detection.metadata)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log detection: {e}")
    
    async def _update_indicators_periodically(self):
        """Periodically update indicators from external sources"""
        while True:
            try:
                await asyncio.sleep(self.update_interval)
                logger.info("Updating phishing indicators...")
                
                await self._load_from_threat_feeds()
                self.stats['last_update'] = datetime.now().isoformat()
                
                logger.info("Phishing indicators update completed")
                
            except Exception as e:
                logger.error(f"Error during indicator update: {e}")
    
    async def add_to_whitelist(self, domain: str, reason: str = "Manual addition") -> bool:
        """Add domain to whitelist"""
        try:
            async with self.lock:
                self.whitelist_domains.add(domain)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO whitelist (domain, added_at, reason)
                    VALUES (?, ?, ?)
                ''', (domain, datetime.now().isoformat(), reason))
                conn.commit()
                conn.close()
                
                logger.info(f"Added {domain} to whitelist")
                return True
        except Exception as e:
            logger.error(f"Failed to add {domain} to whitelist: {e}")
            return False
    
    async def remove_from_whitelist(self, domain: str) -> bool:
        """Remove domain from whitelist"""
        try:
            async with self.lock:
                self.whitelist_domains.discard(domain)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM whitelist WHERE domain = ?', (domain,))
                conn.commit()
                conn.close()
                
                logger.info(f"Removed {domain} from whitelist")
                return True
        except Exception as e:
            logger.error(f"Failed to remove {domain} from whitelist: {e}")
            return False
    
    def get_stats(self) -> Dict:
        """Get phishing blocker statistics"""
        return {
            'total_indicators': len(self.indicators),
            'blocked_domains': len(self.blocked_domains),
            'blocked_urls': len(self.blocked_urls),
            'blocked_ips': len(self.blocked_ips),
            'whitelisted_domains': len(self.whitelist_domains),
            'detection_stats': self.stats
        }
    
    def get_recent_detections(self, limit: int = 100) -> List[Dict]:
        """Get recent phishing detections"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM phishing_detections 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            conn.close()
            
            detections = []
            for row in rows:
                detection_dict = {
                    'id': row[0],
                    'type': row[1],
                    'target_url': row[2],
                    'source_ip': row[3],
                    'severity': row[4],
                    'confidence': row[5],
                    'indicators': json.loads(row[6]),
                    'timestamp': row[7],
                    'blocked': bool(row[8]),
                    'metadata': json.loads(row[9]) if row[9] else {}
                }
                detections.append(detection_dict)
            
            return detections
        except Exception as e:
            logger.error(f"Failed to get recent detections: {e}")
            return []

