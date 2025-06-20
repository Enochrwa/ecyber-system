# Advanced Signature-Based Detection System
# This module provides enterprise-grade signature-based threat detection

import asyncio
import re
import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import aiohttp
import sqlite3
from pathlib import Path
import os
import yaml
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

@dataclass
class ThreatSignature:
    """Represents a threat detection signature"""
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    category: str  # malware, exploit, trojan, etc.
    pattern: str
    pattern_type: str  # regex, hex, string, yara
    protocol: str  # tcp, udp, http, https, any
    source_port: Optional[str] = None
    dest_port: Optional[str] = None
    direction: str = "any"  # inbound, outbound, any
    enabled: bool = True
    created_at: datetime = None
    updated_at: datetime = None
    author: str = "system"
    ref_links: List[str] = None
    mitre_attack: Dict[str, str] = None
    cve_ids: List[str] = None
    confidence: float = 1.0
    false_positive_rate: float = 0.0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if self.ref_links is None:
            self.ref_links = []
        if self.mitre_attack is None:
            self.mitre_attack = {}
        if self.cve_ids is None:
            self.cve_ids = []

@dataclass
class SignatureMatch:
    """Represents a signature match result"""
    signature_id: str
    signature_name: str
    severity: str
    category: str
    confidence: float
    matched_content: str
    source_ip: str
    dest_ip: str
    protocol: str
    timestamp: datetime
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class AdvancedSignatureEngine:
    """Advanced signature-based detection engine"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.signatures: Dict[str, ThreatSignature] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.yara_rules: Dict[str, Any] = {}
        data_dir = Path(__file__).resolve().parent.parent.parent.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = data_dir / "signatures.db"
        self.signature_sources = self.config.get('signature_sources', [])
        self.update_interval = self.config.get('update_interval', 3600)  # 1 hour
        self.lock = asyncio.Lock()
        
        # Performance tracking
        self.match_stats = {
            'total_matches': 0,
            'matches_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'matches_by_category': {},
            'false_positives': 0,
            'last_update': None
        }
        
        # Initialize components
        self._init_database()
        self.update_task = None
        
    def _init_database(self):
        """Initialize SQLite database for signature storage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Signatures table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    category TEXT,
                    pattern TEXT,
                    pattern_type TEXT,
                    protocol TEXT,
                    source_port TEXT,
                    dest_port TEXT,
                    direction TEXT,
                    enabled BOOLEAN,
                    created_at TEXT,
                    updated_at TEXT,
                    author TEXT,
                    ref_links TEXT,
                    mitre_attack TEXT,
                    cve_ids TEXT,
                    confidence REAL,
                    false_positive_rate REAL
                )
            ''')
            
            # Matches table for tracking detections
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signature_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id TEXT,
                    signature_name TEXT,
                    severity TEXT,
                    category TEXT,
                    confidence REAL,
                    matched_content TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    protocol TEXT,
                    timestamp TEXT,
                    metadata TEXT,
                    FOREIGN KEY (signature_id) REFERENCES signatures (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Signature database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize signature database: {e}")
    
    async def start(self):
        """Start the signature engine"""
        await self._load_signatures()
        await self._compile_patterns()
        
        # Start background update task
        self.update_task = asyncio.create_task(self._update_signatures_periodically())
        logger.info("Advanced signature engine started")
    
    async def stop(self):
        """Stop the signature engine"""
        if self.update_task:
            self.update_task.cancel()
        logger.info("Advanced signature engine stopped")
    
    async def _load_signatures(self):
        """Load signatures from database and external sources"""
        async with self.lock:
            # Load from database
            await self._load_from_database()
            
            # Load from external sources
            for source in self.signature_sources:
                await self._load_from_source(source)
            
            logger.info(f"Loaded {len(self.signatures)} signatures")
    
    async def _load_from_database(self):
        """Load signatures from local database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT id, name, description, severity, category, pattern, pattern_type, protocol, source_port, dest_port, direction, enabled, created_at, updated_at, author, ref_links, mitre_attack, cve_ids, confidence, false_positive_rate FROM signatures WHERE enabled = 1')
            rows = cursor.fetchall()
            
            for row in rows:
                (id, name, description, severity, category, pattern, pattern_type,
                 protocol, source_port, dest_port, direction, enabled, created_at,
                 updated_at, author, ref_links, mitre_attack, cve_ids, confidence,
                 false_positive_rate) = row
                
                signature = ThreatSignature(
                    id=id,
                    name=name,
                    description=description,
                    severity=severity,
                    category=category,
                    pattern=pattern,
                    pattern_type=pattern_type,
                    protocol=protocol,
                    source_port=source_port,
                    dest_port=dest_port,
                    direction=direction,
                    enabled=bool(enabled),
                    created_at=datetime.fromisoformat(created_at),
                    updated_at=datetime.fromisoformat(updated_at),
                    author=author,
                    ref_links=json.loads(ref_links) if ref_links else [],
                    mitre_attack=json.loads(mitre_attack) if mitre_attack else {},
                    cve_ids=json.loads(cve_ids) if cve_ids else [],
                    confidence=confidence,
                    false_positive_rate=false_positive_rate
                )
                
                self.signatures[id] = signature
            
            conn.close()
            logger.info(f"Loaded {len(rows)} signatures from database")
        except Exception as e:
            logger.error(f"Failed to load signatures from database: {e}")
    
    async def _load_from_source(self, source: Dict[str, Any]):
        """Load signatures from external source"""
        try:
            source_type = source.get('type')
            source_url = source.get('url')
            
            if source_type == 'snort':
                await self._load_snort_rules(source_url)
            elif source_type == 'suricata':
                await self._load_suricata_rules(source_url)
            elif source_type == 'yara':
                await self._load_yara_rules(source_url)
            elif source_type == 'custom_json':
                await self._load_custom_json(source_url)
            else:
                logger.warning(f"Unknown signature source type: {source_type}")
                
        except Exception as e:
            logger.error(f"Failed to load from source {source}: {e}")
    
    async def _load_snort_rules(self, url: str):
        """Load Snort rules and convert to internal format"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        rules = self._parse_snort_rules(content)
                        
                        for rule in rules:
                            signature = self._convert_snort_to_signature(rule)
                            if signature:
                                self.signatures[signature.id] = signature
                                await self._save_signature_to_db(signature)
                        
                        logger.info(f"Loaded {len(rules)} Snort rules from {url}")
        except Exception as e:
            logger.error(f"Failed to load Snort rules from {url}: {e}")
    
    async def _load_suricata_rules(self, url: str):
        """Load Suricata rules and convert to internal format"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        rules = self._parse_suricata_rules(content)
                        
                        for rule in rules:
                            signature = self._convert_suricata_to_signature(rule)
                            if signature:
                                self.signatures[signature.id] = signature
                                await self._save_signature_to_db(signature)
                        
                        logger.info(f"Loaded {len(rules)} Suricata rules from {url}")
        except Exception as e:
            logger.error(f"Failed to load Suricata rules from {url}: {e}")
    
    async def _load_yara_rules(self, url: str):
        """Load YARA rules for malware detection"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Store YARA rules separately for specialized processing
                        self.yara_rules[url] = content
                        logger.info(f"Loaded YARA rules from {url}")
        except Exception as e:
            logger.error(f"Failed to load YARA rules from {url}: {e}")
    
    async def _load_custom_json(self, url: str):
        """Load custom JSON signature format"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        signatures = data.get('signatures', [])
                        
                        for sig_data in signatures:
                            signature = ThreatSignature(**sig_data)
                            self.signatures[signature.id] = signature
                            await self._save_signature_to_db(signature)
                        
                        logger.info(f"Loaded {len(signatures)} custom signatures from {url}")
        except Exception as e:
            logger.error(f"Failed to load custom signatures from {url}: {e}")
    
    def _parse_snort_rules(self, content: str) -> List[Dict]:
        """Parse Snort rule format"""
        rules = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                rule = self._parse_snort_rule_line(line)
                if rule:
                    rules.append(rule)
        return rules
    
    def _parse_snort_rule_line(self, line: str) -> Optional[Dict]:
        """Parse individual Snort rule line"""
        try:
            # Basic Snort rule parsing
            parts = line.split(' ', 6)
            if len(parts) < 7:
                return None
            
            action = parts[0]
            protocol = parts[1]
            src_ip = parts[2]
            src_port = parts[3]
            direction = parts[4]
            dst_ip = parts[5]
            dst_port = parts[6].split(' ')[0]
            options = ' '.join(parts[6].split(' ')[1:])
            
            # Extract content and metadata from options
            content_match = re.search(r'content:"([^"]+)"', options)
            msg_match = re.search(r'msg:"([^"]+)"', options)
            sid_match = re.search(r'sid:(\d+)', options)
            
            return {
                'action': action,
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'direction': direction,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'content': content_match.group(1) if content_match else '',
                'msg': msg_match.group(1) if msg_match else '',
                'sid': sid_match.group(1) if sid_match else '',
                'options': options
            }
        except Exception as e:
            logger.error(f"Failed to parse Snort rule: {line}, Error: {e}")
            return None
    
    def _parse_suricata_rules(self, content: str) -> List[Dict]:
        """Parse Suricata rule format (similar to Snort)"""
        return self._parse_snort_rules(content)  # Suricata uses similar format
    
    def _convert_snort_to_signature(self, rule: Dict) -> Optional[ThreatSignature]:
        """Convert Snort rule to internal signature format"""
        try:
            signature_id = f"snort_{rule.get('sid', hashlib.md5(str(rule).encode()).hexdigest()[:8])}"
            
            return ThreatSignature(
                id=signature_id,
                name=rule.get('msg', 'Snort Rule'),
                description=rule.get('msg', 'Converted from Snort rule'),
                severity=self._determine_severity_from_snort(rule),
                category=self._determine_category_from_snort(rule),
                pattern=rule.get('content', ''),
                pattern_type='string',
                protocol=rule.get('protocol', 'any'),
                source_port=rule.get('src_port') if rule.get('src_port') != 'any' else None,
                dest_port=rule.get('dst_port') if rule.get('dst_port') != 'any' else None,
                direction=self._convert_snort_direction(rule.get('direction', '->')),
                enabled=True,
                author='snort',
                confidence=0.8
            )
        except Exception as e:
            logger.error(f"Failed to convert Snort rule: {e}")
            return None
    
    def _convert_suricata_to_signature(self, rule: Dict) -> Optional[ThreatSignature]:
        """Convert Suricata rule to internal signature format"""
        return self._convert_snort_to_signature(rule)  # Similar format
    
    def _determine_severity_from_snort(self, rule: Dict) -> str:
        """Determine severity from Snort rule content"""
        msg = rule.get('msg', '').lower()
        if any(word in msg for word in ['critical', 'exploit', 'backdoor', 'trojan']):
            return 'critical'
        elif any(word in msg for word in ['attack', 'malware', 'virus']):
            return 'high'
        elif any(word in msg for word in ['suspicious', 'scan', 'probe']):
            return 'medium'
        else:
            return 'low'
    
    def _determine_category_from_snort(self, rule: Dict) -> str:
        """Determine category from Snort rule content"""
        msg = rule.get('msg', '').lower()
        if 'trojan' in msg:
            return 'trojan'
        elif 'malware' in msg:
            return 'malware'
        elif 'exploit' in msg:
            return 'exploit'
        elif 'scan' in msg:
            return 'scan'
        elif 'dos' in msg:
            return 'dos'
        else:
            return 'unknown'
    
    def _convert_snort_direction(self, direction: str) -> str:
        """Convert Snort direction to internal format"""
        if direction == '->':
            return 'outbound'
        elif direction == '<-':
            return 'inbound'
        else:
            return 'any'
    
    async def _compile_patterns(self):
        """Compile regex patterns for performance"""
        async with self.lock:
            self.compiled_patterns.clear()
            
            for sig_id, signature in self.signatures.items():
                if signature.pattern_type == 'regex':
                    try:
                        self.compiled_patterns[sig_id] = re.compile(
                            signature.pattern, 
                            re.IGNORECASE | re.MULTILINE
                        )
                    except re.error as e:
                        logger.error(f"Failed to compile regex for signature {sig_id}: {e}")
            
            logger.info(f"Compiled {len(self.compiled_patterns)} regex patterns")
    
    async def detect_threats(self, packet_data: bytes, source_ip: str, dest_ip: str, 
                           protocol: str) -> List[SignatureMatch]:
        """Detect threats in packet data using signatures"""
        matches = []
        
        try:
            # Convert packet data to string for pattern matching
            packet_str = packet_data.decode('utf-8', errors='ignore')
            packet_hex = packet_data.hex()
            
            for sig_id, signature in self.signatures.items():
                if not signature.enabled:
                    continue
                
                # Protocol filtering
                if signature.protocol != 'any' and signature.protocol.lower() != protocol.lower():
                    continue
                
                # Pattern matching based on type
                match_found = False
                matched_content = ""
                
                if signature.pattern_type == 'string':
                    if signature.pattern.lower() in packet_str.lower():
                        match_found = True
                        matched_content = signature.pattern
                
                elif signature.pattern_type == 'regex':
                    compiled_pattern = self.compiled_patterns.get(sig_id)
                    if compiled_pattern:
                        match = compiled_pattern.search(packet_str)
                        if match:
                            match_found = True
                            matched_content = match.group(0)
                
                elif signature.pattern_type == 'hex':
                    hex_pattern = signature.pattern.replace(' ', '').lower()
                    if hex_pattern in packet_hex:
                        match_found = True
                        matched_content = hex_pattern
                
                if match_found:
                    signature_match = SignatureMatch(
                        signature_id=signature.id,
                        signature_name=signature.name,
                        severity=signature.severity,
                        category=signature.category,
                        confidence=signature.confidence,
                        matched_content=matched_content,
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        protocol=protocol,
                        timestamp=datetime.now(),
                        metadata={
                            'mitre_attack': signature.mitre_attack,
                            'cve_ids': signature.cve_ids,
                            'references': signature.ref_links
                        }
                    )
                    
                    matches.append(signature_match)
                    await self._log_match(signature_match)
                    
                    # Update statistics
                    self.match_stats['total_matches'] += 1
                    self.match_stats['matches_by_severity'][signature.severity] += 1
                    if signature.category not in self.match_stats['matches_by_category']:
                        self.match_stats['matches_by_category'][signature.category] = 0
                    self.match_stats['matches_by_category'][signature.category] += 1
        
        except Exception as e:
            logger.error(f"Error during threat detection: {e}")
        
        return matches
    
    async def _log_match(self, match: SignatureMatch):
        """Log signature match to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO signature_matches 
                (signature_id, signature_name, severity, category, confidence, 
                 matched_content, source_ip, dest_ip, protocol, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                match.signature_id,
                match.signature_name,
                match.severity,
                match.category,
                match.confidence,
                match.matched_content,
                match.source_ip,
                match.dest_ip,
                match.protocol,
                match.timestamp.isoformat(),
                json.dumps(match.metadata)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log signature match: {e}")
    
    async def _save_signature_to_db(self, signature: ThreatSignature):
        """Save signature to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO signatures 
                (id, name, description, severity, category, pattern, pattern_type,
                 protocol, source_port, dest_port, direction, enabled, created_at,
                 updated_at, author, ref_links, mitre_attack, cve_ids, confidence,
                 false_positive_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                signature.id,
                signature.name,
                signature.description,
                signature.severity,
                signature.category,
                signature.pattern,
                signature.pattern_type,
                signature.protocol,
                signature.source_port,
                signature.dest_port,
                signature.direction,
                signature.enabled,
                signature.created_at.isoformat(),
                signature.updated_at.isoformat(),
                signature.author,
                json.dumps(signature.ref_links),
                json.dumps(signature.mitre_attack),
                json.dumps(signature.cve_ids),
                signature.confidence,
                signature.false_positive_rate
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save signature to database: {e}")
    
    async def _update_signatures_periodically(self):
        """Periodically update signatures from external sources"""
        while True:
            try:
                await asyncio.sleep(self.update_interval)
                logger.info("Updating signatures from external sources...")
                
                for source in self.signature_sources:
                    await self._load_from_source(source)
                
                await self._compile_patterns()
                self.match_stats['last_update'] = datetime.now().isoformat()
                
                logger.info("Signature update completed")
                
            except Exception as e:
                logger.error(f"Error during signature update: {e}")
    
    async def add_custom_signature(self, signature: ThreatSignature) -> bool:
        """Add custom signature"""
        try:
            async with self.lock:
                self.signatures[signature.id] = signature
                await self._save_signature_to_db(signature)
                
                # Compile pattern if regex
                if signature.pattern_type == 'regex':
                    try:
                        self.compiled_patterns[signature.id] = re.compile(
                            signature.pattern, 
                            re.IGNORECASE | re.MULTILINE
                        )
                    except re.error as e:
                        logger.error(f"Failed to compile regex for custom signature {signature.id}: {e}")
                        return False
                
                logger.info(f"Added custom signature: {signature.id}")
                return True
        except Exception as e:
            logger.error(f"Failed to add custom signature: {e}")
            return False
    
    async def disable_signature(self, signature_id: str) -> bool:
        """Disable a signature"""
        try:
            if signature_id in self.signatures:
                self.signatures[signature_id].enabled = False
                await self._save_signature_to_db(self.signatures[signature_id])
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to disable signature {signature_id}: {e}")
            return False
    
    def get_signature_stats(self) -> Dict:
        """Get signature engine statistics"""
        return {
            'total_signatures': len(self.signatures),
            'enabled_signatures': len([s for s in self.signatures.values() if s.enabled]),
            'compiled_patterns': len(self.compiled_patterns),
            'match_stats': self.match_stats,
            'signature_categories': list(set(s.category for s in self.signatures.values())),
            'signature_severities': list(set(s.severity for s in self.signatures.values()))
        }
    
    def get_recent_matches(self, limit: int = 100) -> List[Dict]:
        """Get recent signature matches"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM signature_matches 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            conn.close()
            
            matches = []
            for row in rows:
                match_dict = {
                    'id': row[0],
                    'signature_id': row[1],
                    'signature_name': row[2],
                    'severity': row[3],
                    'category': row[4],
                    'confidence': row[5],
                    'matched_content': row[6],
                    'source_ip': row[7],
                    'dest_ip': row[8],
                    'protocol': row[9],
                    'timestamp': row[10],
                    'metadata': json.loads(row[11]) if row[11] else {}
                }
                matches.append(match_dict)
            
            return matches
        except Exception as e:
            logger.error(f"Failed to get recent matches: {e}")
            return []

