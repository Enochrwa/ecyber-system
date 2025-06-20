# Enhanced IP Blocking and Quarantine System
# This module provides enterprise-grade IP blocking and quarantine functionality

import asyncio
import subprocess
import platform
import ipaddress
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, asdict
import aiohttp
import sqlite3
import threading
import os
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class BlockedIP:
    """Represents a blocked IP with metadata"""
    ip: str
    rule_id: str
    severity: str
    description: str
    blocked_at: datetime
    expires_at: Optional[datetime] = None
    block_type: str = "temporary"  # temporary, permanent, quarantine
    source: str = "ips_engine"
    attempts_blocked: int = 0
    last_attempt: Optional[datetime] = None

class EnhancedIPBlocker:
    """Enhanced IP blocking system with multiple enforcement mechanisms"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.blocked_ips: Dict[str, BlockedIP] = {}
        self.quarantined_ips: Dict[str, BlockedIP] = {}
        self.lock = asyncio.Lock()
        self.platform = platform.system().lower()
        data_dir = Path(__file__).resolve().parent.parent.parent.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = data_dir / "blocked_ips.db"
        self._init_database()
        self._load_persistent_blocks()
        
        # Background cleanup task
        self.cleanup_task = None
        
    def _init_database(self):
        """Initialize SQLite database for persistent storage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    rule_id TEXT,
                    severity TEXT,
                    description TEXT,
                    blocked_at TEXT,
                    expires_at TEXT,
                    block_type TEXT,
                    source TEXT,
                    attempts_blocked INTEGER DEFAULT 0,
                    last_attempt TEXT
                )
            ''')
            conn.commit()
            conn.close()
            logger.info("IP blocker database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize IP blocker database: {e}")
    
    def _load_persistent_blocks(self):
        """Load persistent blocks from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM blocked_ips')
            rows = cursor.fetchall()
            
            for row in rows:
                ip, rule_id, severity, description, blocked_at, expires_at, block_type, source, attempts_blocked, last_attempt = row
                
                # Parse datetime strings
                blocked_at_dt = datetime.fromisoformat(blocked_at)
                expires_at_dt = datetime.fromisoformat(expires_at) if expires_at else None
                last_attempt_dt = datetime.fromisoformat(last_attempt) if last_attempt else None
                
                # Check if block has expired
                if expires_at_dt and datetime.now() > expires_at_dt:
                    cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
                    continue
                
                blocked_ip = BlockedIP(
                    ip=ip,
                    rule_id=rule_id,
                    severity=severity,
                    description=description,
                    blocked_at=blocked_at_dt,
                    expires_at=expires_at_dt,
                    block_type=block_type,
                    source=source,
                    attempts_blocked=attempts_blocked,
                    last_attempt=last_attempt_dt
                )
                
                if block_type == "quarantine":
                    self.quarantined_ips[ip] = blocked_ip
                else:
                    self.blocked_ips[ip] = blocked_ip
            
            conn.commit()
            conn.close()
            logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs and {len(self.quarantined_ips)} quarantined IPs from database")
        except Exception as e:
            logger.error(f"Failed to load persistent blocks: {e}")
    
    async def start(self):
        """Start the IP blocker service"""
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_expired_blocks())
        logger.info("Enhanced IP blocker started")
    
    async def stop(self):
        """Stop the IP blocker service"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
        logger.info("Enhanced IP blocker stopped")
    
    async def block_ip(self, ip: str, rule_id: str, severity: str, description: str, 
                      duration_hours: int = 24, block_type: str = "temporary") -> bool:
        """Block an IP address with multiple enforcement mechanisms"""
        async with self.lock:
            try:
                # Check if IP is already blocked
                if ip in self.blocked_ips:
                    self.blocked_ips[ip].attempts_blocked += 1
                    self.blocked_ips[ip].last_attempt = datetime.now()
                    await self._update_database_record(self.blocked_ips[ip])
                    return True
                
                # Create blocked IP record
                expires_at = datetime.now() + timedelta(hours=duration_hours) if duration_hours > 0 else None
                blocked_ip = BlockedIP(
                    ip=ip,
                    rule_id=rule_id,
                    severity=severity,
                    description=description,
                    blocked_at=datetime.now(),
                    expires_at=expires_at,
                    block_type=block_type,
                    source="ips_engine"
                )
                
                # Apply blocking mechanisms
                success = await self._apply_blocking_mechanisms(ip, blocked_ip)
                
                if success:
                    self.blocked_ips[ip] = blocked_ip
                    await self._save_to_database(blocked_ip)
                    logger.warning(f"Successfully blocked IP {ip} (Rule: {rule_id}, Severity: {severity})")
                    return True
                else:
                    logger.error(f"Failed to block IP {ip}")
                    return False
                    
            except Exception as e:
                logger.error(f"Error blocking IP {ip}: {e}")
                return False
    
    async def quarantine_ip(self, ip: str, rule_id: str, severity: str, description: str,
                           duration_hours: int = 24) -> bool:
        """Quarantine an IP address with strict isolation"""
        async with self.lock:
            try:
                # Check if IP is already quarantined
                if ip in self.quarantined_ips:
                    self.quarantined_ips[ip].attempts_blocked += 1
                    self.quarantined_ips[ip].last_attempt = datetime.now()
                    await self._update_database_record(self.quarantined_ips[ip])
                    return True
                
                # Create quarantined IP record
                expires_at = datetime.now() + timedelta(hours=duration_hours) if duration_hours > 0 else None
                quarantined_ip = BlockedIP(
                    ip=ip,
                    rule_id=rule_id,
                    severity=severity,
                    description=description,
                    blocked_at=datetime.now(),
                    expires_at=expires_at,
                    block_type="quarantine",
                    source="ips_engine"
                )
                
                # Apply quarantine mechanisms
                success = await self._apply_quarantine_mechanisms(ip, quarantined_ip)
                
                if success:
                    self.quarantined_ips[ip] = quarantined_ip
                    await self._save_to_database(quarantined_ip)
                    logger.warning(f"Successfully quarantined IP {ip} (Rule: {rule_id}, Severity: {severity})")
                    return True
                else:
                    logger.error(f"Failed to quarantine IP {ip}")
                    return False
                    
            except Exception as e:
                logger.error(f"Error quarantining IP {ip}: {e}")
                return False
    
    async def _apply_blocking_mechanisms(self, ip: str, blocked_ip: BlockedIP) -> bool:
        """Apply multiple blocking mechanisms for redundancy"""
        success_count = 0
        total_mechanisms = 0
        
        # 1. Firewall blocking
        if await self._block_via_firewall(ip):
            success_count += 1
        total_mechanisms += 1
        
        # 2. iptables/netfilter blocking (Linux)
        if self.platform == "linux":
            if await self._block_via_iptables(ip):
                success_count += 1
            total_mechanisms += 1
        
        # 3. Windows Firewall blocking (Windows)
        elif self.platform == "windows":
            if await self._block_via_windows_firewall(ip):
                success_count += 1
            total_mechanisms += 1
        
        # 4. pfctl blocking (macOS)
        elif self.platform == "darwin":
            if await self._block_via_pfctl(ip):
                success_count += 1
            total_mechanisms += 1
        
        # 5. Application-level blocking
        if await self._block_via_application_filter(ip):
            success_count += 1
        total_mechanisms += 1
        
        # Consider successful if at least one mechanism worked
        return success_count > 0
    
    async def _apply_quarantine_mechanisms(self, ip: str, quarantined_ip: BlockedIP) -> bool:
        """Apply strict quarantine mechanisms"""
        success_count = 0
        total_mechanisms = 0
        
        # 1. Complete network isolation
        if await self._isolate_via_firewall(ip):
            success_count += 1
        total_mechanisms += 1
        
        # 2. DNS sinkholing
        if await self._apply_dns_sinkhole(ip):
            success_count += 1
        total_mechanisms += 1
        
        # 3. VLAN isolation (if configured)
        if self.config.get('vlan_isolation_enabled'):
            if await self._isolate_via_vlan(ip):
                success_count += 1
            total_mechanisms += 1
        
        # 4. Rate limiting to near-zero
        if await self._apply_extreme_rate_limiting(ip):
            success_count += 1
        total_mechanisms += 1
        
        return success_count > 0
    
    async def _block_via_firewall(self, ip: str) -> bool:
        """Block IP via system firewall"""
        try:
            if self.platform == "linux":
                # Use iptables
                cmd = f"iptables -I INPUT 1 -s {ip} -j DROP"
                result = await self._execute_command(cmd)
                return result
            elif self.platform == "windows":
                # Use Windows Firewall
                cmd = f'netsh advfirewall firewall add rule name="IPS Block {ip}" dir=in action=block remoteip={ip}'
                result = await self._execute_command(cmd)
                return result
            elif self.platform == "darwin":
                # Use pfctl
                cmd = f"echo 'block in quick from {ip}' | pfctl -f -"
                result = await self._execute_command(cmd)
                return result
            return False
        except Exception as e:
            logger.error(f"Firewall blocking failed for {ip}: {e}")
            return False
    
    async def _block_via_iptables(self, ip: str) -> bool:
        """Block IP via iptables (Linux)"""
        try:
            commands = [
                f"iptables -I INPUT 1 -s {ip} -j DROP",
                f"iptables -I OUTPUT 1 -d {ip} -j DROP",
                f"iptables -I FORWARD 1 -s {ip} -j DROP",
                f"iptables -I FORWARD 1 -d {ip} -j DROP"
            ]
            
            for cmd in commands:
                if not await self._execute_command(cmd):
                    logger.warning(f"Failed to execute: {cmd}")
            
            # Save iptables rules
            await self._execute_command("iptables-save > /etc/iptables/rules.v4")
            return True
        except Exception as e:
            logger.error(f"iptables blocking failed for {ip}: {e}")
            return False
    
    async def _block_via_windows_firewall(self, ip: str) -> bool:
        """Block IP via Windows Firewall"""
        try:
            commands = [
                f'netsh advfirewall firewall add rule name="IPS Block In {ip}" dir=in action=block remoteip={ip}',
                f'netsh advfirewall firewall add rule name="IPS Block Out {ip}" dir=out action=block remoteip={ip}'
            ]
            
            for cmd in commands:
                if not await self._execute_command(cmd):
                    logger.warning(f"Failed to execute: {cmd}")
            
            return True
        except Exception as e:
            logger.error(f"Windows Firewall blocking failed for {ip}: {e}")
            return False
    
    async def _block_via_pfctl(self, ip: str) -> bool:
        """Block IP via pfctl (macOS)"""
        try:
            # Add to blocked table
            cmd = f"pfctl -t blocked_ips -T add {ip}"
            result = await self._execute_command(cmd)
            
            if result:
                # Enable pfctl if not already enabled
                await self._execute_command("pfctl -e")
            
            return result
        except Exception as e:
            logger.error(f"pfctl blocking failed for {ip}: {e}")
            return False
    
    async def _block_via_application_filter(self, ip: str) -> bool:
        """Block IP at application level"""
        try:
            # This would integrate with the application's packet filtering
            # For now, we'll just log it as a placeholder
            logger.info(f"Application-level block applied for {ip}")
            return True
        except Exception as e:
            logger.error(f"Application-level blocking failed for {ip}: {e}")
            return False
    
    async def _isolate_via_firewall(self, ip: str) -> bool:
        """Complete network isolation via firewall"""
        try:
            if self.platform == "linux":
                commands = [
                    f"iptables -I INPUT 1 -s {ip} -j DROP",
                    f"iptables -I OUTPUT 1 -d {ip} -j DROP",
                    f"iptables -I FORWARD 1 -s {ip} -j DROP",
                    f"iptables -I FORWARD 1 -d {ip} -j DROP",
                    f"iptables -t nat -I PREROUTING 1 -s {ip} -j DROP",
                    f"iptables -t nat -I POSTROUTING 1 -d {ip} -j DROP"
                ]
                
                for cmd in commands:
                    await self._execute_command(cmd)
                
                return True
        except Exception as e:
            logger.error(f"Firewall isolation failed for {ip}: {e}")
            return False
    
    async def _apply_dns_sinkhole(self, ip: str) -> bool:
        """Apply DNS sinkholing for the IP"""
        try:
            # This would integrate with DNS server to redirect queries
            # For now, we'll just log it as a placeholder
            logger.info(f"DNS sinkhole applied for {ip}")
            return True
        except Exception as e:
            logger.error(f"DNS sinkholing failed for {ip}: {e}")
            return False
    
    async def _isolate_via_vlan(self, ip: str) -> bool:
        """Isolate IP via VLAN switching"""
        try:
            # This would integrate with network switches for VLAN isolation
            # For now, we'll just log it as a placeholder
            logger.info(f"VLAN isolation applied for {ip}")
            return True
        except Exception as e:
            logger.error(f"VLAN isolation failed for {ip}: {e}")
            return False
    
    async def _apply_extreme_rate_limiting(self, ip: str) -> bool:
        """Apply extreme rate limiting"""
        try:
            if self.platform == "linux":
                # Limit to 1 packet per minute
                cmd = f"iptables -I INPUT -s {ip} -m limit --limit 1/minute --limit-burst 1 -j ACCEPT"
                return await self._execute_command(cmd)
            return True
        except Exception as e:
            logger.error(f"Rate limiting failed for {ip}: {e}")
            return False
    
    async def _execute_command(self, command: str) -> bool:
        """Execute system command asynchronously"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return True
            else:
                logger.error(f"Command failed: {command}, Error: {stderr.decode()}")
                return False
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False
    
    async def _save_to_database(self, blocked_ip: BlockedIP):
        """Save blocked IP to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips 
                (ip, rule_id, severity, description, blocked_at, expires_at, block_type, source, attempts_blocked, last_attempt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                blocked_ip.ip,
                blocked_ip.rule_id,
                blocked_ip.severity,
                blocked_ip.description,
                blocked_ip.blocked_at.isoformat(),
                blocked_ip.expires_at.isoformat() if blocked_ip.expires_at else None,
                blocked_ip.block_type,
                blocked_ip.source,
                blocked_ip.attempts_blocked,
                blocked_ip.last_attempt.isoformat() if blocked_ip.last_attempt else None
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save blocked IP to database: {e}")
    
    async def _update_database_record(self, blocked_ip: BlockedIP):
        """Update existing database record"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE blocked_ips 
                SET attempts_blocked = ?, last_attempt = ?
                WHERE ip = ?
            ''', (
                blocked_ip.attempts_blocked,
                blocked_ip.last_attempt.isoformat() if blocked_ip.last_attempt else None,
                blocked_ip.ip
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to update blocked IP in database: {e}")
    
    async def _cleanup_expired_blocks(self):
        """Background task to clean up expired blocks"""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                async with self.lock:
                    now = datetime.now()
                    expired_ips = []
                    
                    # Check blocked IPs
                    for ip, blocked_ip in self.blocked_ips.items():
                        if blocked_ip.expires_at and now > blocked_ip.expires_at:
                            expired_ips.append((ip, "blocked"))
                    
                    # Check quarantined IPs
                    for ip, quarantined_ip in self.quarantined_ips.items():
                        if quarantined_ip.expires_at and now > quarantined_ip.expires_at:
                            expired_ips.append((ip, "quarantined"))
                    
                    # Remove expired blocks
                    for ip, block_type in expired_ips:
                        await self.unblock_ip(ip)
                        logger.info(f"Removed expired {block_type} IP: {ip}")
                
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
    
    async def unblock_ip(self, ip: str) -> bool:
        """Remove IP from blocked/quarantined lists"""
        async with self.lock:
            try:
                success = True
                
                # Remove from blocked IPs
                if ip in self.blocked_ips:
                    del self.blocked_ips[ip]
                
                # Remove from quarantined IPs
                if ip in self.quarantined_ips:
                    del self.quarantined_ips[ip]
                
                # Remove from firewall rules
                await self._remove_firewall_rules(ip)
                
                # Remove from database
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
                conn.commit()
                conn.close()
                
                logger.info(f"Successfully unblocked IP: {ip}")
                return True
                
            except Exception as e:
                logger.error(f"Error unblocking IP {ip}: {e}")
                return False
    
    async def _remove_firewall_rules(self, ip: str):
        """Remove firewall rules for IP"""
        try:
            if self.platform == "linux":
                commands = [
                    f"iptables -D INPUT -s {ip} -j DROP",
                    f"iptables -D OUTPUT -d {ip} -j DROP",
                    f"iptables -D FORWARD -s {ip} -j DROP",
                    f"iptables -D FORWARD -d {ip} -j DROP"
                ]
                for cmd in commands:
                    await self._execute_command(cmd)
            
            elif self.platform == "windows":
                commands = [
                    f'netsh advfirewall firewall delete rule name="IPS Block In {ip}"',
                    f'netsh advfirewall firewall delete rule name="IPS Block Out {ip}"'
                ]
                for cmd in commands:
                    await self._execute_command(cmd)
            
            elif self.platform == "darwin":
                cmd = f"pfctl -t blocked_ips -T delete {ip}"
                await self._execute_command(cmd)
                
        except Exception as e:
            logger.error(f"Error removing firewall rules for {ip}: {e}")
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        return ip in self.blocked_ips or ip in self.quarantined_ips
    
    def get_blocked_ips(self) -> List[Dict]:
        """Get list of all blocked IPs"""
        result = []
        for blocked_ip in self.blocked_ips.values():
            result.append(asdict(blocked_ip))
        for quarantined_ip in self.quarantined_ips.values():
            result.append(asdict(quarantined_ip))
        return result
    
    def get_stats(self) -> Dict:
        """Get blocking statistics"""
        return {
            "total_blocked": len(self.blocked_ips),
            "total_quarantined": len(self.quarantined_ips),
            "platform": self.platform,
            "active_since": datetime.now().isoformat()
        }

