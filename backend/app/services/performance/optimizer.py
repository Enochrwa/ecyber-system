# Performance Optimization Module for AURORE Cybersecurity System
# This module provides comprehensive performance monitoring and optimization capabilities

import asyncio
import gc
import logging
import psutil
import time
import threading
import weakref
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import resource
import tracemalloc
import sys
import os

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    memory_available: float
    disk_io_read: int
    disk_io_write: int
    network_io_sent: int
    network_io_recv: int
    active_connections: int
    thread_count: int
    process_count: int
    gc_collections: Dict[int, int] = field(default_factory=dict)
    custom_metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MemoryProfile:
    """Memory profiling data structure"""
    timestamp: datetime
    current_memory: int
    peak_memory: int
    memory_blocks: int
    top_allocations: List[Dict[str, Any]]
    memory_leaks: List[Dict[str, Any]]

class PerformanceMonitor:
    """Advanced performance monitoring and optimization system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.monitoring_interval = self.config.get('monitoring_interval', 30)  # seconds
        self.metrics_history = deque(maxlen=self.config.get('history_size', 1000))
        self.memory_profiles = deque(maxlen=100)
        self.running = False
        self.monitor_task = None
        
        # Performance thresholds
        self.cpu_threshold = self.config.get('cpu_threshold', 80.0)
        self.memory_threshold = self.config.get('memory_threshold', 85.0)
        self.disk_threshold = self.config.get('disk_threshold', 90.0)
        
        # Callbacks for threshold violations
        self.alert_callbacks: List[Callable] = []
        
        # Memory tracking
        self.memory_tracker = MemoryTracker()
        
        # Performance optimizers
        self.cache_manager = CacheManager()
        self.connection_pool_manager = ConnectionPoolManager()
        
    async def start(self):
        """Start performance monitoring"""
        self.running = True
        
        # Start memory tracking
        tracemalloc.start()
        
        # Start monitoring task
        self.monitor_task = asyncio.create_task(self._monitoring_loop())
        
        # Start memory tracker
        await self.memory_tracker.start()
        
        logger.info("Performance monitoring started")
    
    async def stop(self):
        """Stop performance monitoring"""
        self.running = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        await self.memory_tracker.stop()
        
        # Stop memory tracking
        tracemalloc.stop()
        
        logger.info("Performance monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Collect metrics
                metrics = await self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Check thresholds
                await self._check_thresholds(metrics)
                
                # Collect memory profile
                if len(self.memory_profiles) == 0 or \
                   (datetime.now() - self.memory_profiles[-1].timestamp).seconds > 300:  # Every 5 minutes
                    profile = await self._collect_memory_profile()
                    self.memory_profiles.append(profile)
                
                # Trigger garbage collection if needed
                await self._optimize_memory()
                
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                await asyncio.sleep(self.monitoring_interval)
    
    async def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        try:
            # CPU and memory
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            
            # Network I/O
            network_io = psutil.net_io_counters()
            
            # Process information
            process = psutil.Process()
            
            # Garbage collection stats
            gc_stats = {}
            for i in range(3):
                gc_stats[i] = gc.get_count()[i]
            
            metrics = PerformanceMetrics(
                timestamp=datetime.now(),
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                memory_available=memory.available,
                disk_io_read=disk_io.read_bytes if disk_io else 0,
                disk_io_write=disk_io.write_bytes if disk_io else 0,
                network_io_sent=network_io.bytes_sent if network_io else 0,
                network_io_recv=network_io.bytes_recv if network_io else 0,
                active_connections=len(process.connections()),
                thread_count=process.num_threads(),
                process_count=len(psutil.pids()),
                gc_collections=gc_stats
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
            return PerformanceMetrics(
                timestamp=datetime.now(),
                cpu_usage=0.0,
                memory_usage=0.0,
                memory_available=0,
                disk_io_read=0,
                disk_io_write=0,
                network_io_sent=0,
                network_io_recv=0,
                active_connections=0,
                thread_count=0,
                process_count=0
            )
    
    async def _collect_memory_profile(self) -> MemoryProfile:
        """Collect detailed memory profiling information"""
        try:
            current, peak = tracemalloc.get_traced_memory()
            snapshot = tracemalloc.take_snapshot()
            
            # Get top memory allocations
            top_stats = snapshot.statistics('lineno')
            top_allocations = []
            
            for stat in top_stats[:10]:
                top_allocations.append({
                    'filename': stat.traceback.format()[0] if stat.traceback.format() else 'unknown',
                    'size': stat.size,
                    'count': stat.count
                })
            
            # Detect potential memory leaks
            memory_leaks = await self._detect_memory_leaks()
            
            profile = MemoryProfile(
                timestamp=datetime.now(),
                current_memory=current,
                peak_memory=peak,
                memory_blocks=len(top_stats),
                top_allocations=top_allocations,
                memory_leaks=memory_leaks
            )
            
            return profile
            
        except Exception as e:
            logger.error(f"Error collecting memory profile: {e}")
            return MemoryProfile(
                timestamp=datetime.now(),
                current_memory=0,
                peak_memory=0,
                memory_blocks=0,
                top_allocations=[],
                memory_leaks=[]
            )
    
    async def _detect_memory_leaks(self) -> List[Dict[str, Any]]:
        """Detect potential memory leaks"""
        leaks = []
        
        try:
            # Check for objects that should have been garbage collected
            for obj_type in [list, dict, set]:
                count = len([obj for obj in gc.get_objects() if isinstance(obj, obj_type)])
                if count > 10000:  # Threshold for potential leak
                    leaks.append({
                        'type': obj_type.__name__,
                        'count': count,
                        'severity': 'high' if count > 50000 else 'medium'
                    })
            
            # Check for circular references
            if gc.garbage:
                leaks.append({
                    'type': 'circular_references',
                    'count': len(gc.garbage),
                    'severity': 'high'
                })
            
        except Exception as e:
            logger.error(f"Error detecting memory leaks: {e}")
        
        return leaks
    
    async def _check_thresholds(self, metrics: PerformanceMetrics):
        """Check if performance metrics exceed thresholds"""
        alerts = []
        
        if metrics.cpu_usage > self.cpu_threshold:
            alerts.append({
                'type': 'cpu_high',
                'value': metrics.cpu_usage,
                'threshold': self.cpu_threshold,
                'severity': 'high'
            })
        
        if metrics.memory_usage > self.memory_threshold:
            alerts.append({
                'type': 'memory_high',
                'value': metrics.memory_usage,
                'threshold': self.memory_threshold,
                'severity': 'high'
            })
        
        # Trigger alerts
        for alert in alerts:
            await self._trigger_alert(alert)
    
    async def _trigger_alert(self, alert: Dict[str, Any]):
        """Trigger performance alert"""
        logger.warning(f"Performance alert: {alert}")
        
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    async def _optimize_memory(self):
        """Optimize memory usage"""
        try:
            # Force garbage collection if memory usage is high
            if self.metrics_history and self.metrics_history[-1].memory_usage > 70:
                collected = gc.collect()
                logger.debug(f"Garbage collection freed {collected} objects")
            
            # Clear caches if memory pressure is high
            if self.metrics_history and self.metrics_history[-1].memory_usage > 80:
                await self.cache_manager.clear_expired_entries()
                logger.debug("Cleared expired cache entries due to memory pressure")
                
        except Exception as e:
            logger.error(f"Error optimizing memory: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Add callback for performance alerts"""
        self.alert_callbacks.append(callback)
    
    def get_current_metrics(self) -> Optional[PerformanceMetrics]:
        """Get the most recent performance metrics"""
        return self.metrics_history[-1] if self.metrics_history else None
    
    def get_metrics_history(self, hours: int = 1) -> List[PerformanceMetrics]:
        """Get performance metrics history for the specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [m for m in self.metrics_history if m.timestamp >= cutoff_time]

class MemoryTracker:
    """Advanced memory tracking and leak detection"""
    
    def __init__(self):
        self.object_counts = defaultdict(int)
        self.tracking_enabled = False
        self.track_task = None
    
    async def start(self):
        """Start memory tracking"""
        self.tracking_enabled = True
        self.track_task = asyncio.create_task(self._tracking_loop())
        logger.info("Memory tracking started")
    
    async def stop(self):
        """Stop memory tracking"""
        self.tracking_enabled = False
        if self.track_task:
            self.track_task.cancel()
            try:
                await self.track_task
            except asyncio.CancelledError:
                pass
        logger.info("Memory tracking stopped")
    
    async def _tracking_loop(self):
        """Memory tracking loop"""
        while self.tracking_enabled:
            try:
                # Track object counts
                current_counts = defaultdict(int)
                for obj in gc.get_objects():
                    current_counts[type(obj).__name__] += 1
                
                # Check for significant increases
                for obj_type, count in current_counts.items():
                    if obj_type in self.object_counts:
                        increase = count - self.object_counts[obj_type]
                        if increase > 1000:  # Significant increase
                            logger.warning(f"Memory leak detected: {obj_type} increased by {increase}")
                
                self.object_counts = current_counts
                
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in memory tracking: {e}")
                await asyncio.sleep(60)

class CacheManager:
    """Intelligent cache management system"""
    
    def __init__(self):
        self.caches: Dict[str, Dict] = {}
        self.cache_stats: Dict[str, Dict] = {}
        self.max_cache_size = 1000
        self.ttl_seconds = 3600  # 1 hour default TTL
    
    def create_cache(self, name: str, max_size: int = None, ttl: int = None):
        """Create a new cache"""
        self.caches[name] = {}
        self.cache_stats[name] = {
            'hits': 0,
            'misses': 0,
            'size': 0,
            'max_size': max_size or self.max_cache_size,
            'ttl': ttl or self.ttl_seconds
        }
    
    def get(self, cache_name: str, key: str) -> Any:
        """Get value from cache"""
        if cache_name not in self.caches:
            return None
        
        cache = self.caches[cache_name]
        stats = self.cache_stats[cache_name]
        
        if key in cache:
            entry = cache[key]
            # Check TTL
            if time.time() - entry['timestamp'] < stats['ttl']:
                stats['hits'] += 1
                return entry['value']
            else:
                # Expired
                del cache[key]
                stats['size'] -= 1
        
        stats['misses'] += 1
        return None
    
    def set(self, cache_name: str, key: str, value: Any):
        """Set value in cache"""
        if cache_name not in self.caches:
            self.create_cache(cache_name)
        
        cache = self.caches[cache_name]
        stats = self.cache_stats[cache_name]
        
        # Check if cache is full
        if len(cache) >= stats['max_size']:
            # Remove oldest entry
            oldest_key = min(cache.keys(), key=lambda k: cache[k]['timestamp'])
            del cache[oldest_key]
            stats['size'] -= 1
        
        cache[key] = {
            'value': value,
            'timestamp': time.time()
        }
        stats['size'] += 1
    
    async def clear_expired_entries(self):
        """Clear expired cache entries"""
        current_time = time.time()
        
        for cache_name, cache in self.caches.items():
            stats = self.cache_stats[cache_name]
            expired_keys = []
            
            for key, entry in cache.items():
                if current_time - entry['timestamp'] >= stats['ttl']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del cache[key]
                stats['size'] -= 1
            
            if expired_keys:
                logger.debug(f"Cleared {len(expired_keys)} expired entries from cache '{cache_name}'")

class ConnectionPoolManager:
    """Manage database and network connection pools for optimal performance"""
    
    def __init__(self):
        self.pools: Dict[str, Any] = {}
        self.pool_stats: Dict[str, Dict] = {}
    
    def create_pool(self, name: str, max_connections: int = 20, min_connections: int = 5):
        """Create a connection pool"""
        self.pool_stats[name] = {
            'max_connections': max_connections,
            'min_connections': min_connections,
            'active_connections': 0,
            'total_requests': 0,
            'failed_requests': 0
        }
    
    def get_pool_stats(self, name: str) -> Dict[str, Any]:
        """Get connection pool statistics"""
        return self.pool_stats.get(name, {})
    
    async def optimize_pools(self):
        """Optimize connection pool sizes based on usage patterns"""
        for name, stats in self.pool_stats.items():
            # Implement pool optimization logic
            utilization = stats['active_connections'] / stats['max_connections']
            
            if utilization > 0.8:
                logger.warning(f"High utilization in pool '{name}': {utilization:.2%}")
            elif utilization < 0.2:
                logger.info(f"Low utilization in pool '{name}': {utilization:.2%}")

class PerformanceOptimizer:
    """Main performance optimization coordinator"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.monitor = PerformanceMonitor(config.get('monitoring', {}))
        self.running = False
        
    async def start(self):
        """Start performance optimization"""
        await self.monitor.start()
        
        # Add alert callback for automatic optimization
        self.monitor.add_alert_callback(self._handle_performance_alert)
        
        self.running = True
        logger.info("Performance optimizer started")
    
    async def stop(self):
        """Stop performance optimization"""
        self.running = False
        await self.monitor.stop()
        logger.info("Performance optimizer stopped")
    
    async def _handle_performance_alert(self, alert: Dict[str, Any]):
        """Handle performance alerts with automatic optimization"""
        alert_type = alert.get('type')
        
        if alert_type == 'memory_high':
            await self._optimize_memory_usage()
        elif alert_type == 'cpu_high':
            await self._optimize_cpu_usage()
    
    async def _optimize_memory_usage(self):
        """Optimize memory usage when high memory alert is triggered"""
        logger.info("Optimizing memory usage due to high memory alert")
        
        # Force garbage collection
        collected = gc.collect()
        logger.info(f"Garbage collection freed {collected} objects")
        
        # Clear caches
        await self.monitor.cache_manager.clear_expired_entries()
        
        # Additional memory optimization strategies
        # ... implement based on specific application needs
    
    async def _optimize_cpu_usage(self):
        """Optimize CPU usage when high CPU alert is triggered"""
        logger.info("Optimizing CPU usage due to high CPU alert")
        
        # Implement CPU optimization strategies
        # ... implement based on specific application needs
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        current_metrics = self.monitor.get_current_metrics()
        recent_metrics = self.monitor.get_metrics_history(hours=1)
        
        if not current_metrics or not recent_metrics:
            return {"error": "No performance data available"}
        
        # Calculate averages
        avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
        
        return {
            "current": {
                "cpu_usage": current_metrics.cpu_usage,
                "memory_usage": current_metrics.memory_usage,
                "memory_available": current_metrics.memory_available,
                "active_connections": current_metrics.active_connections,
                "thread_count": current_metrics.thread_count
            },
            "averages_1h": {
                "cpu_usage": avg_cpu,
                "memory_usage": avg_memory
            },
            "memory_profiles": len(self.monitor.memory_profiles),
            "cache_stats": self.monitor.cache_manager.cache_stats,
            "recommendations": self._generate_recommendations(current_metrics, recent_metrics)
        }
    
    def _generate_recommendations(self, current: PerformanceMetrics, history: List[PerformanceMetrics]) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        if current.cpu_usage > 80:
            recommendations.append("Consider scaling horizontally or optimizing CPU-intensive operations")
        
        if current.memory_usage > 85:
            recommendations.append("Memory usage is high - consider implementing memory optimization strategies")
        
        if current.active_connections > 100:
            recommendations.append("High number of active connections - consider connection pooling optimization")
        
        # Trend analysis
        if len(history) > 10:
            recent_cpu_trend = sum(m.cpu_usage for m in history[-10:]) / 10
            older_cpu_trend = sum(m.cpu_usage for m in history[-20:-10]) / 10
            
            if recent_cpu_trend > older_cpu_trend * 1.2:
                recommendations.append("CPU usage is trending upward - investigate potential performance degradation")
        
        return recommendations

