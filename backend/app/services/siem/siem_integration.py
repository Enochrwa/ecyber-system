# SIEM Integration with Elasticsearch and Kibana
# This module provides comprehensive SIEM capabilities for the AURORE cybersecurity system

import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk
import aiohttp
import hashlib
import uuid

logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """Standardized security event structure for SIEM"""
    id: str
    timestamp: datetime
    event_type: str  # threat, alert, network, system, user_activity
    severity: str    # critical, high, medium, low, info
    source: str      # component that generated the event
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None  # success, failure, unknown
    message: str = ""
    details: Dict[str, Any] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if self.tags is None:
            self.tags = []
        if not self.id:
            self.id = str(uuid.uuid4())

class ElasticsearchSIEM:
    """Advanced SIEM integration with Elasticsearch"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.es_client = None
        self.index_prefix = config.get('index_prefix', 'aurore-siem')
        self.batch_size = config.get('batch_size', 100)
        self.flush_interval = config.get('flush_interval', 30)  # seconds
        self.event_buffer = []
        self.buffer_lock = asyncio.Lock()
        self.running = False
        self.flush_task = None
        
        # Index templates for different event types
        self.index_templates = {
            'threat': f"{self.index_prefix}-threat",
            'alert': f"{self.index_prefix}-alert", 
            'network': f"{self.index_prefix}-network",
            'system': f"{self.index_prefix}-system",
            'user_activity': f"{self.index_prefix}-user",
            'audit': f"{self.index_prefix}-audit"
        }
        
    async def start(self):
        """Initialize Elasticsearch connection and start background tasks"""
        try:
            # Initialize Elasticsearch client
            es_config = {
                'hosts': self.config.get('elasticsearch_hosts', ['localhost:9200']),
                'http_auth': None,
                'use_ssl': self.config.get('use_ssl', False),
                'verify_certs': self.config.get('verify_certs', False),
                'timeout': self.config.get('timeout', 30)
            }
            
            # Add authentication if provided
            if self.config.get('username') and self.config.get('password'):
                es_config['http_auth'] = (
                    self.config['username'], 
                    self.config['password']
                )
            
            self.es_client = AsyncElasticsearch(**es_config)
            
            # Test connection
            await self.es_client.ping()
            logger.info("Successfully connected to Elasticsearch")
            
            # Create index templates
            await self._create_index_templates()
            
            # Start background flush task
            self.running = True
            self.flush_task = asyncio.create_task(self._flush_events_periodically())
            
            logger.info("SIEM Elasticsearch integration started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Elasticsearch SIEM: {e}")
            raise
    
    async def stop(self):
        """Stop SIEM and flush remaining events"""
        self.running = False
        
        if self.flush_task:
            self.flush_task.cancel()
            try:
                await self.flush_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining events
        await self._flush_events()
        
        if self.es_client:
            await self.es_client.close()
        
        logger.info("SIEM Elasticsearch integration stopped")
    
    async def _create_index_templates(self):
        """Create Elasticsearch index templates for security events"""
        
        # Common mapping for all security events
        common_mapping = {
            "properties": {
                "id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "event_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "source": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "dest_ip": {"type": "ip"},
                "user": {"type": "keyword"},
                "action": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                "message": {"type": "text", "analyzer": "standard"},
                "details": {"type": "object", "dynamic": True},
                "tags": {"type": "keyword"},
                "@timestamp": {"type": "date"}
            }
        }
        
        # Create index template for each event type
        for event_type, index_name in self.index_templates.items():
            template = {
                "index_patterns": [f"{index_name}-*"],
                "template": {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                        "index.refresh_interval": "5s"
                    },
                    "mappings": common_mapping
                }
            }
            
            try:
                await self.es_client.indices.put_index_template(
                    name=f"{index_name}-template",
                    body=template
                )
                logger.info(f"Created index template for {event_type}")
            except Exception as e:
                logger.error(f"Failed to create index template for {event_type}: {e}")
    
    async def log_event(self, event: SecurityEvent):
        """Log a security event to SIEM"""
        async with self.buffer_lock:
            self.event_buffer.append(event)
            
            # Flush if buffer is full
            if len(self.event_buffer) >= self.batch_size:
                await self._flush_events()
    
    async def log_threat_detection(self, 
                                 threat_type: str,
                                 severity: str,
                                 source_ip: str,
                                 dest_ip: str = None,
                                 details: Dict[str, Any] = None):
        """Log threat detection event"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type="threat",
            severity=severity,
            source="threat_detector",
            source_ip=source_ip,
            dest_ip=dest_ip,
            action="detect",
            outcome="success",
            message=f"Threat detected: {threat_type}",
            details=details or {},
            tags=["threat", threat_type]
        )
        await self.log_event(event)
    
    async def log_security_alert(self,
                               alert_type: str,
                               severity: str,
                               message: str,
                               details: Dict[str, Any] = None):
        """Log security alert event"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type="alert",
            severity=severity,
            source="security_monitor",
            action="alert",
            outcome="success",
            message=message,
            details=details or {},
            tags=["alert", alert_type]
        )
        await self.log_event(event)
    
    async def log_network_event(self,
                              source_ip: str,
                              dest_ip: str,
                              protocol: str,
                              action: str,
                              outcome: str,
                              details: Dict[str, Any] = None):
        """Log network security event"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type="network",
            severity="info",
            source="network_monitor",
            source_ip=source_ip,
            dest_ip=dest_ip,
            action=action,
            outcome=outcome,
            message=f"Network {action}: {source_ip} -> {dest_ip} ({protocol})",
            details=details or {},
            tags=["network", protocol.lower()]
        )
        await self.log_event(event)
    
    async def log_user_activity(self,
                              user: str,
                              action: str,
                              outcome: str,
                              source_ip: str = None,
                              details: Dict[str, Any] = None):
        """Log user activity event"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type="user_activity",
            severity="info",
            source="user_monitor",
            source_ip=source_ip,
            user=user,
            action=action,
            outcome=outcome,
            message=f"User {user} {action}: {outcome}",
            details=details or {},
            tags=["user", action]
        )
        await self.log_event(event)
    
    async def _flush_events(self):
        """Flush buffered events to Elasticsearch"""
        if not self.event_buffer:
            return
        
        events_to_flush = self.event_buffer.copy()
        self.event_buffer.clear()
        
        try:
            # Prepare bulk operations
            operations = []
            for event in events_to_flush:
                # Determine index name based on event type and date
                index_name = f"{self.index_templates.get(event.event_type, self.index_prefix)}-{event.timestamp.strftime('%Y.%m.%d')}"
                
                # Convert event to dict and add @timestamp for Kibana
                event_dict = asdict(event)
                event_dict['@timestamp'] = event.timestamp.isoformat()
                
                operation = {
                    "_index": index_name,
                    "_id": event.id,
                    "_source": event_dict
                }
                operations.append(operation)
            
            # Bulk index to Elasticsearch
            if operations:
                success, failed = await async_bulk(
                    self.es_client,
                    operations,
                    chunk_size=self.batch_size
                )
                
                if failed:
                    logger.error(f"Failed to index {len(failed)} events to Elasticsearch")
                else:
                    logger.debug(f"Successfully indexed {success} events to Elasticsearch")
                    
        except Exception as e:
            logger.error(f"Error flushing events to Elasticsearch: {e}")
            # Re-add events to buffer for retry
            async with self.buffer_lock:
                self.event_buffer.extend(events_to_flush)
    
    async def _flush_events_periodically(self):
        """Periodically flush events to Elasticsearch"""
        while self.running:
            try:
                await asyncio.sleep(self.flush_interval)
                async with self.buffer_lock:
                    if self.event_buffer:
                        await self._flush_events()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic flush: {e}")
    
    async def search_events(self,
                          query: Dict[str, Any] = None,
                          time_range: Dict[str, str] = None,
                          event_types: List[str] = None,
                          size: int = 100) -> Dict[str, Any]:
        """Search security events in Elasticsearch"""
        try:
            # Build search query
            search_body = {
                "size": size,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            # Build query
            must_clauses = []
            
            if query:
                must_clauses.append(query)
            
            if time_range:
                must_clauses.append({
                    "range": {
                        "timestamp": time_range
                    }
                })
            
            if event_types:
                must_clauses.append({
                    "terms": {
                        "event_type": event_types
                    }
                })
            
            if must_clauses:
                search_body["query"] = {
                    "bool": {
                        "must": must_clauses
                    }
                }
            
            # Determine indices to search
            if event_types:
                indices = [f"{self.index_templates.get(et, self.index_prefix)}-*" for et in event_types]
            else:
                indices = [f"{self.index_prefix}-*"]
            
            # Execute search
            response = await self.es_client.search(
                index=indices,
                body=search_body
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error searching events: {e}")
            return {"hits": {"hits": [], "total": {"value": 0}}}
    
    async def get_threat_statistics(self, time_range: Dict[str, str] = None) -> Dict[str, Any]:
        """Get threat statistics from SIEM data"""
        try:
            # Build aggregation query
            agg_body = {
                "size": 0,
                "aggs": {
                    "severity_breakdown": {
                        "terms": {"field": "severity"}
                    },
                    "threat_types": {
                        "terms": {"field": "tags"}
                    },
                    "timeline": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "1h"
                        }
                    }
                }
            }
            
            if time_range:
                agg_body["query"] = {
                    "bool": {
                        "must": [
                            {"term": {"event_type": "threat"}},
                            {"range": {"timestamp": time_range}}
                        ]
                    }
                }
            else:
                agg_body["query"] = {"term": {"event_type": "threat"}}
            
            response = await self.es_client.search(
                index=f"{self.index_templates['threat']}-*",
                body=agg_body
            )
            
            return response.get("aggregations", {})
            
        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            return {}

class KibanaIntegration:
    """Integration with Kibana for visualization and dashboards"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.kibana_url = config.get('kibana_url', 'http://localhost:5601')
        self.username = config.get('username')
        self.password = config.get('password')
        self.space_id = config.get('space_id', 'default')
        
    async def create_index_patterns(self):
        """Create Kibana index patterns for SIEM data"""
        index_patterns = [
            {
                "title": "aurore-siem-threat-*",
                "timeFieldName": "@timestamp",
                "attributes": {
                    "title": "aurore-siem-threat-*",
                    "timeFieldName": "@timestamp"
                }
            },
            {
                "title": "aurore-siem-alert-*", 
                "timeFieldName": "@timestamp",
                "attributes": {
                    "title": "aurore-siem-alert-*",
                    "timeFieldName": "@timestamp"
                }
            },
            {
                "title": "aurore-siem-network-*",
                "timeFieldName": "@timestamp", 
                "attributes": {
                    "title": "aurore-siem-network-*",
                    "timeFieldName": "@timestamp"
                }
            }
        ]
        
        async with aiohttp.ClientSession() as session:
            for pattern in index_patterns:
                try:
                    url = f"{self.kibana_url}/api/saved_objects/index-pattern"
                    headers = {
                        'Content-Type': 'application/json',
                        'kbn-xsrf': 'true'
                    }
                    
                    if self.username and self.password:
                        auth = aiohttp.BasicAuth(self.username, self.password)
                    else:
                        auth = None
                    
                    async with session.post(
                        url,
                        json=pattern,
                        headers=headers,
                        auth=auth
                    ) as response:
                        if response.status in [200, 409]:  # 409 = already exists
                            logger.info(f"Index pattern {pattern['title']} created/exists")
                        else:
                            logger.error(f"Failed to create index pattern {pattern['title']}: {response.status}")
                            
                except Exception as e:
                    logger.error(f"Error creating index pattern {pattern['title']}: {e}")
    
    async def create_security_dashboard(self):
        """Create a comprehensive security dashboard in Kibana"""
        dashboard_config = {
            "attributes": {
                "title": "AURORE Security Dashboard",
                "type": "dashboard",
                "description": "Comprehensive security monitoring dashboard for AURORE system",
                "panelsJSON": json.dumps([
                    {
                        "version": "8.0.0",
                        "type": "visualization",
                        "gridData": {"x": 0, "y": 0, "w": 24, "h": 15},
                        "panelIndex": "1",
                        "embeddableConfig": {},
                        "panelRefName": "panel_1"
                    }
                ]),
                "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
                "version": 1,
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
                }
            },
            "references": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.kibana_url}/api/saved_objects/dashboard"
                headers = {
                    'Content-Type': 'application/json',
                    'kbn-xsrf': 'true'
                }
                
                auth = None
                if self.username and self.password:
                    auth = aiohttp.BasicAuth(self.username, self.password)
                
                async with session.post(
                    url,
                    json=dashboard_config,
                    headers=headers,
                    auth=auth
                ) as response:
                    if response.status in [200, 409]:
                        logger.info("Security dashboard created successfully")
                    else:
                        logger.error(f"Failed to create dashboard: {response.status}")
                        
        except Exception as e:
            logger.error(f"Error creating security dashboard: {e}")

class SIEMManager:
    """Main SIEM manager that coordinates Elasticsearch and Kibana integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.elasticsearch_siem = ElasticsearchSIEM(config.get('elasticsearch', {}))
        self.kibana_integration = KibanaIntegration(config.get('kibana', {}))
        self.running = False
        
    async def start(self):
        """Start SIEM integration"""
        try:
            # Start Elasticsearch integration
            await self.elasticsearch_siem.start()
            
            # Setup Kibana
            await self.kibana_integration.create_index_patterns()
            await self.kibana_integration.create_security_dashboard()
            
            self.running = True
            logger.info("SIEM Manager started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start SIEM Manager: {e}")
            raise
    
    async def stop(self):
        """Stop SIEM integration"""
        self.running = False
        await self.elasticsearch_siem.stop()
        logger.info("SIEM Manager stopped")
    
    async def log_event(self, event: SecurityEvent):
        """Log event to SIEM"""
        if self.running:
            await self.elasticsearch_siem.log_event(event)
    
    async def search_events(self, **kwargs):
        """Search events in SIEM"""
        return await self.elasticsearch_siem.search_events(**kwargs)
    
    async def get_threat_statistics(self, **kwargs):
        """Get threat statistics"""
        return await self.elasticsearch_siem.get_threat_statistics(**kwargs)

