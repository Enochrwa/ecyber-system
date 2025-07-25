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
        self._session = None # For service checks
        
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
            # Get aiohttp session for checks
            http_session = await self._get_aiohttp_session()

            # Determine Elasticsearch hosts and perform reachability check
            use_ssl_config = self.config.get('use_ssl', False)
            verify_certs_config = self.config.get('verify_certs', False)
            
            original_hosts = self.config.get('elasticsearch_hosts', ['localhost:9200'])
            processed_hosts = []
            for host in original_hosts:
                if use_ssl_config:
                    if not host.startswith('https://'):
                        processed_hosts.append(f'https://{host}')
                    else:
                        processed_hosts.append(host)
                else:
                    if not host.startswith('http://'):
                        processed_hosts.append(f'http://{host}')
                    else:
                        processed_hosts.append(host)
            
            if not processed_hosts:
                logger.error("No Elasticsearch hosts configured.")
                raise ValueError("Elasticsearch hosts are not configured.")

            # Check reachability of the first Elasticsearch host
            # A more robust check might try all hosts or a specific health check endpoint
            first_es_host_for_check = processed_hosts[0]
            # Ensure the URL has a scheme for the check
            if not first_es_host_for_check.startswith(('http://', 'https://')):
                first_es_host_for_check = f"http{'s' if use_ssl_config else ''}://{first_es_host_for_check}"
            
            if not await self._check_service_availability(first_es_host_for_check, "Elasticsearch", http_session):
                logger.error(f"Elasticsearch is not reachable at {first_es_host_for_check}. Aborting SIEM start.")
                # Optionally, set self.es_client to None or handle as per application's error strategy
                self.es_client = None 
                return # Or raise an exception

            es_constructor_args = {
                'hosts': processed_hosts
                # 'timeout' parameter removed
            }
            # If a request timeout is desired, it should be added like this:
            # es_constructor_args['request_timeout'] = self.config.get('request_timeout', 30)

            if self.config.get('username') and self.config.get('password'):
                es_constructor_args['http_auth'] = (
                    self.config['username'], 
                    self.config['password']
                )

            # Add verify_certs only if SSL is intended
            if use_ssl_config:
                self.es_client = AsyncElasticsearch(**es_constructor_args, verify_certs=verify_certs_config)
            else:
                self.es_client = AsyncElasticsearch(**es_constructor_args)
            
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

    async def _get_aiohttp_session(self):
        """Get or create an aiohttp.ClientSession."""
        if self._session is None or self._session.closed:
            # You might want to configure the session further, e.g., with timeouts
            self._session = aiohttp.ClientSession()
        return self._session

    async def _check_service_availability(self, url: str, service_name: str, session: aiohttp.ClientSession) -> bool:
        """Helper function to check if a service is available."""
        try:
            async with session.get(url, timeout=5) as response: # Basic check, adjust timeout as needed
                # Consider any 2xx or 3xx status as available for basic check
                if response.status < 400:
                    logger.info(f"{service_name} is reachable at {url} with status {response.status}.")
                    return True
                else:
                    logger.warning(f"{service_name} at {url} returned status {response.status}.")
                    return False
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Error connecting to {service_name} at {url}: {e}. Service might be down or host unreachable.")
            return False
        except asyncio.TimeoutError:
            logger.error(f"Timeout connecting to {service_name} at {url}. Service might be slow or down.")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while checking {service_name} at {url}: {e}")
            return False

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
        
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("aiohttp session for service checks closed.")

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
    
    def __init__(self, config: Dict[str, Any], es_siem_instance: ElasticsearchSIEM):
        self.config = config
        self.kibana_url = config.get('kibana_url', 'http://localhost:5601')
        self.username = config.get('username')
        self.es_siem_instance = es_siem_instance # To access _check_service_availability and session
        self.password = config.get('password')
        self.space_id = config.get('space_id', 'default')
        
    async def create_index_patterns(self):
        """Create Kibana index patterns for SIEM data"""
        
        http_session = await self.es_siem_instance._get_aiohttp_session()
        if not await self.es_siem_instance._check_service_availability(self.kibana_url, "Kibana", http_session):
            logger.error(f"Kibana is not reachable at {self.kibana_url}. Skipping index pattern creation.")
            return

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
        # Pass ElasticsearchSIEM instance to KibanaIntegration
        self.kibana_integration = KibanaIntegration(config.get('kibana', {}), self.elasticsearch_siem)
        self.running = False
        
    async def start(self):
        """Start SIEM integration"""
        try:
            # Start Elasticsearch integration
            await self.elasticsearch_siem.start()

            # If Elasticsearch client failed to initialize (e.g., ES not reachable),
            # elasticsearch_siem.es_client might be None.
            # We should not proceed with Kibana setup if ES is not up.
            if not self.elasticsearch_siem.es_client:
                logger.warning("Elasticsearch client not available. Skipping Kibana setup.")
                # Depending on desired behavior, you might want to set self.running to False
                # or handle this as a partial failure.
                return

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

