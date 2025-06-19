# SIEM API endpoints for AURORE cybersecurity system
# Provides REST API access to SIEM data and functionality

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import JSONResponse
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import logging

from ..siem.siem_integration import SIEMManager, SecurityEvent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/siem", tags=["SIEM"])

# Pydantic models for API requests/responses
class EventSearchRequest(BaseModel):
    query: Optional[str] = None
    event_types: Optional[List[str]] = None
    severity_levels: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    size: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)

class EventCreateRequest(BaseModel):
    event_type: str
    severity: str
    source: str
    message: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None

class ThreatStatisticsResponse(BaseModel):
    total_threats: int
    severity_breakdown: Dict[str, int]
    threat_types: Dict[str, int]
    timeline: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]
    top_targets: List[Dict[str, Any]]

class AlertSummaryResponse(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    recent_alerts: List[Dict[str, Any]]

# Global SIEM manager instance (will be initialized in main.py)
siem_manager: Optional[SIEMManager] = None

def get_siem_manager() -> SIEMManager:
    """Dependency to get SIEM manager instance"""
    if siem_manager is None:
        raise HTTPException(status_code=503, detail="SIEM service not available")
    return siem_manager

@router.get("/health")
async def siem_health_check():
    """Check SIEM service health"""
    try:
        if siem_manager and siem_manager.running:
            return {"status": "healthy", "message": "SIEM service is running"}
        else:
            return {"status": "unhealthy", "message": "SIEM service is not running"}
    except Exception as e:
        logger.error(f"SIEM health check failed: {e}")
        return {"status": "error", "message": str(e)}

@router.post("/events")
async def create_event(
    event_request: EventCreateRequest,
    siem: SIEMManager = Depends(get_siem_manager)
):
    """Create a new security event in SIEM"""
    try:
        event = SecurityEvent(
            id="",  # Will be auto-generated
            timestamp=datetime.utcnow(),
            event_type=event_request.event_type,
            severity=event_request.severity,
            source=event_request.source,
            source_ip=event_request.source_ip,
            dest_ip=event_request.dest_ip,
            user=event_request.user,
            action=event_request.action,
            outcome=event_request.outcome,
            message=event_request.message,
            details=event_request.details or {},
            tags=event_request.tags or []
        )
        
        await siem.log_event(event)
        
        return {
            "status": "success",
            "message": "Event logged successfully",
            "event_id": event.id
        }
        
    except Exception as e:
        logger.error(f"Failed to create SIEM event: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create event: {str(e)}")

@router.get("/events/search")
async def search_events(
    query: Optional[str] = Query(None, description="Search query"),
    event_types: Optional[str] = Query(None, description="Comma-separated event types"),
    severity_levels: Optional[str] = Query(None, description="Comma-separated severity levels"),
    start_time: Optional[datetime] = Query(None, description="Start time for search"),
    end_time: Optional[datetime] = Query(None, description="End time for search"),
    source_ip: Optional[str] = Query(None, description="Source IP address"),
    dest_ip: Optional[str] = Query(None, description="Destination IP address"),
    user: Optional[str] = Query(None, description="Username"),
    size: int = Query(100, le=1000, description="Number of results to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    siem: SIEMManager = Depends(get_siem_manager)
):
    """Search security events in SIEM"""
    try:
        # Build search parameters
        search_params = {"size": size}
        
        # Build Elasticsearch query
        must_clauses = []
        
        if query:
            must_clauses.append({
                "multi_match": {
                    "query": query,
                    "fields": ["message", "details.*", "tags"]
                }
            })
        
        if event_types:
            event_type_list = [et.strip() for et in event_types.split(",")]
            must_clauses.append({
                "terms": {"event_type": event_type_list}
            })
        
        if severity_levels:
            severity_list = [s.strip() for s in severity_levels.split(",")]
            must_clauses.append({
                "terms": {"severity": severity_list}
            })
        
        if source_ip:
            must_clauses.append({"term": {"source_ip": source_ip}})
        
        if dest_ip:
            must_clauses.append({"term": {"dest_ip": dest_ip}})
        
        if user:
            must_clauses.append({"term": {"user": user}})
        
        # Time range
        time_range = {}
        if start_time:
            time_range["gte"] = start_time.isoformat()
        if end_time:
            time_range["lte"] = end_time.isoformat()
        
        if time_range:
            search_params["time_range"] = time_range
        
        if must_clauses:
            search_params["query"] = {
                "bool": {"must": must_clauses}
            }
        
        # Execute search
        results = await siem.search_events(**search_params)
        
        # Format response
        events = []
        for hit in results.get("hits", {}).get("hits", []):
            event_data = hit["_source"]
            event_data["_id"] = hit["_id"]
            events.append(event_data)
        
        total = results.get("hits", {}).get("total", {}).get("value", 0)
        
        return {
            "events": events,
            "total": total,
            "size": size,
            "offset": offset,
            "has_more": (offset + size) < total
        }
        
    except Exception as e:
        logger.error(f"Failed to search SIEM events: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@router.get("/statistics/threats", response_model=ThreatStatisticsResponse)
async def get_threat_statistics(
    hours: int = Query(24, description="Time range in hours"),
    siem: SIEMManager = Depends(get_siem_manager)
):
    """Get threat statistics from SIEM"""
    try:
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        time_range = {
            "gte": start_time.isoformat(),
            "lte": end_time.isoformat()
        }
        
        # Get threat statistics
        stats = await siem.get_threat_statistics(time_range=time_range)
        
        # Process aggregation results
        severity_breakdown = {}
        for bucket in stats.get("severity_breakdown", {}).get("buckets", []):
            severity_breakdown[bucket["key"]] = bucket["doc_count"]
        
        threat_types = {}
        for bucket in stats.get("threat_types", {}).get("buckets", []):
            threat_types[bucket["key"]] = bucket["doc_count"]
        
        timeline = []
        for bucket in stats.get("timeline", {}).get("buckets", []):
            timeline.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        total_threats = sum(severity_breakdown.values())
        
        return ThreatStatisticsResponse(
            total_threats=total_threats,
            severity_breakdown=severity_breakdown,
            threat_types=threat_types,
            timeline=timeline,
            top_source_ips=[],  # Would need additional aggregation
            top_targets=[]      # Would need additional aggregation
        )
        
    except Exception as e:
        logger.error(f"Failed to get threat statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

@router.get("/statistics/alerts", response_model=AlertSummaryResponse)
async def get_alert_summary(
    hours: int = Query(24, description="Time range in hours"),
    siem: SIEMManager = Depends(get_siem_manager)
):
    """Get alert summary from SIEM"""
    try:
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        time_range = {
            "gte": start_time.isoformat(),
            "lte": end_time.isoformat()
        }
        
        # Search for alerts
        results = await siem.search_events(
            query={"term": {"event_type": "alert"}},
            time_range=time_range,
            size=1000
        )
        
        # Process results
        alerts = results.get("hits", {}).get("hits", [])
        total_alerts = len(alerts)
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        recent_alerts = []
        
        for hit in alerts[:10]:  # Get recent 10 alerts
            alert = hit["_source"]
            severity = alert.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            recent_alerts.append({
                "id": hit["_id"],
                "timestamp": alert.get("timestamp"),
                "severity": severity,
                "message": alert.get("message", ""),
                "source": alert.get("source", ""),
                "tags": alert.get("tags", [])
            })
        
        return AlertSummaryResponse(
            total_alerts=total_alerts,
            critical_alerts=severity_counts["critical"],
            high_alerts=severity_counts["high"],
            medium_alerts=severity_counts["medium"],
            low_alerts=severity_counts["low"],
            recent_alerts=recent_alerts
        )
        
    except Exception as e:
        logger.error(f"Failed to get alert summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get alert summary: {str(e)}")

@router.get("/dashboard/data")
async def get_dashboard_data(
    hours: int = Query(24, description="Time range in hours"),
    siem: SIEMManager = Depends(get_siem_manager)
):
    """Get comprehensive dashboard data from SIEM"""
    try:
        # Get threat statistics and alert summary in parallel
        threat_stats = await get_threat_statistics(hours, siem)
        alert_summary = await get_alert_summary(hours, siem)
        
        # Get recent high-priority events
        high_priority_events = await siem.search_events(
            query={
                "bool": {
                    "must": [
                        {"terms": {"severity": ["critical", "high"]}},
                        {"range": {
                            "timestamp": {
                                "gte": (datetime.utcnow() - timedelta(hours=hours)).isoformat()
                            }
                        }}
                    ]
                }
            },
            size=20
        )
        
        events = []
        for hit in high_priority_events.get("hits", {}).get("hits", []):
            event = hit["_source"]
            event["_id"] = hit["_id"]
            events.append(event)
        
        return {
            "threat_statistics": threat_stats.dict(),
            "alert_summary": alert_summary.dict(),
            "high_priority_events": events,
            "timestamp": datetime.utcnow().isoformat(),
            "time_range_hours": hours
        }
        
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")

@router.post("/events/bulk")
async def bulk_create_events(
    events: List[EventCreateRequest],
    siem: SIEMManager = Depends(get_siem_manager)
):
    """Bulk create security events in SIEM"""
    try:
        created_events = []
        
        for event_request in events:
            event = SecurityEvent(
                id="",  # Will be auto-generated
                timestamp=datetime.utcnow(),
                event_type=event_request.event_type,
                severity=event_request.severity,
                source=event_request.source,
                source_ip=event_request.source_ip,
                dest_ip=event_request.dest_ip,
                user=event_request.user,
                action=event_request.action,
                outcome=event_request.outcome,
                message=event_request.message,
                details=event_request.details or {},
                tags=event_request.tags or []
            )
            
            await siem.log_event(event)
            created_events.append(event.id)
        
        return {
            "status": "success",
            "message": f"Successfully created {len(created_events)} events",
            "event_ids": created_events
        }
        
    except Exception as e:
        logger.error(f"Failed to bulk create SIEM events: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk create failed: {str(e)}")

@router.get("/indices/status")
async def get_indices_status(siem: SIEMManager = Depends(get_siem_manager)):
    """Get status of SIEM indices"""
    try:
        # This would require direct Elasticsearch client access
        # For now, return basic status
        return {
            "status": "active",
            "indices": [
                {"name": "aurore-siem-threat", "status": "active", "docs": "unknown"},
                {"name": "aurore-siem-alert", "status": "active", "docs": "unknown"},
                {"name": "aurore-siem-network", "status": "active", "docs": "unknown"},
                {"name": "aurore-siem-system", "status": "active", "docs": "unknown"},
                {"name": "aurore-siem-user", "status": "active", "docs": "unknown"}
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get indices status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get indices status: {str(e)}")

# Function to initialize SIEM manager (called from main.py)
def initialize_siem_manager(config: Dict[str, Any]) -> SIEMManager:
    """Initialize the global SIEM manager"""
    global siem_manager
    siem_manager = SIEMManager(config)
    return siem_manager

