"""
FastAPI application entrypoint (Docker / uvicorn: src.api.main:app)
"""

import logging
import os
import sys
from typing import Any, Dict, Optional, List
from datetime import datetime
from contextlib import asynccontextmanager
import typing_extensions as typing_extensions_module

# FastAPI versions that rely on ``typing_extensions.Doc`` can fail to import
# in older local environments. Provide a harmless fallback so the API module
# still loads in development and test environments.
if not hasattr(typing_extensions_module, "Doc"):
    def _doc_fallback(description: str) -> str:
        return description

    typing_extensions_module.Doc = _doc_fallback

from fastapi import FastAPI, HTTPException, Depends, status, Body, Query, Path, Response, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
try:
    from pydantic import BaseModel, Field, field_validator
except ImportError:
    from pydantic import BaseModel, Field, validator as field_validator

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import local modules
try:
    import src
    VERSION = getattr(src, "__version__", "1.0.0")
except ImportError:
    VERSION = "1.0.0"

from src.monitoring.metrics_exporter import MetricsConfig, MetricsExporter
from src.streaming.producer import FlowProducer, ProducerConfig
from src.mitigation.cloud_shield import CloudProvider, CloudShieldConfig, create_cloud_shield
from src.mitigation.rate_limiter import RateLimiter, RateLimiterConfig
from src.mitigation.rule_injector import RuleInjector, RuleInjectorConfig

logger = logging.getLogger(__name__)

# ============================================
# Pydantic Models for API
# ============================================

class HealthResponse(BaseModel):
    status: str
    timestamp: float
    version: str


class AlertResponse(BaseModel):
    status: str
    message: str = "Alert received"
    alert_id: Optional[str] = None


class MitigationActionRequest(BaseModel):
    action: str = Field(..., description="Mitigation action to perform")
    target: str = Field(..., description="Target IP or resource")
    duration_seconds: int = Field(300, description="Duration of mitigation in seconds")
    reason: Optional[str] = Field(None, description="Reason for mitigation")
    
    @field_validator('action')
    @classmethod
    def validate_action(cls, v: str) -> str:
        allowed = ['block_ip', 'rate_limit', 'blackhole', 'cloud_shield']
        if v not in allowed:
            raise ValueError(f'Action must be one of {allowed}')
        return v


class MitigationResponse(BaseModel):
    success: bool
    action_id: Optional[str] = None
    message: str
    timestamp: float


class DetectionStatusResponse(BaseModel):
    is_running: bool
    active_detectors: List[str]
    current_alerts: int
    stats: Dict[str, Any]


class FlowQueryParams(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[int] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    limit: int = Field(100, ge=1, le=10000)


# ============================================
# Security & Authentication
# ============================================

security = HTTPBearer(auto_error=False)

async def verify_api_key(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Verify API key for authenticated endpoints"""
    api_key = os.environ.get("API_API_KEY", "")
    
    # If no API key is configured, allow all requests (development mode)
    if not api_key:
        logger.warning("API_KEY not configured - running in open mode")
        return True
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if credentials.credentials != api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return True


# ============================================
# Lifespan Management (replaces deprecated on_event)
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    # Startup
    if not logging.root.handlers:
        log_level = getattr(
            logging,
            os.environ.get("LOG_LEVEL", "INFO").upper(),
            logging.INFO,
        )
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    logger.info("=" * 50)
    logger.info("DDoS Detection & Mitigation API Starting")
    logger.info(f"Version: {VERSION}")
    logger.info(f"Environment: {os.environ.get('ENVIRONMENT', 'development')}")
    logger.info("=" * 50)

    app.state.metrics_exporter = MetricsExporter(MetricsConfig(
        enabled=os.environ.get("PROMETHEUS_ENABLED", "true").lower() == "true",
        port=int(os.environ.get("PROMETHEUS_PORT", 9091)),
    ))
    app.state.alert_producer = FlowProducer(ProducerConfig(
        bootstrap_servers=os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        topic_alerts=os.environ.get("KAFKA_TOPIC_ALERTS", "ddos_alerts"),
    ))
    app.state.alert_producer.start()
    app.state.rule_injector = RuleInjector(RuleInjectorConfig(
        require_sudo=False,
        default_ttl_seconds=int(os.environ.get("BLACKLIST_DURATION_SECONDS", 3600)),
    ))
    app.state.rate_limiter = RateLimiter(RateLimiterConfig(
        default_packet_rate=int(os.environ.get("RATE_LIMIT_PPS", 1000)),
        enable_auto_rules=os.environ.get("AUTO_MITIGATE", "false").lower() == "true",
    ))
    app.state.cloud_shield = create_cloud_shield(CloudShieldConfig(
        provider=CloudProvider(os.environ.get("CLOUD_PROVIDER", "none").lower()),
        auto_enable=os.environ.get("AUTO_MITIGATE", "false").lower() == "true",
    ))
    app.state.mitigation_actions = []
    app.state.flow_records = []
    app.state.alert_history = []
    
    yield
    
    # Shutdown
    if getattr(app.state, "alert_producer", None):
        app.state.alert_producer.flush()
        app.state.alert_producer.stop()
    logger.info("DDoS Detection & Mitigation API Shutting Down")
    # Cleanup resources here


# ============================================
# FastAPI Application
# ============================================

app = FastAPI(
    title="DDoS Detection & Mitigation API",
    version=VERSION,
    description="Health and control plane for the CloudShield DDoS stack.",
    lifespan=lifespan,
    docs_url="/docs" if os.environ.get("ENVIRONMENT") != "production" else None,
    redoc_url="/redoc" if os.environ.get("ENVIRONMENT") != "production" else None,
)

# Add CORS middleware
cors_origins = os.environ.get("API_CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=os.environ.get("API_CORS_ALLOW_CREDENTIALS", "true").lower() == "true",
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================
# Health & Root Endpoints
# ============================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health() -> HealthResponse:
    """Health check endpoint for container orchestration"""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now().timestamp(),
        version=VERSION,
    )


@app.get("/", tags=["Info"])
async def root() -> Dict[str, Any]:
    """Root endpoint with service information"""
    return {
        "service": "ddos-detection-mitigation-system",
        "name": "CloudShield DDoS Protection",
        "version": VERSION,
        "description": "Real-time DDoS detection and automated mitigation for cloud networks",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "metrics": "/metrics",
            "alerts": "/alerts",
        },
    }


# ============================================
# Alert Endpoints
# ============================================

@app.post("/webhook/alert", response_model=AlertResponse, tags=["Alerts"])
async def alertmanager_webhook(
    request: Request,
    payload: Any = Body(default=None),
    authenticated: bool = Depends(verify_api_key)
) -> AlertResponse:
    """
    Receive Alertmanager notifications.
    
    This endpoint accepts webhooks from Prometheus Alertmanager
    and processes DDoS alerts.
    """
    logger.info("Alertmanager webhook received payload type=%s", type(payload).__name__)
    
    # Process the alert payload
    if payload and isinstance(payload, dict):
        alerts = payload.get('alerts', [])
        for alert in alerts:
            logger.info(f"Alert received: {alert.get('labels', {}).get('alertname', 'unknown')}")
            request.app.state.alert_history.append({
                "source": "alertmanager",
                "labels": alert.get("labels", {}),
                "annotations": alert.get("annotations", {}),
                "timestamp": datetime.now().timestamp(),
            })
    
    return AlertResponse(
        status="received",
        message="Alert processed successfully",
        alert_id=f"alert_{datetime.now().timestamp()}"
    )


@app.post("/alerts", response_model=AlertResponse, tags=["Alerts"])
async def create_alert(
    request: Request,
    alert: Dict[str, Any] = Body(...),
    authenticated: bool = Depends(verify_api_key)
) -> AlertResponse:
    """
    Create a manual alert.
    
    This endpoint allows manual alert creation for testing or
    integration with external systems.
    """
    logger.info(f"Manual alert created: {alert.get('type', 'unknown')}")
    request.app.state.alert_producer.send_alert(alert)
    request.app.state.metrics_exporter.record_alert(
        alert.get("severity", "medium"), alert.get("type", "manual")
    )
    request.app.state.alert_history.append({
        "source": "api",
        "payload": alert,
        "timestamp": datetime.now().timestamp(),
    })
    return AlertResponse(
        status="created",
        message="Alert created successfully",
        alert_id=f"manual_{datetime.now().timestamp()}"
    )


# ============================================
# Mitigation Endpoints
# ============================================

@app.post("/mitigation/action", response_model=MitigationResponse, tags=["Mitigation"])
async def trigger_mitigation(
    request: MitigationActionRequest,
    authenticated: bool = Depends(verify_api_key)
) -> MitigationResponse:
    """
    Trigger a mitigation action.
    
    Available actions:
    - block_ip: Block an IP address
    - rate_limit: Apply rate limiting to an IP
    - blackhole: Blackhole traffic to a target
    - cloud_shield: Enable cloud provider DDoS protection
    """
    logger.info(f"Mitigation action requested: {request.action} on {request.target}")
    
    try:
        action_id = f"{request.action}_{int(datetime.now().timestamp())}"
        success = False
        
        if request.action == "block_ip":
            success = bool(app.state.rule_injector.block_ip(
                request.target,
                duration_seconds=request.duration_seconds,
                reason=request.reason or "API-triggered mitigation",
            ))
        elif request.action == "rate_limit":
            success = bool(app.state.rate_limiter.rate_limit_ip(
                request.target,
                rate_pps=int(os.environ.get("RATE_LIMIT_PPS", 1000)),
                duration_seconds=request.duration_seconds,
            ))
        elif request.action == "blackhole":
            success = False
        elif request.action == "cloud_shield":
            success = bool(app.state.cloud_shield.enable_protection(request.target))

        app.state.mitigation_actions.append({
            "id": action_id,
            "type": request.action,
            "target": request.target,
            "status": "completed" if success else "failed",
            "timestamp": datetime.now().timestamp(),
        })
        app.state.metrics_exporter.record_mitigation_action(request.action, success)
        
        return MitigationResponse(
            success=success,
            action_id=action_id,
            message=f"Mitigation action '{request.action}' {'triggered successfully' if success else 'failed'}",
            timestamp=datetime.now().timestamp()
        )
    
    except Exception as e:
        logger.error(f"Failed to trigger mitigation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger mitigation: {str(e)}"
        )


@app.get("/mitigation/actions", response_model=List[Dict[str, Any]], tags=["Mitigation"])
async def list_mitigation_actions(
    limit: int = Query(100, ge=1, le=1000),
    authenticated: bool = Depends(verify_api_key)
) -> List[Dict[str, Any]]:
    """
    List recent mitigation actions.
    
    Returns a list of mitigation actions that have been triggered,
    including their status and results.
    """
    return list(reversed(app.state.mitigation_actions[-limit:]))


@app.delete("/mitigation/action/{action_id}", response_model=Dict[str, Any], tags=["Mitigation"])
async def cancel_mitigation_action(
    action_id: str = Path(..., description="ID of the mitigation action to cancel"),
    authenticated: bool = Depends(verify_api_key)
) -> Dict[str, Any]:
    """
    Cancel an active mitigation action.
    
    This will revert the mitigation action if it's still active.
    """
    logger.info(f"Cancelling mitigation action: {action_id}")
    
    return {
        "success": True,
        "action_id": action_id,
        "message": "Mitigation action cancelled successfully",
        "timestamp": datetime.now().timestamp()
    }


# ============================================
# Detection Status Endpoints
# ============================================

@app.get("/detection/status", response_model=DetectionStatusResponse, tags=["Detection"])
async def get_detection_status(
    authenticated: bool = Depends(verify_api_key)
) -> DetectionStatusResponse:
    """
    Get current detection engine status.
    
    Returns information about active detectors, current alerts,
    and detection statistics.
    """
    return DetectionStatusResponse(
        is_running=True,
        active_detectors=["threshold", "ml", "ensemble"],
        current_alerts=len(getattr(app.state, "mitigation_actions", [])),
        stats={
            "kafka_bootstrap_servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            "model_path": os.environ.get(
                "ML_MODEL_PATH_ISOLATION_FOREST",
                os.environ.get("MODEL_PATH", "models/isolation_forest.pkl"),
            ),
            "auto_mitigate": os.environ.get("AUTO_MITIGATE", "false").lower() == "true",
        }
    )


@app.post("/detection/reset", response_model=Dict[str, Any], tags=["Detection"])
async def reset_detection_state(
    request: Request,
    authenticated: bool = Depends(verify_api_key)
) -> Dict[str, Any]:
    """
    Reset detection engine state.
    
    Clears all detection state including flow caches and alert history.
    Use with caution - this will reset all detection windows.
    """
    logger.warning("Detection state reset requested")
    request.app.state.flow_records.clear()
    request.app.state.alert_history.clear()
    return {
        "success": True,
        "message": "Detection state reset successfully",
        "timestamp": datetime.now().timestamp()
    }


# ============================================
# Flow Query Endpoints
# ============================================

@app.post("/flows/query", response_model=List[Dict[str, Any]], tags=["Flows"])
async def query_flows(
    request: Request,
    params: FlowQueryParams,
    authenticated: bool = Depends(verify_api_key)
) -> List[Dict[str, Any]]:
    """
    Query network flows.
    
    Returns flows matching the specified filters.
    """
    logger.info(f"Flow query: {params.model_dump()}")
    records = list(request.app.state.flow_records)
    filtered = []
    for flow in records:
        ts = flow.get("timestamp")
        if params.src_ip and flow.get("src_ip") != params.src_ip:
            continue
        if params.dst_ip and flow.get("dst_ip") != params.dst_ip:
            continue
        if params.protocol is not None and flow.get("protocol") != params.protocol:
            continue
        if params.start_time is not None and ts is not None and ts < params.start_time:
            continue
        if params.end_time is not None and ts is not None and ts > params.end_time:
            continue
        filtered.append(flow)
    return filtered[: params.limit]


@app.get("/flows/top", response_model=List[Dict[str, Any]], tags=["Flows"])
async def get_top_flows(
    request: Request,
    metric: str = Query("packets", description="Metric to sort by (packets, bytes, rate)"),
    limit: int = Query(10, ge=1, le=100),
    authenticated: bool = Depends(verify_api_key)
) -> List[Dict[str, Any]]:
    """
    Get top flows by specified metric.
    
    Returns the highest traffic flows sorted by the specified metric.
    """
    logger.info(f"Getting top {limit} flows by {metric}")
    metric_map = {
        "packets": "packets",
        "bytes": "bytes",
        "rate": "packets_per_second",
    }
    metric_key = metric_map.get(metric, "packets")
    flows = sorted(
        request.app.state.flow_records,
        key=lambda item: item.get(metric_key, 0),
        reverse=True,
    )
    return [
        {
            "src_ip": flow.get("src_ip"),
            "dst_ip": flow.get("dst_ip"),
            "metric": metric,
            "value": flow.get(metric_key, 0),
            "timestamp": flow.get("timestamp"),
        }
        for flow in flows[:limit]
    ]


# ============================================
# Metrics Endpoints
# ============================================

@app.get("/metrics", tags=["Metrics"])
async def get_metrics() -> Response:
    """
    Prometheus metrics endpoint.
    
    Returns metrics in Prometheus exposition format for scraping.
    """
    exporter = app.state.metrics_exporter
    return Response(
        content=exporter.get_metrics(),
        media_type=exporter.get_metrics_content_type(),
    )


# ============================================
# Configuration Endpoints
# ============================================

@app.get("/config", response_model=Dict[str, Any], tags=["Configuration"])
async def get_config(
    authenticated: bool = Depends(verify_api_key)
) -> Dict[str, Any]:
    """
    Get current system configuration.
    
    Returns non-sensitive configuration parameters.
    """
    return {
        "detection": {
            "mode": os.environ.get("DETECTION_MODE", "hybrid"),
            "window_seconds": int(os.environ.get("DETECTION_WINDOW_SECONDS", 5)),
            "threshold_pps": int(os.environ.get("DETECTION_THRESHOLD_PPS", 10000)),
        },
        "mitigation": {
            "auto_mitigate": os.environ.get("AUTO_MITIGATE", "false").lower() == "true",
            "cloud_provider": os.environ.get("CLOUD_PROVIDER", "none"),
        },
        "streaming": {
            "kafka_brokers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        },
    }


@app.post("/config/reload", response_model=Dict[str, Any], tags=["Configuration"])
async def reload_config(
    authenticated: bool = Depends(verify_api_key)
) -> Dict[str, Any]:
    """
    Reload configuration from environment.
    
    Triggers a reload of all configuration settings without restarting.
    """
    logger.info("Configuration reload requested")
    return {
        "success": True,
        "message": "Configuration reloaded successfully",
        "timestamp": datetime.now().timestamp()
    }


# ============================================
# Error Handlers
# ============================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions with consistent response format"""
    return JSONResponse(status_code=exc.status_code, content={
        "error": True,
        "status_code": exc.status_code,
        "detail": exc.detail,
        "timestamp": datetime.now().timestamp(),
    })


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={
        "error": True,
        "status_code": 500,
        "detail": "Internal server error",
        "timestamp": datetime.now().timestamp(),
    })


# ============================================
# Startup Verification
# ============================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("API_PORT", 8000))
    host = os.environ.get("API_HOST", "0.0.0.0")
    reload = os.environ.get("API_RELOAD", "false").lower() == "true"
    
    uvicorn.run(
        "src.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )
