# API Service

The API service provides a RESTful interface for system management, status monitoring, and manual intervention. Built with FastAPI for high performance and auto-generated docs.

## Components

* `main.py`: FastAPI application with endpoints for health checks, metrics, mitigation controls, and configuration.

## Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /health | GET | System readiness and liveness probe |
| /metrics | GET | Current detection/mitigation metrics |
| /mitigation/actions | GET/POST | List/Trigger manual mitigation |
| /config/thresholds | GET/PUT | View/Update detection thresholds |
| /status | GET | Overall system status dashboard |

## Configuration

Uses `src/utils/config_loader.py` and `.env` for API_KEY auth.

```python
# Example usage
curl -H \"Authorization: Bearer $API_KEY\" http://localhost:8000/health
```

Integrates with Redis for state and direct service inspection. Swagger docs at /docs.
