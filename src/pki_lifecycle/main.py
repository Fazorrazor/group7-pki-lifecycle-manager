"""
FastAPI application entrypoint for Group 7 Private PKI & Lifecycle Manager.
Implements strict security headers, structured routing, and input validation.
"""

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from pki_lifecycle.config import settings
from pki_lifecycle.validation.schemas import (
    CertificateIssueRequest,
    EndpointRegisterRequest,
    RevocationRequest,
)
from pki_lifecycle.database.repository import CertificateRepository
from pki_lifecycle.rendering.templates import SafeRenderer

app = FastAPI(
    title="Private PKI & Certificate Lifecycle Manager",
    description="Automated certificate lifecycle management, ACME integration, and TLS inventory.",
    version="0.1.0",
)

# In-memory or connected database repository instance
repo = CertificateRepository()


@app.middleware("http")
async def add_security_headers(request, call_next):
    """
    Applies security headers to every HTTP response as recommended by OWASP Secure Headers.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    return response


@app.get("/health", tags=["System"])
def health_check():
    """Healthcheck endpoint for container orchestration and uptime monitoring."""
    return {"status": "healthy", "environment": settings.environment}


@app.post("/api/v1/endpoints", status_code=status.HTTP_201_CREATED, tags=["Endpoints"])
def register_endpoint(payload: EndpointRegisterRequest):
    """Registers an internal TLS endpoint into the monitoring inventory."""
    try:
        endpoint_id = repo.add_endpoint(
            hostname=payload.hostname,
            port=payload.port,
            service_name=payload.service_name,
            environment=payload.environment,
        )
        return {
            "message": "Endpoint successfully registered",
            "endpoint_id": endpoint_id,
            "hostname": payload.hostname,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to register endpoint: {str(e)}",
        )


@app.post("/api/v1/certificates/revoke", tags=["Certificates"])
def revoke_certificate(payload: RevocationRequest):
    """Marks a certificate as revoked in the inventory and submits to OCSP responder."""
    success = repo.revoke_certificate(
        serial_number=payload.serial_number,
        reason=payload.reason.value,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate serial number not found in active inventory",
        )
    return {
        "status": "revoked",
        "serial_number": payload.serial_number,
        "reason": payload.reason.value,
    }


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
def get_dashboard():
    """Renders the administrative dashboard with auto-escaped dynamic data."""
    endpoints = repo.search_endpoints_by_service("")
    rows_html = "".join([SafeRenderer.render_endpoint_row(ep) for ep in endpoints])

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Group 7 PKI & Certificate Lifecycle Manager</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }}
            h1 {{ color: #38bdf8; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; background: #1e293b; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }}
            th {{ background: #334155; color: #94a3b8; font-weight: 600; }}
            .badge {{ display: inline-block; padding: 4px 8px; font-size: 12px; border-radius: 4px; text-transform: uppercase; }}
            .badge-lab {{ background: #0284c7; color: white; }}
        </style>
    </head>
    <body>
        <h1>🔐 PKI Certificate Lifecycle Dashboard (Group 7)</h1>
        <p>Two-tier PKI, Automated ACME Renewal, and Real-Time TLS Compliance Grading.</p>
        
        <h2>Monitored Lab Endpoints</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Hostname</th>
                    <th>Port</th>
                    <th>Service Name</th>
                    <th>Environment</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if rows_html else "<tr><td colspan='5'>No endpoints registered yet.</td></tr>"}
            </tbody>
        </table>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
