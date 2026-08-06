"""
SecureAI REST API — FastAPI application.

Endpoints:
  POST /api/v1/scan/snippet     → Scan a code snippet (synchronous, < 5s)
  POST /api/v1/scan/repo        → Submit a repo path for full scan (async job)
  GET  /api/v1/scan/{job_id}    → Get scan job status and results
  POST /api/v1/fix/generate     → Generate AI fix for a finding
  POST /api/v1/search           → Semantic code search
  GET  /api/v1/health           → Health check
  GET  /api/v1/stats            → System stats

Architecture:
  - Synchronous scan (< 1K LoC): run inline
  - Async scan (larger repos): enqueue to Celery, return job_id
  - All results stored in PostgreSQL
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import BaseModel, Field

from api.rest.scanner import ScannerService
from api.rest.fix_service import FixService
from api.rest.search_service import SearchService

# ──────────────────────────────────────────────
# App Setup
# ──────────────────────────────────────────────

app = FastAPI(
    title="SecureAI API",
    description="AI-powered security vulnerability detection, fix generation, and semantic code search",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────
# Request / Response Models
# ──────────────────────────────────────────────

class SnippetScanRequest(BaseModel):
    code: str = Field(..., description="Source code to analyze", min_length=10)
    language: str = Field(..., description="Programming language", pattern="^(python|javascript|java|go|cpp)$")
    filename: str = Field(default="<snippet>", description="Optional filename for context")

    model_config = {"json_schema_extra": {
        "example": {
            "code": "def get_user(user_id):\n    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n    return db.execute(query)",
            "language": "python",
            "filename": "auth.py"
        }
    }}


class RepoScanRequest(BaseModel):
    repo_path: str = Field(..., description="Absolute path to repository")
    languages: list[str] = Field(default=["python", "javascript"])
    severity_threshold: str = Field(default="LOW", pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    max_files: int = Field(default=500, ge=1, le=10000)


class FixGenerateRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID from scan results")
    vulnerable_code: str = Field(..., min_length=10)
    language: str
    cwe_id: str
    severity: str
    taint_path: str = Field(default="")
    num_candidates: int = Field(default=3, ge=1, le=5)


class SearchRequest(BaseModel):
    query: str = Field(..., description="Natural language search query", min_length=5)
    repo_path: str = Field(..., description="Repository path to search")
    top_k: int = Field(default=10, ge=1, le=50)
    language: str | None = None


class VulnerabilityFindingResponse(BaseModel):
    finding_id: str
    function_name: str
    file_path: str
    line_start: int
    line_end: int
    cwe_id: str
    severity: str
    description: str
    fix_suggestion: str
    confidence: float
    cvss_estimate: float


class ScanResponse(BaseModel):
    scan_id: str
    status: str          # pending | running | completed | failed
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    findings: list[VulnerabilityFindingResponse]
    scan_duration_ms: float
    files_scanned: int


class FixResponse(BaseModel):
    finding_id: str
    candidates: list[str]
    recommended_fix: str
    explanation: str


class SearchResult(BaseModel):
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    relevance_score: float
    code_preview: str
    vulnerability_match: str | None


class CVEResponse(BaseModel):
    cve_id: str
    description: str
    published_date: str | None
    cvss_score: float | None
    cwe_nodes: list[str] = []


# ──────────────────────────────────────────────
# Dependency Injection
# ──────────────────────────────────────────────

_scanner: ScannerService | None = None
_fix_service: FixService | None = None
_search_service: SearchService | None = None


def get_scanner() -> ScannerService:
    global _scanner
    if _scanner is None:
        _scanner = ScannerService()
    return _scanner


def get_fix_service() -> FixService:
    global _fix_service
    if _fix_service is None:
        _fix_service = FixService()
    return _fix_service


def get_search_service() -> SearchService:
    global _search_service
    if _search_service is None:
        _search_service = SearchService()
    return _search_service


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.get("/api/v1/health", tags=["System"])
async def health_check():
    """Health check endpoint for load balancers and monitoring."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "timestamp": time.time(),
    }


@app.get("/api/v1/stats", tags=["System"])
async def get_stats(scanner: ScannerService = Depends(get_scanner)):
    """System statistics: models loaded, scans performed, etc."""
    return await scanner.get_stats()


@app.post(
    "/api/v1/scan/snippet",
    response_model=ScanResponse,
    tags=["Scanning"],
    summary="Scan a code snippet for vulnerabilities",
)
async def scan_snippet(
    request: SnippetScanRequest,
    scanner: ScannerService = Depends(get_scanner),
):
    """
    Synchronously scan a code snippet.

    Returns vulnerability findings within ~2 seconds for snippets < 500 lines.
    For larger code, use the /scan/repo endpoint.
    """
    start_time = time.time()
    scan_id = str(uuid.uuid4())

    try:
        findings = await scanner.scan_snippet(
            code=request.code,
            language=request.language,
            filename=request.filename,
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    duration_ms = (time.time() - start_time) * 1000
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    finding_responses = [
        VulnerabilityFindingResponse(
            finding_id=f"{scan_id}_{i}",
            function_name=f.function_name,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            cwe_id=f.cwe.value,
            severity=f.severity.value,
            description=f.description,
            fix_suggestion=f.fix_suggestion or "",
            confidence=f.confidence,
            cvss_estimate=f.cvss_estimate,
        )
        for i, f in enumerate(findings)
    ]

    return ScanResponse(
        scan_id=scan_id,
        status="completed",
        total_findings=len(findings),
        critical=severity_counts.get("CRITICAL", 0),
        high=severity_counts.get("HIGH", 0),
        medium=severity_counts.get("MEDIUM", 0),
        low=severity_counts.get("LOW", 0),
        findings=finding_responses,
        scan_duration_ms=duration_ms,
        files_scanned=1,
    )


@app.post(
    "/api/v1/scan/repo",
    tags=["Scanning"],
    summary="Submit a repository for full security scan (async)",
)
async def scan_repo(
    request: RepoScanRequest,
    background_tasks: BackgroundTasks,
    scanner: ScannerService = Depends(get_scanner),
):
    """
    Submit a repository for asynchronous scanning.

    Returns a job_id immediately. Poll /scan/{job_id} for results.
    Large repos (100K+ LoC) may take 2–5 minutes.
    """
    repo_path = Path(request.repo_path)
    if not repo_path.exists():
        raise HTTPException(status_code=404, detail=f"Repository not found: {request.repo_path}")

    job_id = str(uuid.uuid4())
    background_tasks.add_task(
        scanner.scan_repo_async,
        job_id=job_id,
        repo_path=repo_path,
        languages=request.languages,
        severity_threshold=request.severity_threshold,
        max_files=request.max_files,
    )

    return {
        "job_id": job_id,
        "status": "pending",
        "message": f"Scan started for {request.repo_path}. Poll /api/v1/scan/{job_id} for results.",
    }


@app.get(
    "/api/v1/scan/{job_id}",
    response_model=ScanResponse,
    tags=["Scanning"],
    summary="Get scan job status and results",
)
async def get_scan_results(
    job_id: str,
    scanner: ScannerService = Depends(get_scanner),
):
    """Get the current status and results of an async scan job."""
    result = await scanner.get_job_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    return result


@app.post(
    "/api/v1/fix/generate",
    response_model=FixResponse,
    tags=["Fix Generation"],
    summary="Generate AI-powered fix for a vulnerability",
)
async def generate_fix(
    request: FixGenerateRequest,
    fix_service: FixService = Depends(get_fix_service),
):
    """
    Generate N candidate fixes for a detected vulnerability.

    Uses the fine-tuned StarCoderBase-1B model with RLHF to produce
    contextually appropriate, security-correct patches.
    """
    try:
        candidates = await fix_service.generate(
            finding_id=request.finding_id,
            vulnerable_code=request.vulnerable_code,
            language=request.language,
            cwe_id=request.cwe_id,
            severity=request.severity,
            taint_path=request.taint_path,
            num_candidates=request.num_candidates,
        )
    except Exception as e:
        logger.error(f"Fix generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Fix generation failed: {str(e)}")

    return FixResponse(
        finding_id=request.finding_id,
        candidates=candidates["candidates"],
        recommended_fix=candidates["recommended"],
        explanation=candidates["explanation"],
    )


@app.post(
    "/api/v1/search",
    response_model=list[SearchResult],
    tags=["Semantic Search"],
    summary="Semantic code search using natural language",
)
async def semantic_search(
    request: SearchRequest,
    search_service: SearchService = Depends(get_search_service),
):
    """
    Search a codebase using natural language queries.

    Examples:
      - "find all SQL queries built with string concatenation"
      - "show me where user input reaches os.system or subprocess"
      - "find eval() calls with user-controlled data"
      - "locate all pickle.loads calls"
    """
    results = await search_service.search(
        query=request.query,
        repo_path=request.repo_path,
        top_k=request.top_k,
        language=request.language,
    )
    return results


@app.get(
    "/api/v1/cve/{cve_id}",
    response_model=CVEResponse,
    tags=["Knowledge Base"],
    summary="Get detailed information about a specific CVE",
)
async def get_cve_details(cve_id: str):
    """
    Fetch details for a specific CVE from the Neo4j Knowledge Graph.
    Includes CVSS scores, descriptions, and linked CWE taxonomy.
    """
    # Placeholder for Neo4j lookup (will connect to NVDSyncEngine / Knowledge Base later)
    # In a full implementation, we would query the Neo4j driver here.
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Invalid CVE ID format. Must start with 'CVE-'")
        
    return CVEResponse(
        cve_id=cve_id.upper(),
        description="Placeholder description for the requested CVE. Data is synced from NVD.",
        published_date="2024-01-01",
        cvss_score=7.5,
        cwe_nodes=["CWE-89"]
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.rest.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
