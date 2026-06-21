from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

app = FastAPI(
    title="ADSentinel API",
    version="1.0.0"
)

templates = Jinja2Templates(
    directory="api/templates"
)

FINDINGS_CACHE = []


@app.on_event("startup")
def startup_event():
    from api.cache import load_cache_from_file

    load_cache_from_file()


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "findings_loaded": len(FINDINGS_CACHE)
    }


@app.get("/findings")
def findings():
    return FINDINGS_CACHE


@app.get("/critical-findings")
def critical_findings():
    return [
        finding
        for finding in FINDINGS_CACHE
        if finding["risk_level"] == "Critical"
    ]


@app.get("/summary")
def summary():
    return get_summary()


@app.get("/top-risks")
def top_risks():
    return get_top_risks()


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    summary_data = get_summary()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "findings": FINDINGS_CACHE,
            "top_risks": get_top_risks(),
            "total_findings": summary_data["total_findings"],
            "critical": summary_data["critical"],
            "high": summary_data["high"],
            "medium": summary_data["medium"],
            "low": summary_data["low"]
        }
    )


def get_summary():
    critical = len(
        [
            finding
            for finding in FINDINGS_CACHE
            if finding["risk_level"] == "Critical"
        ]
    )

    high = len(
        [
            finding
            for finding in FINDINGS_CACHE
            if finding["risk_level"] == "High"
        ]
    )

    medium = len(
        [
            finding
            for finding in FINDINGS_CACHE
            if finding["risk_level"] == "Medium"
        ]
    )

    low = len(
        [
            finding
            for finding in FINDINGS_CACHE
            if finding["risk_level"] == "Low"
        ]
    )

    return {
        "total_findings": len(FINDINGS_CACHE),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }


def get_top_risks():
    return sorted(
        FINDINGS_CACHE,
        key=lambda finding: finding["risk_score"],
        reverse=True
    )[:10]