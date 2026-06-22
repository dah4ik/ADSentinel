import json
import os

from fastapi import Depends
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from api.auth import login_for_access_token
from api.auth import require_roles

app = FastAPI(
    title="ADSentinel API",
    version="1.0.0"
)

templates = Jinja2Templates(
    directory="api/templates"
)

FINDINGS_CACHE = []

COMPARISON_FILE = "output/json/scan_comparison.json"


@app.on_event("startup")
def startup_event():
    from api.cache import load_cache_from_file

    load_cache_from_file()


@app.post("/auth/login")
def login(
        token_data=Depends(login_for_access_token)
):
    return token_data


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "findings_loaded": len(FINDINGS_CACHE)
    }


@app.get("/findings")
def findings(
        current_user=Depends(
            require_roles(
                [
                    "admin",
                    "auditor",
                    "viewer"
                ]
            )
        )
):
    return FINDINGS_CACHE


@app.get("/critical-findings")
def critical_findings(
        current_user=Depends(
            require_roles(
                [
                    "admin",
                    "auditor",
                    "viewer"
                ]
            )
        )
):
    return [
        finding
        for finding in FINDINGS_CACHE
        if finding["risk_level"] == "Critical"
    ]


@app.get("/summary")
def summary(
        current_user=Depends(
            require_roles(
                [
                    "admin",
                    "auditor",
                    "viewer"
                ]
            )
        )
):
    return get_summary()


@app.get("/top-risks")
def top_risks(
        current_user=Depends(
            require_roles(
                [
                    "admin",
                    "auditor",
                    "viewer"
                ]
            )
        )
):
    return get_top_risks()


@app.get("/history/comparison")
def history_comparison(
        current_user=Depends(
            require_roles(
                [
                    "admin",
                    "auditor"
                ]
            )
        )
):
    return load_comparison()


@app.get("/admin/status")
def admin_status(
        current_user=Depends(
            require_roles(
                [
                    "admin"
                ]
            )
        )
):
    return {
        "status": "admin access granted",
        "loaded_findings": len(FINDINGS_CACHE)
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(
        request: Request
):
    summary_data = get_summary()
    comparison = load_comparison()

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
            "low": summary_data["low"],
            "comparison": comparison
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


def load_comparison():
    if not os.path.exists(COMPARISON_FILE):
        return {
            "previous_total": 0,
            "current_total": len(FINDINGS_CACHE),
            "new_findings": 0,
            "resolved_findings": 0,
            "new_critical": 0,
            "new_high": 0,
            "resolved_critical": 0,
            "resolved_high": 0,
            "new_findings_details": [],
            "resolved_findings_details": []
        }

    with open(
            COMPARISON_FILE,
            "r",
            encoding="utf-8"
    ) as file:
        return json.load(file)