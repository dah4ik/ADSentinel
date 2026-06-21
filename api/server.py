from fastapi import FastAPI

app = FastAPI(
    title="ADSentinel API",
    version="1.0.0"
)

FINDINGS_CACHE = []


@app.get("/health")
def health():
    return {
        "status": "healthy"
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


@app.get("/top-risks")
def top_risks():

    return sorted(
        FINDINGS_CACHE,
        key=lambda finding: finding["risk_score"],
        reverse=True
    )[:10]