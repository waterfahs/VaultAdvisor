import math
import random
import hashlib
import json
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse

app = FastAPI(
    title="VaultAdvisor Enterprise Quant & Security Engine",
    description="Institutional Quantitative Advisory and Governance Engine for FinTechathon 2026",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ASSETS = ["Cash", "Bonds", "Global Equities", "Real Estate", "Crypto"]
EXPECTED_RETURNS = [0.030, 0.045, 0.090, 0.065, 0.180]

STRESS_SCENARIOS = {
    "2008 Financial Crisis Shock": {"Cash": 0.01, "Bonds": 0.05, "Global Equities": -0.38, "Real Estate": -0.25, "Crypto": -0.50},
    "2020 COVID Market Crash": {"Cash": 0.00, "Bonds": 0.02, "Global Equities": -0.20, "Real Estate": -0.15, "Crypto": -0.30},
    "High Inflation / Stagflation": {"Cash": -0.05, "Bonds": -0.08, "Global Equities": -0.05, "Real Estate": 0.08, "Crypto": 0.15}
}

class AdvisoryRequest(BaseModel):
    client_name: str
    client_email: str
    client_phone: str
    account_number: str
    initial_capital: float
    monthly_contribution: float
    horizon_years: int
    risk_score: int
    advisory_message: str

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def scan_threats(message: str) -> Dict[str, Any]:
    threat_patterns = [
        r"ignore (all\s+)?prior\s+(instructions|rules)",
        r"you are now (an\s+)?unrestricted",
        r"system prompt",
        r"bypass security",
        r"guarantee\s+(\d+%)?\s*(profit|return)"
    ]
    for pattern in threat_patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return {"detected": True, "reason": f"OWASP LLM01 threat vector blocked matching pattern: '{pattern}'"}
    return {"detected": False, "reason": None}

def tokenize_pii(message: str) -> Dict[str, Any]:
    masked = message
    count = 0
    email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    acct_regex = r'\b\d{10,12}\b'

    emails = re.findall(email_regex, masked)
    for email in emails:
        token = f"[SECURE_EMAIL_TOKEN_{sha256_hash(email)[:8].upper()}]"
        masked = masked.replace(email, token)
        count += 1

    accts = re.findall(acct_regex, masked)
    for acct in accts:
        token = f"[SECURE_ACCOUNT_TOKEN_{sha256_hash(acct)[:8].upper()}]"
        masked = masked.replace(acct, token)
        count += 1

    return {"masked_text": masked, "mask_count": count}

def optimize_markowitz(risk_score: int) -> Dict[str, Any]:
    if risk_score < 30:
        alloc = {"Cash": 0.35, "Bonds": 0.45, "Global Equities": 0.12, "Real Estate": 0.08, "Crypto": 0.00}
    elif risk_score < 75:
        alloc = {"Cash": 0.05, "Bonds": 0.30, "Global Equities": 0.40, "Real Estate": 0.18, "Crypto": 0.07}
    else:
        alloc = {"Cash": 0.02, "Bonds": 0.10, "Global Equities": 0.55, "Real Estate": 0.18, "Crypto": 0.15}

    overridden = False
    if risk_score < 30:
        high_risk_sum = alloc["Global Equities"] + alloc["Crypto"]
        if high_risk_sum > 0.20:
            scale = 0.20 / high_risk_sum
            alloc["Global Equities"] *= scale
            alloc["Crypto"] *= scale
            alloc["Cash"] += (1.0 - sum(alloc.values()))
            overridden = True

    mu = sum(alloc[asset] * EXPECTED_RETURNS[i] for i, asset in enumerate(ASSETS))
    sigma = 0.08 + (risk_score / 100.0) * 0.10
    return {"allocations": alloc, "mu": mu, "sigma": sigma, "overridden": overridden}

def run_monte_carlo(initial_cap: float, monthly_contrib: float, horizon_years: int, mu: float, sigma: float):
    dt = 1 / 12.0
    steps = horizon_years * 12
    num_paths = 100
    paths = []

    for _ in range(num_paths):
        path = [initial_cap]
        for _ in range(steps):
            z = random.gauss(0, 1)
            prev = path[-1]
            growth = math.exp((mu - 0.5 * sigma ** 2) * dt + sigma * math.sqrt(dt) * z)
            path.append(prev * growth + monthly_contrib)
        paths.append(path)

    final_vals = sorted([p[-1] for p in paths])
    return {
        "p5": final_vals[int(num_paths * 0.05)],
        "p50": final_vals[int(num_paths * 0.50)],
        "p95": final_vals[int(num_paths * 0.95)]
    }

@app.post("/api/v1/analyze")
async def analyze_portfolio(req: AdvisoryRequest):
    threat = scan_threats(req.advisory_message)
    if threat["detected"]:
        raise HTTPException(status_code=400, detail=threat["reason"])

    pii = tokenize_pii(req.advisory_message)
    quant = optimize_markowitz(req.risk_score)
    allocations = quant["allocations"]
    mu = quant["mu"]
    sigma = quant["sigma"]

    mc = run_monte_carlo(req.initial_capital, req.monthly_contribution, req.horizon_years, mu, sigma)

    sharpe = round((mu - 0.025) / sigma, 2)
    var95 = round(sigma * 1.645 * 100, 2)
    max_dd = round(sigma * 2.1 * 100, 2)

    stress_results = {}
    for scenario, shocks in STRESS_SCENARIOS.items():
        impact = sum(allocations[a] * shocks.get(a, 0.0) for a in ASSETS)
        stress_results[scenario] = round(impact * 100, 2)

    h1 = sha256_hash(f"1_raw_input:{req.advisory_message}")
    h2 = sha256_hash(f"2_masked_input:{pii['masked_text']}")
    h3 = sha256_hash(f"3_portfolio:{json.dumps(allocations)}")
    h4 = sha256_hash(f"4_metrics:mu={mu};sharpe={sharpe}")
    merkle_root = sha256_hash(h1 + h2 + h3 + h4)

    return {
        "status": "success",
        "pii_vault": pii,
        "quant_metrics": {
            "expected_return": round(mu * 100, 2),
            "sharpe_ratio": sharpe,
            "var_95": var95,
            "max_drawdown": max_dd,
            "mifid_override": quant["overridden"]
        },
        "allocations": allocations,
        "monte_carlo_projections": mc,
        "stress_tests": stress_results,
        "merkle_audit_chain": {
            "layer_1_input_hash": h1,
            "layer_2_pii_hash": h2,
            "layer_3_alloc_hash": h3,
            "layer_4_metrics_hash": h4,
            "merkle_root": merkle_root
        }
    }

@app.get("/")
async def serve_ui():
    return FileResponse("vault_advisor_ui.html")
