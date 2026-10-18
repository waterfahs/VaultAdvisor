# VaultAdvisor Enterprise - Quantitative Advisory and Governance Engine

An institutional-grade Wealth Advisory Agent built for the 2026 Shenzhen International FinTech Competition (FinTechathon - Topic B: Wealth Advisory Agent).

## Overview
VaultAdvisor Enterprise combines quantitative portfolio optimization, AI guardrail threat mitigation, privacy tokenization, stochastic Monte Carlo projections, and cryptographic audit ledgers into a unified platform.

## Architecture and Core Modules
1. Security Gate (Threat Shield & PII Tokenizer): Intercepts OWASP LLM01 injection vectors and tokenizes client email and custody account numbers via SHA-256 tokens.
2. Quantitative Optimization Engine: Markowitz Modern Portfolio Theory (MPT) asset allocation with MiFID II regulatory constraint enforcement.
3. Stochastic Engine: Geometric Brownian Motion (GBM) Monte Carlo simulation generating 1,000 statistical trajectories (P5, P50, P95 percentiles).
4. Explainable AI (XAI) Module: Transparent attribution explanation linking client risk tolerance to tactical weights.
5. Cryptographic Merkle Audit Chain: Multi-layer SHA-256 hashing establishing an immutable log root for full regulatory verification.

## Repository File Structure
- app.py: FastAPI REST Engine & Web Server
- vault_advisor_ui.html: Single-page Enterprise Dark-mode Interface
- requirements.txt: Dependency manifest
- technical_documentation.md: Comprehensive System Architecture & Algorithmic Formulation
- security_assessment.md: Security Permission Tiers & Risk Mitigation Matrix
- execution_evidence.json: Execution Sandbox Verification Output

## Deployment Instructions

### Prerequisites
- Python 3.9 or higher

### Installation & Local Run
1. Install dependencies:
   pip install -r requirements.txt

2. Launch backend engine:
   uvicorn app:app --reload --port 8000

3. Access interface:
   Open http://localhost:8000 in your browser.

## Verified Test Cases
- Test Case 1 (Balanced Portfolio): Risk Score = 50 -> Target Return ~7.20%, Sharpe ~0.36, MiFID II Compliant.
- Test Case 2 (Conservative & MiFID II Override): Risk Score = 10 -> High-risk asset ceiling enforced <= 20%.
- Test Case 3 (Security Threat Interception): Prompt containing 'ignore all prior instructions' -> Trigger 400 Exception (OWASP LLM01 Threat Blocked).
- Test Case 4 (PII Scrubbing): Raw prompt containing email/account -> Converted to secure tokenized strings.
