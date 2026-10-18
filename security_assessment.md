# Security Self-Assessment Report

## 1. Permission-Tier Implementation

### Tier 1: Input Threat Guardrail
- Publicly accessible input processing layer.
- Enforces strict string pattern matching for prompt injection attack vectors (OWASP LLM01).
- Instantly rejects malicious requests with HTTP 400 error codes without exposing backend resources.

### Tier 2: Privacy Vault (PII Safeguard)
- Automatically intercepts Personally Identifiable Information (PII), specifically email addresses and bank custody account numbers.
- Replaces raw data with deterministic SHA-256 tokens (`[SECURE_EMAIL_TOKEN_...]`, `[SECURE_ACCOUNT_TOKEN_...]`) prior to execution.

### Tier 3: Regulatory Compliance Engine
- Applies MiFID II suitability rules automatically based on client risk scoring.
- Overrides aggressive weights for low-risk clients to guarantee regulatory compliance.

### Tier 4: Immutable Audit Logging
- Hashing layer using SHA-256 cryptographic trees.
- Outputs Merkle Root hashes to provide tamper-proof evidence for internal compliance officers and external auditors.

## 2. Known-Risk Matrix and Mitigation Strategies

| Vulnerability Vector | Severity | Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| OWASP LLM01 Prompt Injection | High | Pre-execution heuristic scanner blocking adversarial instruction overrides. | Verified |
| PII Data Exposure | High | Regex tokenization vaulting emails and account numbers before processing. | Verified |
| Portfolio Suitability Violation | Medium | Hard-coded MiFID II capping rules for low risk scores. | Verified |
| Audit Trail Tampering | Low | SHA-256 Merkle chain verification establishing execution non-repudiation. | Verified |
