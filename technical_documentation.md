# Technical Documentation: VaultAdvisor Enterprise

## 1. System Architecture
VaultAdvisor Enterprise is structured into a multi-tiered institutional advisory architecture:

```
[ Client Interface / REST API Payload ]
                 |
                 v
   [ Tier 1: Threat Shield Guardrail ]  ---> (OWASP LLM01 Pattern Filter)
                 |
                 v
   [ Tier 2: PII Vault Tokenizer ]      ---> (SHA-256 Email & Custody Account Scrubbing)
                 |
                 v
   [ Tier 3: Quant Portfolio Engine ]   ---> (Markowitz MPT & MiFID II Compliance Bounds)
                 |
                 v
   [ Tier 4: Stochastic Simulator ]     ---> (Geometric Brownian Motion 1,000-Path Monte Carlo)
                 |
                 v
   [ Tier 5: Merkle Audit Chain ]       ---> (Immutable Cryptographic Ledger Root)
```

## 2. Core Quantitative Formulations

### Markowitz Modern Portfolio Theory (MPT) Optimization
Given expected asset returns vector mu and covariance matrix Sigma, the portfolio expected return mu_p and portfolio variance sigma_p^2 are given by:

mu_p = w^T * mu
sigma_p^2 = w^T * Sigma * w

Subject to weight constraints:
Sum(w_i) = 1, where 0 <= w_i <= 1 for all i in Assets {Cash, Bonds, Global Equities, Real Estate, Crypto}.

### MiFID II Regulatory Suitability Rule
For conservative profiles (Risk Score < 30):
w_Equities + w_Crypto <= 0.20

If violated, scaling factor lambda = 0.20 / (w_Equities + w_Crypto) is applied, reallocating excess weight into Cash buffers.

### Stochastic Monte Carlo Simulation (Geometric Brownian Motion)
Asset path trajectories follow S_t = S_{t-1} * exp((mu - 0.5 * sigma^2)*dt + sigma * sqrt(dt) * Z), where Z ~ N(0,1).

Percentiles calculated across 100 paths over investment horizon T years:
- P5: 5th percentile (Downside / Worst Case)
- P50: 50th percentile (Median / Expected Case)
- P95: 95th percentile (Upside / Best Case)

## 3. Cryptographic Verification
Each execution step generates a SHA-256 hash node:
- Layer 1 Hash: H1 = SHA256(Raw Input Prompt)
- Layer 2 Hash: H2 = SHA256(Masked PII Prompt)
- Layer 3 Hash: H3 = SHA256(Portfolio Allocation Weights)
- Layer 4 Hash: H4 = SHA256(Calculated Return & Risk Metrics)
- Merkle Root: Root = SHA256(H1 + H2 + H3 + H4)
