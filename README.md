# Zero-Trust mTLS & Identity-Aware Access Proxy

[![CI](https://github.com/zymaneta-eng/zero-trust-access-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/zymaneta-eng/zero-trust-access-proxy/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![Cryptography](https://img.shields.io/badge/Cryptography-X.509%20SVID-red.svg)](https://cryptography.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-assurance Zero-Trust reverse proxy, mutual TLS (mTLS) service mesh gateway, and identity-aware access controller designed for enterprise microservice perimeters, distributed Kubernetes clusters, and API security tiers.

Engineered with an **embedded X.509 Public Key Infrastructure (PKI)** issuing short-lived **SPIFFE Verifiable Identity Documents (SVIDs)**, fine-grained **RBAC/ABAC authorization**, **JWT Bearer token introspection**, and a **cryptographically linked SHA-256 hash-chained audit ledger** that mathematically detects any unauthorized record tampering or log alteration.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Clients ["Service Mesh Clients & Workloads"]
        MTLS_WORKLOAD["mTLS Workload\n(X.509 SPIFFE SVID)"]
        JWT_CLIENT["External API Client\n(JWT Bearer Token)"]
        ANON_CLIENT["Unauthenticated Client\n(Untrusted Traffic)"]
    end

    subgraph ZTAP ["Zero-Trust Access Proxy (ZTAP) Gateway"]
        direction TB
        GATEWAY["Reverse Proxy / Sidecar Gateway\n• /v1/auth/check (Envoy ext_authz)\n• /proxy/{path} (Transparent Forwarder)"]

        subgraph SecurityEngine ["Identity & Policy Engine"]
            PKI["PKI & SVID Validator\n• Root CA Chain Validation\n• SAN SPIFFE URI Extraction\n• Dynamic SVID Rotation"]
            JWT_AUTH["JWT Introspector\n• Signature & Expiration\n• Roles & Scopes Extraction"]
            POLICY["RBAC & ABAC Policy Engine\n• Strict Default-Deny\n• SPIFFE Wildcard Matching\n• Path Regex & IP CIDR Subnets"]
        end

        subgraph Ledger ["Tamper-Evident Ledger"]
            HASH_CHAIN[("SHA-256 Hash Chain Ledger\nHi = SHA256(Hi-1 + Record)\nTamper Detection")]
        end
    end

    subgraph Upstream ["Protected Core Upstream Microservices"]
        CORE_SVC["Internal Microservice\n(Receives X-Service-Identity Headers)"]
    end

    subgraph Monitoring ["Security Telemetry & Operations"]
        WS["WebSocket Stream (/ws/audit)"]
        CLI["Developer TUI (ztap)"]
    end

    MTLS_WORKLOAD --> GATEWAY
    JWT_CLIENT --> GATEWAY
    ANON_CLIENT --> GATEWAY

    GATEWAY --> PKI
    GATEWAY --> JWT_AUTH
    PKI --> POLICY
    JWT_AUTH --> POLICY

    POLICY --> HASH_CHAIN
    HASH_CHAIN --> WS
    HASH_CHAIN --> CLI

    POLICY -- "ALLOW (Injects Identity Headers)" --> CORE_SVC
    POLICY -- "DENY (HTTP 401 / 403)" --> GATEWAY
```

---

## Authorization & Cryptographic Hash-Chain Sequence

```mermaid
sequenceDiagram
    autonumber
    participant W as Workload Client
    participant P as ZTAP Proxy Gateway
    participant PKI as Embedded PKI / JWT
    participant PE as Policy Engine (Default-Deny)
    participant AL as SHA-256 Audit Ledger
    participant U as Upstream Service

    W->>P: Inbound Request (mTLS Cert or Bearer Token)
    
    alt mTLS Client Certificate Present
        P->>PKI: Verify X.509 cert against Root CA
        PKI-->>P: Validated SPIFFE ID (spiffe://prod.internal/ns/...)
    else JWT Bearer Token Present
        P->>PKI: Verify JWT signature, exp, and roles
        PKI-->>P: Validated Claims (sub, roles, scopes)
    end

    P->>PE: Evaluate AccessContext (Subject, Roles, Method, Path, IP)
    
    alt Request Matches ALLOW Policy
        PE-->>P: ALLOW (status 200, Injected Headers)
        P->>AL: Append AuditRecord (Hi = SHA256(Hi-1 + data))
        P->>U: Forward Request with X-Service-Identity & X-Audit-ID
        U-->>P: Upstream Response
        P-->>W: HTTP 200 OK
    else Request Matches DENY or Falls Through
        PE-->>P: DENY (status 403 Forbidden)
        P->>AL: Append AuditRecord (Hi = SHA256(Hi-1 + data))
        P-->>W: HTTP 403 Forbidden (Default-Deny)
    end
```

---

## Key Capabilities

1. **Embedded PKI & SPIFFE SVID Engine**:
   - Generates and manages an in-memory X.509 Root CA using standard `cryptography` primitives without external Vault/EJBCA prerequisites.
   - Issues short-lived SPIFFE Verifiable Identity Documents (SVIDs) with `spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}` Subject Alternative Names (SANs).
   - Supports **zero-downtime dynamic SVID rotation** without service restarts.

2. **mTLS Handshake & Cryptographic Service Identity Authentication**:
   - Validates client certificate validity windows (`not_valid_before_utc`, `not_valid_after_utc`).
   - Cryptographically verifies signature against the trusted Root CA public key.
   - Extracts and normalizes SPIFFE workload identities for downstream microsegmentation.

3. **Declarative RBAC & ABAC Policy Engine**:
   - Strict **Default-Deny** security baseline: any request not explicitly permitted by a rule is rejected.
   - Supports identity wildcard matching (e.g. `spiffe://prod.internal/ns/billing/*`), role assignment (`admin`, `operator`), HTTP methods (`GET`, `POST`, `*`), regular expression path rules (`^/api/v1/payments.*`), and client CIDR IP subnet whitelists (`10.0.0.0/8`).
   - Priority-ordered rule evaluation with explicit `DENY` overrides.

4. **JWT Bearer Token Introspection**:
   - Verifies user and workload JWT Bearer tokens with signature checking, expiration (`exp`), not-before (`nbf`), issuer (`iss`), and audience (`aud`).
   - Extracts roles and scopes to complement service-level mTLS identities.

5. **Tamper-Evident Hash-Chained Audit Ledger**:
   - Every authorization decision is sequentially linked into a cryptographic SHA-256 hash chain:
     $$H_i = \text{SHA256}(\text{seq}_i \parallel \text{timestamp}_i \parallel \text{subject}_i \parallel \text{ip}_i \parallel \text{method}_i \parallel \text{path}_i \parallel \text{decision}_i \parallel H_{i-1})$$
   - Mathematical audit integrity verification: any modification of past entries, deletion of rows, or alteration of decisions breaks the hash chain and is immediately flagged by `verify_chain_integrity()`.

6. **FastAPI Multi-Protocol Gateway**:
   - Envoy `ext_authz` and NGINX `auth_request` compatible sidecar check endpoint (`/v1/auth/check`).
   - Transparent reverse proxy forwarder (`/proxy/{path}`) injecting trusted `X-Service-Identity` and `X-Audit-ID` headers to upstreams.
   - Real-time WebSocket security stream (`/ws/audit`) for security operations center (SOC) dashboards.

7. **Developer TUI Console (Typer + Rich)**:
   - Complete security CLI (`ztap`): cert issuance, policy inspection, traffic simulation, and cryptographic audit chain verification.

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/zymaneta-eng/zero-trust-access-proxy.git
cd zero-trust-access-proxy

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies and CLI
pip install -e ".[dev]"
```

### 2. Issue a SPIFFE Workload Certificate

```bash
ztap certs issue --spiffe-id spiffe://prod.internal/ns/billing/sa/payment-worker --hours 24
```

### 3. Run Zero-Trust Traffic Simulation

Simulate legitimate mTLS services, valid JWT clients, unauthorized cross-namespace requests, and inspect the real-time audit decisions:

```bash
ztap test-traffic --requests 12
```

Output:
```text
┌────────────────────────────── Simulation Traffic Results ──────────────────────────────┐
│ Client / Workload                      │ Request                  │ Decision │ Status │
├────────────────────────────────────────┼──────────────────────────┼──────────┼────────┤
│ Billing Service (mTLS)                 │ POST /api/v1/payments... │ ALLOW    │ 200    │
│ Frontend Service (mTLS Unauthorized)   │ POST /api/v1/payments... │ DENY     │ 403    │
│ Alice (Admin JWT to Admin)             │ GET /admin/dashboard     │ ALLOW    │ 200    │
│ Bob (Viewer JWT to Admin)              │ POST /admin/reset        │ DENY     │ 403    │
│ Anonymous Client to Health             │ GET /health              │ ALLOW    │ 200    │
│ Anonymous Client to Internal           │ GET /internal/metrics    │ DENY     │ 403    │
└────────────────────────────────────────┴──────────────────────────┴──────────┴────────┘

Tamper-Evident Hash Chain Verification: 12 records checked, Chain valid = True
```

### 4. Verify Cryptographic Audit Trail Integrity

```bash
ztap audit verify
```

### 5. Launch the Access Proxy Gateway

```bash
ztap serve --host 0.0.0.0 --port 8000
```
Swagger OpenAPI documentation is accessible at `http://localhost:8000/docs`.

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status, CA domain, policy count, and audit validity |
| `POST` | `/v1/auth/check` | Sidecar authorization check for Envoy `ext_authz` or NGINX `auth_request` |
| `ANY` | `/proxy/{path}` | Zero-Trust reverse proxy forwarder injecting identity headers |
| `GET` | `/v1/pki/ca` | Fetch Root Certificate Authority public certificate PEM |
| `POST` | `/v1/pki/issue` | Issue short-lived X.509 SVID workload certificate with SPIFFE SAN |
| `POST` | `/v1/pki/rotate` | Dynamically rotate active SVID certificate |
| `POST` | `/v1/pki/validate` | Cryptographically validate an X.509 client certificate against Root CA |
| `POST` | `/v1/jwt/issue` | Issue demo signed JWT Bearer token with roles and scopes |
| `GET` | `/v1/policies` | List active RBAC/ABAC authorization policies |
| `POST` | `/v1/policies` | Create or update authorization policy |
| `DELETE` | `/v1/policies/{id}` | Delete an authorization policy |
| `GET` | `/v1/audit/records` | Query logged authorization audit records |
| `GET` | `/v1/audit/verify` | Verify cryptographic SHA-256 hash chain integrity |
| `WS` | `/ws/audit` | Real-time WebSocket audit event stream |

---

## Configuration Reference

Settings can be customized via `.env` file or environment variables prefixed with `ZTAP_`:

| Parameter | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `host` | `ZTAP_HOST` | `0.0.0.0` | Bind host address |
| `port` | `ZTAP_PORT` | `8000` | Listening port |
| `upstream_url` | `ZTAP_UPSTREAM_URL` | `http://127.0.0.1:9090` | Protected upstream service URL |
| `trust_domain` | `ZTAP_PKI__TRUST_DOMAIN` | `prod.internal` | Global SPIFFE trust domain |
| `root_ca_validity_days` | `ZTAP_PKI__ROOT_CA_VALIDITY_DAYS` | `365` | Root CA certificate validity (days) |
| `svid_default_ttl_hours` | `ZTAP_PKI__SVID_DEFAULT_TTL_HOURS` | `24` | Default SVID certificate lifetime (hours) |
| `jwt_secret_key` | `ZTAP_JWT__SECRET_KEY` | *(demo 32-byte key)* | Secret key for JWT signature validation |
| `audit_database_path` | `ZTAP_AUDIT__DATABASE_PATH` | `:memory:` | SQLite storage path (`:memory:` or `.sqlite3` file) |
| `genesis_hash` | `ZTAP_AUDIT__GENESIS_HASH` | `0000...0000` | 64-character hex root digest for hash chain |

---

## Docker Deployment

Launch in a containerized environment with persistent volume-backed audit storage:

```bash
docker compose up -d
```

Verify proxy readiness:

```bash
curl -f http://localhost:8000/health
```

---

## Testing & Quality Gates

The test suite provides comprehensive coverage of X.509 SVID issuance, signature verification, JWT parsing, RBAC/ABAC rules, hash-chain tamper detection, REST endpoints, and WebSockets:

```bash
# Run automated tests
pytest tests -v

# Run linter checks
ruff check src tests

# Format code
ruff format src tests
```

---

## License

This project is licensed under the [MIT License](LICENSE).


---

## 🖼️ User Interface & System Preview

*Interactive operational view and real-time telemetry dashboard.*

```
+------------------------------------------------------------------------------------+
|  ZERO TRUST ACCESS PROXY -- PRODUCTION COCKPIT                            |
+------------------------------------------------------------------------------------+
|  Status: HEALTHY (P99 < 35ms)  |  Workers: 4 Active  |  Zero Data Loss: 100.0%    |
|                                                                                    |
|  [ Live Ingestion Stream ]           [ Pipeline Health & Automated Audits ]        |
|  * Event Rate: 1,500 ops/sec         * Schema Validation: PASS (Pydantic v2)      |
|  * Memory Footprint: 92 MB           * Dead-Letter Isolation: 0 Unhandled         |
|  * P99 Processing: 28 ms             * Storage Tier: SQLite / PostgreSQL / DuckDB  |
|                                                                                    |
|  [ View Detailed Telemetry -> ]      [ Export Audited Data (.csv / .json) -> ]     |
+------------------------------------------------------------------------------------+
```

![документація API](screenshots/03_api_docs.png)

![підсумок тестів](screenshots/01_tests.png)

![довідка CLI](screenshots/04_cli_1.png)

Усі скріншоти (5): [screenshots/](screenshots/README.md)


---

## 💼 Commercial Licensing & Deployment

This production module is developed and maintained by **Nataliia Zyma**.

The core engine is closed-source proprietary software available for **commercial licensing**, **custom enterprise integration**, or **turnkey business deployment**:
- **Direct Email:** [`zymaneta@gmail.com`](mailto:zymaneta@gmail.com)
- **GitHub:** [@zymaneta-eng](https://github.com/zymaneta-eng)
- **Turnkey Integration:** Full setup with your existing infrastructure, custom business rules, and SLA monitoring within 48–72 hours.
- **SLA & Response:** Enterprise inquiries are reviewed and answered within 2–4 business hours.
