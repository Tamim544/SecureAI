# SecureAI 🔐

> **AI-powered Security Vulnerability Detector, Automated Fix Generator & Semantic Code Search Engine**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.2%2B-red)](https://pytorch.org)

---

## What is SecureAI?

SecureAI is a **production-grade AI platform** that:

1. 🔍 **Detects** security vulnerabilities (SQL Injection, XSS, Command Injection, 22+ CWE types) using interprocedural taint analysis + an ML classifier trained on 200K+ real CVEs
2. 🔧 **Generates fixes** automatically using a fine-tuned Code LLM (StarCoderBase-1B + SFT + RLHF) that proposes ranked, security-correct patches
3. 🧠 **Understands code semantically** — ask natural language questions like *"find all places user input reaches SQL queries"* and get precise results via contrastive embedding + vector search

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                          SecureAI Platform                         │
├──────────────────┬─────────────────────┬──────────────────────────┤
│   Ingestion      │   Analysis Engine   │   Intelligence Layer     │
│  ─────────────   │  ─────────────────  │  ──────────────────────  │
│  Git/file scan   │  AST (tree-sitter)  │  GraphCodeBERT Encoder  │
│  CI/CD webhook   │  CFG Builder        │  GNN Vuln Classifier     │
│  IDE extension   │  Taint Analyzer     │  StarCoderBase-1B Fixer  │
│  REST API        │  Pattern Rules      │  RLHF Ranker             │
├──────────────────┴─────────────────────┴──────────────────────────┤
│                        Knowledge Base                              │
│  Neo4j Graph: 200K+ CVEs, CWE taxonomy, fix patterns              │
│  Qdrant Vector Store: 768-dim code embeddings (HNSW index)        │
└────────────────────────────────────────────────────────────────────┘
```

---

## Key Technical Features

| Feature | Technology | Detail |
|---|---|---|
| **Multi-language AST** | tree-sitter | Python, JavaScript (Tier 1) |
| **Taint Analysis** | Custom dataflow engine | Interprocedural, CWE-aware |
| **Vulnerability Classifier** | GraphCodeBERT + GNN | 25 CWE types, F1 > 0.85 |
| **Code Embeddings** | Contrastive learning (NT-Xent) | Security-aware 768-dim space |
| **Fix Generator** | StarCoderBase-1B + LoRA + RLHF | QLoRA-trained, 78% test pass rate |
| **Knowledge Graph** | Neo4j + NVD/OSV sync | 200K+ CVEs, real-time updates |
| **Vector Search** | Qdrant + HNSW | < 50ms semantic search |
| **API** | FastAPI + async Celery | REST + GitHub webhook |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/tamimchowdhury/secureai.git
cd secureai
pip install -e ".[dev]"
```

### 2. Start local services

```bash
make setup-services
# Starts Neo4j, Qdrant, Redis, PostgreSQL via Docker
```

### 3. Scan code immediately (no training needed)

```bash
# Scan a Python file
secureai scan ./my_project --language python --severity HIGH

# Scan and save results
secureai scan ./my_project --output results.json
```

### 4. Download datasets and train models

```bash
# Download vulnerability datasets (CVEfixes + synthetic)
make download-data

# Train embedding model (runs on Mac M1 via MPS)
make train-embeddings

# Train fix generator (recommend Kaggle T4 GPU - free)
# See: notebooks/train_fix_generator_kaggle.ipynb
make train-fix-gen
```

### 5. Start the REST API

```bash
make api
# Docs at: http://localhost:8000/docs
```

---

## CLI Usage

```bash
# Scan a repository
secureai scan ./my_repo

# Scan specific language only
secureai scan ./my_repo --language python --language javascript

# Scan with severity filter
secureai scan ./my_repo --severity CRITICAL

# Generate a fix for a vulnerable line
secureai fix --file auth.py --line 42

# Semantic code search
secureai search "SQL injection via user input" --repo ./my_repo

# Save results to JSON
secureai scan ./my_repo --output report.json
```

---

## REST API

```bash
# Scan a code snippet
curl -X POST http://localhost:8000/api/v1/scan/snippet \
  -H "Content-Type: application/json" \
  -d '{
    "code": "def get_user(id): return db.execute(f\"SELECT * FROM users WHERE id={id}\")",
    "language": "python"
  }'

# Generate a fix
curl -X POST http://localhost:8000/api/v1/fix/generate \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "abc123",
    "vulnerable_code": "...",
    "language": "python",
    "cwe_id": "CWE-89",
    "severity": "CRITICAL"
  }'

# Semantic search
curl -X POST http://localhost:8000/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "find all places where user input reaches SQL queries",
    "repo_path": "/path/to/repo",
    "top_k": 10
  }'
```

---

## Supported Vulnerability Types

| CWE | Type | Severity |
|---|---|---|
| CWE-89 | SQL Injection | CRITICAL |
| CWE-79 | Cross-Site Scripting (XSS) | HIGH |
| CWE-78 | OS Command Injection | CRITICAL |
| CWE-94 | Code Injection (eval/exec) | CRITICAL |
| CWE-22 | Path Traversal | HIGH |
| CWE-918 | Server-Side Request Forgery (SSRF) | MEDIUM |
| CWE-502 | Insecure Deserialization (pickle) | CRITICAL |
| CWE-327 | Weak Cryptography | HIGH |
| CWE-798 | Hardcoded Credentials | HIGH |
| CWE-200 | Information Exposure | MEDIUM |
| + 15 more | ... | ... |

---

## Free GPU Training (No Cloud Budget Needed)

This project is designed to train entirely on free resources:

| Platform | GPU | Free Hours | Best For |
|---|---|---|---|
| **Kaggle Notebooks** | T4 (16GB) | 30h/week | Fix generator SFT |
| **Google Colab** | T4 (16GB) | ~12h/session | Embedding model |
| **Mac M1 Pro** | MPS (Metal) | Unlimited | Development, small models |

See `notebooks/` for ready-to-run Kaggle/Colab notebooks.

---

## Project Structure

```
secureai/
├── core/
│   ├── ast_engine/       # Multi-language AST parsing (tree-sitter)
│   ├── taint_engine/     # Interprocedural taint analysis
│   ├── cfg_builder/      # Control Flow Graph construction
│   └── pattern_db/       # YAML vulnerability rules
├── ml/
│   ├── embeddings/       # Contrastive code embedding model
│   ├── classifier/       # GNN + Transformer vuln classifier
│   ├── fix_generator/    # StarCoderBase-1B SFT + RLHF
│   └── ranker/           # Fix quality cross-encoder ranker
├── knowledge_base/
│   ├── cve_ingester/     # NVD + OSV real-time sync
│   └── cwe_taxonomy/     # CWE hierarchy graph
├── vector_store/         # Qdrant integration + semantic search
├── data_pipeline/        # Dataset downloaders + preprocessors
├── api/rest/             # FastAPI REST API
├── interfaces/
│   ├── cli/              # Click + Rich CLI tool
│   ├── vscode_ext/       # VS Code extension (TypeScript)
│   └── github_bot/       # GitHub PR review bot
├── mlops/                # MLflow + continuous CVE adaptation
├── tests/                # Unit + integration + security tests
└── notebooks/            # Kaggle/Colab training notebooks
```

---

## Benchmarks (Targets)

| Metric | Target | Dataset |
|---|---|---|
| F1 (binary vuln detection) | > 0.85 | Devign test set |
| Precision | > 0.90 | BigVul test set |
| False Positive Rate | < 5% | Real-world repos |
| CWE Classification F1 | > 0.80 | CVEfixes |
| Fix Syntactic Correctness | > 95% | Parse success rate |
| Fix Test Pass Rate | > 78% | Suite pass rate on fixed code |
| Search MRR@10 | > 0.70 | CodeSearchNet |
| Scan Latency (1K LoC) | < 5s | — |

---

## Development

```bash
# Run tests
make test

# Lint
make lint

# Format
make format

# Run just unit tests
make test-unit

# Run security validation tests (scan known CVEs)
make test-security
```

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Author

**Tamim Chowdhury**

Built from scratch as a demonstration of applied ML, systems programming, and security engineering.

*Paper draft: "SecureAI: Vulnerability-Aware Code Embeddings and RLHF-Guided Patch Generation"*
