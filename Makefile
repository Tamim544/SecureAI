.DEFAULT_GOAL := help

.PHONY: help install install-dev setup-services teardown-services \
        download-data train-embeddings train-classifier train-fix-generator \
        api test lint format

# ──────────────────────────────────────────────
help:
	@echo ""
	@echo "  ██████╗ ███████╗ ██████╗██╗   ██╗██████╗ ███████╗ █████╗ ██╗"
	@echo "  ██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██║"
	@echo "  ███████║█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████║██║"
	@echo "  ██╔══╝  ██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██║██║"
	@echo "  ██║     ███████╗╚██████╗╚██████╔╝██║  ██║███████╗██║  ██║██║"
	@echo "  ╚═╝     ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝"
	@echo ""
	@echo "  AI-powered Security Vulnerability Detector & Fix Generator"
	@echo ""
	@echo "  Usage: make [target]"
	@echo ""
	@echo "  Setup:"
	@echo "    install          Install production dependencies"
	@echo "    install-dev      Install all dependencies including dev tools"
	@echo "    setup-services   Start local Docker services (Neo4j, Qdrant, Redis, PostgreSQL)"
	@echo "    teardown-services Stop and remove Docker services"
	@echo ""
	@echo "  Data:"
	@echo "    download-data    Download and process vulnerability datasets"
	@echo ""
	@echo "  Training (run in order):"
	@echo "    train-embeddings   Train contrastive code embedding model"
	@echo "    train-classifier   Train vulnerability classifier"
	@echo "    train-fix-gen      Train fix generator (SFT)"
	@echo ""
	@echo "  Running:"
	@echo "    api              Start the REST API server"
	@echo "    scan             Quick scan (usage: make scan TARGET=./my_repo)"
	@echo ""
	@echo "  Development:"
	@echo "    test             Run test suite"
	@echo "    lint             Run ruff linter"
	@echo "    format           Auto-format code"
	@echo ""

# ──────────────────────────────────────────────
# Setup
# ──────────────────────────────────────────────

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"
	pre-commit install

setup-services:
	@echo "Starting local infrastructure services..."
	docker compose up -d
	@echo "Waiting for services to be healthy..."
	sleep 10
	@echo ""
	@echo "Services running:"
	@echo "  PostgreSQL:  localhost:5432"
	@echo "  Neo4j:       http://localhost:7474 (neo4j/secureai_neo4j)"
	@echo "  Qdrant:      http://localhost:6333"
	@echo "  Redis:       localhost:6379"

teardown-services:
	docker compose down

# ──────────────────────────────────────────────
# Data Pipeline
# ──────────────────────────────────────────────

download-data:
	@echo "Downloading vulnerability datasets (CVEfixes + synthetic)..."
	python data_pipeline/downloaders/vuln_datasets.py
	@echo "Dataset ready at data/processed/vuln_pairs/"

download-data-full:
	@echo "Downloading ALL datasets including BigVul (C/C++)..."
	python data_pipeline/downloaders/vuln_datasets.py --include-bigvul

# ──────────────────────────────────────────────
# Training
# ──────────────────────────────────────────────

train-embeddings:
	@echo "Training contrastive code embedding model..."
	@echo "This will run on MPS (Mac M1) - For faster training use Kaggle/Colab T4"
	python ml/embeddings/contrastive_trainer.py \
		--data-path data/processed/vuln_pairs \
		--base-model microsoft/graphcodebert-base \
		--batch-size 16 \
		--epochs 20 \
		--device auto

train-fix-gen:
	@echo "Training fix generator model (SFT with QLoRA)..."
	@echo "Recommended: Run this on Kaggle T4 GPU (free 30h/week)"
	@echo "Kaggle notebook: see notebooks/train_fix_generator_kaggle.ipynb"
	python ml/fix_generator/sft_trainer.py \
		--data-path data/processed/vuln_pairs \
		--epochs 3 \
		--batch-size 2

# ──────────────────────────────────────────────
# Running
# ──────────────────────────────────────────────

api:
	@echo "Starting SecureAI REST API on http://localhost:8000"
	@echo "API docs: http://localhost:8000/docs"
	python -m uvicorn api.rest.app:app --host 0.0.0.0 --port 8000 --reload

scan:
	@[ "$(TARGET)" ] || ( echo "Usage: make scan TARGET=./path/to/repo"; exit 1 )
	python -m interfaces.cli.main scan "$(TARGET)"

# ──────────────────────────────────────────────
# Development
# ──────────────────────────────────────────────

test:
	pytest tests/ -v --cov=. --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v

test-security:
	pytest tests/security/ -v

lint:
	ruff check .

format:
	ruff format .
	ruff check . --fix

type-check:
	mypy . --ignore-missing-imports

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache
