.DEFAULT_GOAL := help

.PHONY: help install install-dev start stop status test cov lint fmt sast audit check

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime dependencies (Apple Silicon / MLX)
	pip install -r requirements.txt

install-dev: ## Install dev dependencies (ruff, pytest, bandit, pip-audit)
	pip install -r requirements-dev.txt

start: ## Start the local AI stack (Flask + nginx)
	./scripts/start_local_ai_stack.sh

stop: ## Stop the local AI stack
	./scripts/stop_local_ai_stack.sh

status: ## Show stack status
	./scripts/status_local_ai_stack.sh

test: ## Run unit tests
	pytest

cov: ## Run tests with coverage (fails under 50%)
	pytest --cov=private_ai_gateway --cov-report=term-missing --cov-fail-under=50

lint: ## Lint with ruff
	ruff check src tests

fmt: ## Auto-format with ruff
	ruff format src tests

sast: ## Static security analysis (bandit)
	bandit -r src -q

audit: ## Dependency vulnerability scan (pip-audit)
	pip-audit -r requirements.txt

check: lint sast audit cov ## Run all CI checks locally
