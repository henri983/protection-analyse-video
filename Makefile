.PHONY: help install test lint security run

help:
	@echo "Commandes pour protection-analyse-video :"
	@echo "  make install    - Installe les dépendances du projet"
	@echo "  make test       - Exécute les tests unitaires, sécurité et IA"
	@echo "  make lint       - Vérification statique avec ruff"
	@echo "  make security   - Scan statique des vulnérabilités avec bandit"
	@echo "  make run        - Démarre l'API FastAPI"

install:
	pip install -r requirements/test.txt

test:
	pytest -v --cov=src

lint:
	ruff check .

security:
	bandit -r src/ -ll

run:
	uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
