.PHONY: setup dev docker-build docker-up
setup:
	python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
dev:
	python app.py
docker-build:
	docker build -t offroad_arena_auth_site:local .
docker-up:
	docker compose up --build
