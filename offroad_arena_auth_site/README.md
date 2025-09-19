# Offroad Arena — prezentacja chroniona logowaniem

Minimalny serwer **Flask** z formularzem logowania (login + hasło) chroniący Twoją prezentację HTML.

## Szybki start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py hash TwojeHaslo  # skopiuj hash do PASSWORD_HASH w .env
python app.py                  # http://localhost:8000

Docker
cp .env.example .env
docker compose up --build
# http://localhost:8000


Po zalogowaniu treść z templates/deck.html jest serwowana pod /deck.
