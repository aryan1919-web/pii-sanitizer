@echo off
echo === PII Sanitizer Setup ===

python -m venv venv
call venv\Scripts\activate

pip install -r requirements.txt
python -m spacy download en_core_web_sm

echo.
echo === Starting Server ===
echo Admin login: admin / admin123
echo Open browser: http://localhost:8000
echo.

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
