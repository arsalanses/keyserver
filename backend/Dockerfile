FROM python:3.14-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/main.py .
COPY backend/hash-ident-tool.py .
COPY backend/templates .

# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
CMD ["uvicorn", "hash-ident-tool:app", "--host", "0.0.0.0", "--port", "8000"]
