FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p output/html output/csv output/json logs

CMD ["python", "main.py", "scan", "--profile", "full"]