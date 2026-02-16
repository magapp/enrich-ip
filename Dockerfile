FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY enrich-ip.py .
COPY app.py .
COPY utils.py .
COPY providers/ providers/
COPY templates/ templates/

# Create directory for data files
RUN mkdir -p /data

CMD ["python", "app.py"]
