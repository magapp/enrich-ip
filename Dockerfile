FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY enrich-ip.py .

# Create directory for data files
RUN mkdir -p /data

ENTRYPOINT ["python", "enrich-ip.py"]
