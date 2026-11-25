FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
# Container image serves only the allowlisted Partner API. Keep the admin
# control plane on the FlowSense host, bound to 127.0.0.1:8001.
EXPOSE 8000
CMD ["uvicorn", "app.partner_app:partner_app", "--host", "0.0.0.0", "--port", "8000"]
