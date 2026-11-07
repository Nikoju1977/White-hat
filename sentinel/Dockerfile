FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && groupadd -g 10001 aegis && useradd -u 10001 -g 10001 -s /usr/sbin/nologin aegis
COPY aegis ./aegis
COPY web ./web
RUN mkdir /app/data && chown 10001:10001 /app/data
USER 10001:10001
EXPOSE 8765
CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8765", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
