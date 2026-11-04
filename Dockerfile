FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY waf waf
RUN useradd --create-home waf && mkdir /data && chown waf /data
USER waf
