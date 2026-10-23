FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md constraints.txt ./
COPY src ./src
RUN pip install --no-cache-dir -c constraints.txt '.[snowflake]' && mkdir -p /app/.sentinel && useradd --create-home sentinel && chown -R sentinel /app
USER sentinel
ENV PYTHONUNBUFFERED=1
EXPOSE 8000 8501
CMD ["sentinel", "serve", "--host", "0.0.0.0"]
