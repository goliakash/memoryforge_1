# Multi-stage secure Dockerfile for Hindsight SecOps Agent
FROM python:3.12-slim AS base

# Security: Set working directory and non-root user
WORKDIR /app
RUN addgroup --system secops && adduser --system --group secops

# Install runtime dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY backend /app/backend
COPY frontend /app/frontend

# Grant permissions to non-root user
RUN chown -R secops:secops /app
USER secops

# Expose FastAPI port
EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["python", "backend/run.py"]
