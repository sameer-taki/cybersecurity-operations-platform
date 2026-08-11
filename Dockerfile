FROM python:3.12-slim
WORKDIR /workspace
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv && uv sync --frozen --no-dev
COPY backend ./backend
COPY alembic.ini ./
ENV PYTHONPATH=/workspace/backend
CMD ["uv", "run", "--no-dev", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
