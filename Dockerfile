FROM python:3.11-slim

# Install system dependencies required for Poetry and building packages
RUN apt-get update && apt-get install -y curl build-essential docker.io && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.2

# Configure Poetry to not use virtual environments (since Docker itself is the isolated environment)
RUN poetry config virtualenvs.create false

# Copy dependency files first to leverage Docker layer caching
COPY pyproject.toml poetry.lock* ./

# Install dependencies only (skip the project itself for now)
RUN poetry install --no-interaction --no-ansi --no-root --without dev

# Copy the rest of the application code
COPY . .

# Install the actual detector package
RUN poetry install --no-interaction --no-ansi --without dev

# Expose the FastAPI port
EXPOSE 8000

# Default command: Start the API server (the agent can be triggered via CLI in parallel or via cron)
CMD ["uvicorn", "detector.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
