# Base Image
FROM python:3.9-slim-bullseye

# Set working directory
WORKDIR /app

# Install system dependencies required for OpenCV
# Install system dependencies
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from backend directory
COPY backend/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ .


# Copy frontend assets to system root /frontend (accessible via ../../../frontend)
COPY frontend/ /frontend

# Copy models directory if it exists (using wildcard hack to avoid failure if missing)
# Note: In production, large models should be downloaded from a cloud storage bucket at runtime
COPY models* /app/models/

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "phishguard.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
