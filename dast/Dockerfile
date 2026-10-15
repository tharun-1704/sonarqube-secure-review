# Runtime image for either app. Runs as a non-root user; ping is installed so
# /ping behaves as it would on a real host.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/* && useradd --create-home lab
WORKDIR /app
RUN pip install --no-cache-dir "flask>=3.0" "requests>=2.31" "bcrypt>=4.1"
USER lab
