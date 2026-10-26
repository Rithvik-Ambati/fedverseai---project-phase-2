# One image for every role (chain node, deployer, server, hospital). UNTESTED: Docker was not running on the dev machine.
FROM node:22-bookworm
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt
COPY chain/package*.json chain/
RUN cd chain && npm ci || npm install
COPY . .
ENV PATH="/venv/bin:$PATH" PYTHONPATH=/app
