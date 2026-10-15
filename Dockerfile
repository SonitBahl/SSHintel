# Use a slim official Python image.
FROM python:3.11-slim

# Install the OpenSSH client (provides ssh-keygen for host key generation).
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container.
WORKDIR /app

# Copy only runtime requirements first for better layer caching.
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

# Copy project files into the container.
COPY . .

# Ensure the static folder exists for storing the private key.
RUN mkdir -p static data

# Expose the SSH port (can be overridden via `-e PORT=`).
ENV PORT=2222
ENV HONEYPOT_USERNAME=user1
ENV HONEYPOT_PASSWORD=pass123
ENV HONEYPOT_SENSOR_ID=docker
ENV HONEYPOT_DB_PATH=/app/data/sshintel.db
EXPOSE ${PORT}

# Generate RSA key if missing, then run the server.
# NOTE: Uses the `serve` subcommand as expected by the current CLI.
# Python reads configuration directly; never interpolate credentials into a shell.
CMD ["sh", "-c", "if [ ! -f static/server.key ]; then ssh-keygen -t rsa -b 2048 -m PEM -f static/server.key -N '' && rm -f static/server.key.pub; fi && exec python run.py serve"]
