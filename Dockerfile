# Use a slim official Python image
# Use a stable official Python image
FROM python:3.11-slim

# Install ssh-keygen via the OpenSSH client
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy project files into the container
COPY . .

# Install Python dependencies
RUN python -m pip install --no-cache-dir -r requirements.txt

# Ensure the static folder exists for storing the private key
RUN mkdir -p static

# Expose the default port (can be overridden via `-e PORT=`)
ENV PORT=2222
ENV HONEYPOT_USERNAME=user1
ENV HONEYPOT_PASSWORD=pass123
EXPOSE ${PORT}

# Generate RSA key if missing, then run the server. Operator can override port/username/password via env.
CMD ["/bin/bash", "-c", "if [ ! -f static/server.key ]; then ssh-keygen -t rsa -b 2048 -m PEM -f static/server.key -N ''; fi && python run.py --port ${PORT} --username ${HONEYPOT_USERNAME} --password ${HONEYPOT_PASSWORD}"]
