# Use a slim official Python image
FROM python:3.11-slim

# Install ssh-keygen via the OpenSSH client
RUN apt-get update && apt-get install -y openssh-client && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy project files into the container
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure the static folder exists for storing the private key
RUN mkdir -p static

# Expose the port your SSH-like app listens on
EXPOSE 2222

# Generate RSA key if missing, then run the server
CMD ["/bin/bash", "-c", "if [ ! -f static/server.key ]; then ssh-keygen -t rsa -b 2048 -m PEM -f static/server.key -N ''; fi && python run.py --port 2222 --username user1 --password pass123"]
