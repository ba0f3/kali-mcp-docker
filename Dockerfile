FROM kalilinux/kali-rolling

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    nmap \
    metasploit-framework \
    netcat-openbsd \
    curl \
    wget \
    dnsutils \
    whois \
    hydra \
    gobuster \
    dirb \
    nikto \
    sqlmap \
    testssl.sh \
    amass \
    httpx-toolkit \
    subfinder \
    gospider \
    golang \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install waybackurls using Go
RUN go install github.com/tomnomnom/waybackurls@latest && \
    cp /root/go/bin/waybackurls /usr/local/bin/

WORKDIR /app

# Copy only dependency files first so dependency install is cached when only code changes
COPY requirements.txt .

# Create venv and install Python dependencies (cached unless requirements.txt changes)
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --no-cache-dir -v uv && pip install --no-cache-dir -v -r requirements.txt

# Copy application code (this layer rebuilds only when source files change)
COPY . /app/

# Ensure output directories and files exist
RUN touch /app/command_output.txt && mkdir -p /app/outputs /app/sessions

# Expose port for SSE
EXPOSE 8000

# Run the server with SSE transport
CMD ["python", "-m", "kali_mcp_server.server", "--transport", "sse", "--port", "8000"]