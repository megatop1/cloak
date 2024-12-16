# Use official Python image as the base
FROM python:3.12-slim

# Install necessary tools
RUN apt-get update && apt-get install -y \
    sshpass \
    netcat-openbsd \
    openssh-client \
    curl \
    wget \
    git \
    software-properties-common \
    freerdp2-x11 \
    ruby-dev \
    build-essential \
    libffi-dev \
    python3-impacket \
    && apt-get clean

# Install Evil-WinRM
RUN gem install ffi
RUN gem install evil-winrm

# Install Chisel
WORKDIR /app
RUN wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.deb && \
    dpkg -i chisel_1.10.1_linux_amd64.deb && \
    rm -f chisel_1.10.1_linux_amd64.deb

# Install Slinger
RUN git clone https://github.com/ghost-ng/slinger.git && \
    cd slinger && \
    pip install -r requirements.txt && \
    pip install . && \
    export PATH=~/.local/bin:$PATH 

# Copy the Python script into the container
COPY cloak.py /app/cloak.py
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir questionary

# Set environment variable for display (for X11 forwarding)
ENV DISPLAY=:0.0

# Default command to run the script
CMD ["python", "cloak.py"]
