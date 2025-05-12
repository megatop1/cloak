# Use official Python image as the base
FROM python:3.12-slim

# Install necessary tools
RUN apt-get update && apt-get install -y \
    sshpass \
    iproute2 \
    net-tools \
    netcat-openbsd \
    openssh-client \
    sqlite3 \
    curl \
    wget \
    git \
    vim \
    software-properties-common \
    freerdp2-x11 \
    ruby-dev \
    build-essential \
    libffi-dev \
    python3-impacket \
    x11-xserver-utils \
    proxychains \
    libx11-6 \
    libxext6 \
    libxrandr2 \
    libxinerama1 \
    libxcursor1 \
    libxi6 \
    libxcomposite1 \
    libxdamage1 && \
    apt-get clean

# Install Evil-WinRM
RUN gem install ffi && \
    gem install evil-winrm

# Set working directory
WORKDIR /app

# Install Chisel
RUN wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.deb && \
    dpkg -i chisel_1.10.1_linux_amd64.deb && \
    rm -f chisel_1.10.1_linux_amd64.deb

# Install Slinger
RUN git clone https://github.com/ghost-ng/slinger.git && \
    cd slinger && \
    pip install -r requirements.txt && \
    pip install .

# Copy your scripts into the container
COPY cloak.py /app/cloak.py
COPY completer.py /app/completer.py
COPY ssh_module.py /app/ssh_module.py

# Install Python dependencies
RUN pip install --no-cache-dir questionary prompt_toolkit rich pexpect

# Set environment variable for display (for X11 forwarding)
ENV DISPLAY=:0.0

# Default command to run the script
CMD ["python", "cloak.py"]

