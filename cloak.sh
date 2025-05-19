#!/bin/bash

IMAGE_NAME="cloak:latest"
REBUILD=false
SSH_KEY_DIR="$HOME/.ssh"
HOST_LOOT_DIR="$(pwd)/loot"
CONTAINER_LOOT_DIR="/app/loot"
HOST_PAYLOADS_DIR="$(pwd)/payloads"
CONTAINER_PAYLOADS_DIR="/app/payloads"
HOST_BRUTEFORCER_DIR="$(pwd)/bruteforcer"        # [ADDED]
CONTAINER_BRUTEFORCER_DIR="/app/bruteforcer"     # [ADDED]

# Ensure the loot, payloads, and bruteforcer directories exist on the host
for DIR in "$HOST_LOOT_DIR" "$HOST_PAYLOADS_DIR" "$HOST_BRUTEFORCER_DIR"; do
    if [ ! -d "$DIR" ]; then
        echo "[+] Creating directory: $DIR"
        mkdir -p "$DIR"
    fi
done

# Check if DISPLAY is set for X11 apps like xfreerdp
if [ -z "$DISPLAY" ]; then
    echo "[-] DISPLAY environment variable is not set. GUI apps like xfreerdp will fail."
    exit 1
fi

xhost +local:docker > /dev/null

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --rebuild)
            REBUILD=true
            ;;
        --keys)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                SSH_KEY_DIR="$2"
                shift
            else
                echo "Error: --keys requires a directory argument."
                exit 1
            fi
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--rebuild] [--keys <ssh-key-directory>]"
            exit 1
            ;;
    esac
    shift
done

# Build Docker image if needed
if $REBUILD; then
    echo "[+] Rebuild flag set. Removing existing image (if any)..."
    if sudo docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
        sudo docker image rm -f "$IMAGE_NAME"
        echo "[+] Removed old image: $IMAGE_NAME"
    else
        echo "[*] No existing image to remove."
    fi
    echo "[+] Rebuilding the Docker image..."
    sudo docker build -t "$IMAGE_NAME" .
    if [ $? -ne 0 ]; then
        echo "[-] Failed to build the Docker image. Exiting."
        exit 1
    fi
    echo "[+] Docker image $IMAGE_NAME built successfully."
elif ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "[+] Image not found. Building the Docker image..."
    sudo docker build -t "$IMAGE_NAME" .
    if [ $? -ne 0 ]; then
        echo "[-] Failed to build the Docker image. Exiting."
        exit 1
    fi
    echo "[+] Docker image $IMAGE_NAME built successfully."
else
    echo "[*] Docker image $IMAGE_NAME already exists. Skipping build."
fi

# Run the container with proper interactive shell
echo "Running the Docker container..."
sudo docker run -it --rm \
    --privileged \
    -e DISPLAY="$DISPLAY" \
    -e XAUTHORITY=/root/.Xauthority \
    -v "$HOME/.Xauthority:/root/.Xauthority:ro" \
    -v "$HOST_LOOT_DIR:$CONTAINER_LOOT_DIR" \
    -v "$HOST_PAYLOADS_DIR:$CONTAINER_PAYLOADS_DIR" \
    -v "$HOST_BRUTEFORCER_DIR:$CONTAINER_BRUTEFORCER_DIR" \
    -v "/tmp/.X11-unix:/tmp/.X11-unix" \
    --network=host \
    ${SSH_KEY_DIR:+-v "$SSH_KEY_DIR:/temp-ssh:ro"} \
    "$IMAGE_NAME" bash -c '
        echo "[+] Ensuring directories exist inside the container..."
        mkdir -p /app/loot /app/payloads /app/bruteforcer     # [ADDED]

        if [ -d /temp-ssh ]; then
            echo "[+] Copying SSH keys..."
            mkdir -p /root/.ssh
            cp -r /temp-ssh/. /root/.ssh/
            chmod -R go-rwx /root/.ssh
        fi

        exec python3 /app/cloak.py
    '

if [ $? -eq 0 ]; then
    echo "Docker container ran successfully."
else
    echo "Docker container encountered an error."
    exit 1
fi
