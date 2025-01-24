#!/bin/bash

IMAGE_NAME="cloak:latest"
REBUILD=false
SSH_KEY_DIR="$HOME/.ssh"
HOST_LOOT_DIR="$(pwd)/loot"
CONTAINER_LOOT_DIR="/app/loot"
HOST_PAYLOADS_DIR="$(pwd)/payloads"
CONTAINER_PAYLOADS_DIR="/app/payloads"

# Ensure the loot and payloads directories exist on the host
for DIR in "$HOST_LOOT_DIR" "$HOST_PAYLOADS_DIR"; do
    if [ ! -d "$DIR" ]; then
        echo "Creating directory: $DIR"
        mkdir -p "$DIR"
    fi
done

xhost +local:docker

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

if $REBUILD || ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "Building the Docker image..."
    sudo docker build -t "$IMAGE_NAME" .
    if [ $? -ne 0 ]; then
        echo "Failed to build the Docker image. Exiting."
        exit 1
    fi
    echo "Docker image $IMAGE_NAME built successfully."
else
    echo "Docker image $IMAGE_NAME already exists. Skipping build."
fi

echo "Running the Docker container..."
DOCKER_RUN_CMD=(
    "sudo" "docker" "run"
    "-it" "--rm"
    "--privileged"
    "-e" "DISPLAY=$DISPLAY"
    "-v" "$HOST_LOOT_DIR:$CONTAINER_LOOT_DIR"
    "-v" "$HOST_PAYLOADS_DIR:$CONTAINER_PAYLOADS_DIR"
    "-v" "/tmp/.X11-unix:/tmp/.X11-unix"
    "--network=host"
)

if [ -n "$SSH_KEY_DIR" ]; then
    DOCKER_RUN_CMD+=("-v" "$SSH_KEY_DIR:/temp-ssh:ro")
fi

DOCKER_RUN_CMD+=( "$IMAGE_NAME" "bash" "-c" "
    echo 'Ensuring directories exist inside the container...'
    mkdir -p $CONTAINER_LOOT_DIR $CONTAINER_PAYLOADS_DIR
    echo 'Verifying directories:'
    ls -ld $CONTAINER_LOOT_DIR $CONTAINER_PAYLOADS_DIR

    # Handle SSH key setup if provided
    if [ -d /temp-ssh ]; then
        echo 'Copying SSH keys...'
        mkdir -p /root/.ssh
        cp /temp-ssh/* /root/.ssh/
        chmod 600 /root/.ssh/*
    fi

    echo 'Starting application...'
    exec python3 /app/cloak.py
")

"${DOCKER_RUN_CMD[@]}"

if [ $? -eq 0 ]; then
    echo "Docker container ran successfully."
else
    echo "Docker container encountered an error."
    exit 1
fi

