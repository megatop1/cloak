# Cloak

Cloak is a utility to connect to remote hosts normally, or via chisel.

## Usage
run `./cloak.sh` to build and run

If using SSH Key authentication, ensure all required SSH keys are in the same directory
Run `./cloak.sh --keys /path/to/your/keys`

## Force Rebuild
After updates are made to cloak.py or the Dockerfile, run `./cloak.sh --rebuild` to rebuild the image.
