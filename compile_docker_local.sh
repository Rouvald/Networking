#!/bin/bash

set -e

IMAGE_NAME="local-build-image"
CONTAINER_NAME="local-build-temp"
ARTIFACTS_DIR="artifacts"

echo "Build project local..."

# update base image
docker pull ghcr.io/rouvald/gcc14_conan:latest

# build project image
docker build -f docker/Dockerfile.build -t $IMAGE_NAME .

# remove old container
docker rm -f $CONTAINER_NAME 2>/dev/null || true

# run build container
docker create --name $CONTAINER_NAME $IMAGE_NAME

# remove old artifacts
rm -rf $ARTIFACTS_DIR

# extract binaries
echo "Extract binaries into [$ARTIFACTS_DIR]..."
mkdir -p $ARTIFACTS_DIR
docker cp $CONTAINER_NAME:/app/build_linux_Release/bin/. $ARTIFACTS_DIR/

# remove project container
docker rm -f $CONTAINER_NAME

echo "Binaries saved into $ARTIFACTS_DIR/"