#!/bin/bash

set -e

# args
ROLE=""
IP_ARG=""
NETWORK_NAME="networking-net"
IMAGE_NAME="networking_runtime"

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -s|--server) ROLE="server" ;;
    -c|--client) ROLE="client" ;;
    --ip) shift; IP_ARG="$1" ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
  shift
done

if [[ -z "$ROLE" ]]; then
  echo "Set run role: -s (server) or -c (client)"
  exit 1
fi

CONTAINER_NAME="networking_$ROLE"

# Create focker net
if ! docker network ls --format '{{.Name}}' | grep -q "^$NETWORK_NAME\$"; then
  echo "Create focker net $NETWORK_NAME..."
  docker network create $NETWORK_NAME
fi

echo "Build Dockerfile.run..."
docker build -f docker/Dockerfile.run -t $IMAGE_NAME --build-arg ROLE=$ROLE .

# Remove old comtainer
if docker ps -a --format '{{.Names}}' | grep -Eq "^$CONTAINER_NAME\$"; then
  echo "Remove old container $CONTAINER_NAME"
  docker rm -f $CONTAINER_NAME
fi

# Update run command
RUN_CMD="./$ROLE"
if [[ -n "$IP_ARG" ]]; then
  RUN_CMD="$RUN_CMD $IP_ARG"
fi

# Run container
echo "Run container ($ROLE) с IP: ${IP_ARG:-<none>}"
docker run -it --rm --network $NETWORK_NAME --name $CONTAINER_NAME $IMAGE_NAME bash -c "$RUN_CMD"