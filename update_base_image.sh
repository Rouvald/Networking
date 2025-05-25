#!/bin/bash

set -e

# === settings ===
USERNAME="rouvald"
REPO="gcc14_conan"
IMAGE="ghcr.io/${USERNAME}/${REPO}"

# === get sha cur commit ===
SHA=$(git rev-parse --short HEAD)
TAG_SHA="sha-${SHA}"
TAG_LATEST="latest"

echo "Building base image with tags: $TAG_SHA, $TAG_LATEST"

# === Auth  GitHub Container Registry ===
if [ -f .env ]; then
  source .env
fi

if [ -z "$GITHUB_TOKEN" ]; then
  echo "GITHUB_TOKEN don't set"
  exit 1
fi

echo "Logging in to GitHub Container Registry..."
echo "${GITHUB_TOKEN}" | docker login ghcr.io -u "${USERNAME}" --password-stdin

# === Build ===
docker build -f docker/Dockerfile.base -t "${IMAGE}:${TAG_SHA}" .

# === setup latest tag ===
docker tag "${IMAGE}:${TAG_SHA}" "${IMAGE}:${TAG_LATEST}"

# === push ===
echo "Pushing image: $TAG_SHA"
docker push "${IMAGE}:${TAG_SHA}"

echo "Pushing image: $TAG_LATEST"
docker push "${IMAGE}:${TAG_LATEST}"

echo "Base image updated: ${IMAGE}:${TAG_SHA} and :latest"