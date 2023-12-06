#!/usr/bin/env bash
set -eu

# Check environment
if [ -z "${AWS_PROFILE}" ]; then
  echo "ERROR: AWS_PROFILE is not set"
  exit 1
fi

# Check that config file exists
if [ ! -f "$HOME/.rds_proxy/config.json" ]; then
  echo "ERROR: Config file not found at $HOME/.rds_proxy/config.yml"
  exit 1
fi

# Build docker image if '--build' is passed
if [ "${1:-}" = "--build" ]; then
  docker build -t rds_proxy:latest .
  shift
fi

# Run docker container with AWS credentials and config mounted
docker run --rm -it -u "$(id -u):$(id -g)" \
  -p 5435:5435 \
  -v $HOME/.aws:/home/rdsproxy/.aws \
  -v $HOME/.rds_proxy:/etc/rds_proxy \
  -e AWS_PROFILE="${AWS_PROFILE}" \
  -e HOME=/home/rdsproxy \
  rds_proxy:latest "${@}"
