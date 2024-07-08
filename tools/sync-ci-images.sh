#! /bin/bash

# This script pulls the images we use in our tests from Docker to the Github
# Container Registry to avoid rate limiting issues.

set -euo pipefail

sync_image () {
  docker pull docker.io/library/$1
  docker tag docker.io/library/$1 ghcr.io/inspektor-gadget/ci/$1
  docker push ghcr.io/inspektor-gadget/ci/$1
}

sync_image busybox:latest
sync_image nginx:latest
sync_image registry:2
