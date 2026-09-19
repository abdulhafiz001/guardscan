#!/bin/bash

# GuardScan Docker Quick Commands
# Reference for common Docker operations

echo "🔍 GuardScan Docker Commands"
echo "=============================="
echo ""

case "${1}" in
  build)
    echo "Building Docker image..."
    docker compose build
    ;;
  
  web)
    echo "Starting GuardScan Web Dashboard..."
    docker compose up -d guardscan-web
    ;;

  cli)
    echo "Running GuardScan CLI..."
    docker compose run --rm guardscan-cli
    ;;

  shell)
    echo "Opening shell in container..."
    docker compose run --rm --entrypoint /bin/bash guardscan-web
    ;;

  clean)
    echo "Cleaning up Docker resources..."
    docker compose down
    docker system prune -f
    ;;
  
  logs)
    echo "Showing container logs..."
    docker compose logs -f guardscan-web
    ;;
  
  update)
    echo "Rebuilding image (no cache)..."
    docker compose build --no-cache
    ;;
  
  *)
    echo "Usage: $0 {build|web|cli|shell|clean|logs|update}"
    echo ""
    echo "Commands:"
    echo "  web     - Start GuardScan Web Dashboard (recommended)"
    echo "  cli     - Run GuardScan CLI interactively"
    echo "  build   - Build Docker image"
    echo "  shell   - Open bash shell inside container"
    echo "  logs    - Follow container logs"
    echo "  clean   - Stop containers and cleanup"
    echo "  update  - Rebuild image with --no-cache"
    exit 1
    ;;
esac
