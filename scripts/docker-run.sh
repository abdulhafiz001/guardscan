#!/bin/bash

# GuardScan Docker Run Script
# This script builds and runs the GuardScan container

echo "🚀 Building GuardScan Docker image..."
docker compose build

echo ""
echo "🔍 Starting GuardScan Web Container (http://localhost:5000)..."
docker compose up -d guardscan-web

echo ""
echo "✅ GuardScan is running! Visit http://localhost:5000"
