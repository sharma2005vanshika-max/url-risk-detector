#!/usr/bin/env bash

# AegisGuard - URL Risk Detector Startup Script
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================================="
echo "🛡️  AegisGuard | Next-Gen URL Risk & Threat Intelligence"
echo "=========================================================="
echo ""
echo "Starting unified server on http://localhost:5001 ..."
echo "Serving both Backend Threat API and Frontend Web UI"
echo ""

cd "$DIR/server"
node server.js
