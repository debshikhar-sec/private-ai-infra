#!/usr/bin/env bash
echo "=== Private AI Lab Status ==="
if lsof -i :8081 -sTCP:LISTEN -t >/dev/null; then echo "[✓] Nginx Proxy: RUNNING (Port 8081)"; else echo "[✗] Nginx Proxy: DOWN"; fi
if lsof -i :8080 -sTCP:LISTEN -t >/dev/null; then echo "[✓] Flask Gateway: RUNNING (Port 8080)"; else echo "[✗] Flask Gateway: DOWN"; fi
echo "============================="
