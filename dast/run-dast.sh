#!/bin/sh
# Start both apps, actively scan each with OWASP ZAP, write reports to dast/reports/.
set -e
cd "$(dirname "$0")"
mkdir -p reports && chmod 777 reports
docker compose up -d --build
sleep 5
for target in vulnerable fixed; do
  docker run --rm --network dast_default -v "$PWD:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
    -t /zap/wrk/openapi.yaml -f openapi -O "http://$target:5000" \
    -r "reports/$target.html" -J "reports/$target.json" -I || true
done
docker compose down
