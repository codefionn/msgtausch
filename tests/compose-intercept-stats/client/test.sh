#!/bin/sh
set -eu

# Bound every request so a stalled proxy/MITM connection fails the test
# instead of hanging the container (and the whole `docker compose up`) forever.
CURL="curl -sS --fail --connect-timeout 5 --max-time 20"

echo "[client] Waiting for proxy and backends to be ready..."
ready=0
for i in $(seq 1 60); do
  if $CURL --proxy "$HTTP_PROXY" http://msgtausch.internal/ >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "[client] Proxy not ready after 60s, aborting"
  exit 1
fi

echo "[client] Testing HTTP via proxy..."
HTTP_OUT=$($CURL --proxy "$HTTP_PROXY" http://http-backend:5678/)
case "$HTTP_OUT" in
  *hello-http*path=/*) ;;
  *) echo "Unexpected HTTP response: $HTTP_OUT"; exit 1;;
esac
echo "[client] HTTP OK: $HTTP_OUT"

echo "[client] Testing HTTPS via proxy (MITM) with test CA..."
# Use the CA used by the proxy for MITM certs
HTTPS_OUT=$($CURL --proxy "$HTTPS_PROXY" --cacert /ca/test_ca.crt https://https-backend:8443/)

case "$HTTPS_OUT" in
  *hello-https*path=/*) ;;
  *) echo "Unexpected HTTPS response: $HTTPS_OUT"; exit 1;;
esac
echo "[client] HTTPS OK: $HTTPS_OUT"

echo "[client] Testing HTTP /curl-http endpoint..."
CURL_HTTP_OUT=$($CURL --proxy "$HTTP_PROXY" http://http-backend:5678/curl-http)
case "$CURL_HTTP_OUT" in
  *curl-http-response*path=/curl-http*method=GET*) ;;
  *) echo "Unexpected HTTP /curl-http response: $CURL_HTTP_OUT"; exit 1;;
esac
echo "[client] HTTP /curl-http OK: $CURL_HTTP_OUT"

echo "[client] Testing HTTPS /curl-https endpoint..."
CURL_HTTPS_OUT=$($CURL --proxy "$HTTPS_PROXY" --cacert /ca/test_ca.crt https://https-backend:8443/curl-https)
case "$CURL_HTTPS_OUT" in
  *curl-https-response*path=/curl-https*method=GET*) ;;
  *) echo "Unexpected HTTPS /curl-https response: $CURL_HTTPS_OUT"; exit 1;;
esac
echo "[client] HTTPS /curl-https OK: $CURL_HTTPS_OUT"

echo "[client] Testing HTTP /connect endpoint..."
CONNECT_OUT=$($CURL --proxy "$HTTP_PROXY" http://http-backend:5678/connect)
case "$CONNECT_OUT" in
  *connect-response*path=/connect*method=GET*) ;;
  *) echo "Unexpected HTTP /connect response: $CONNECT_OUT"; exit 1;;
esac
echo "[client] HTTP /connect OK: $CONNECT_OUT"

echo "[client] All tests passed."
