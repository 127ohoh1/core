#!/usr/bin/env bash
# Reproducible fault injection against the running Docker Compose stack.
# Prerequisite:   make up   (in another terminal, or: docker compose ... up -d)
#                 docker compose -f deploy/docker/compose.yaml --profile multi-edge up -d edge-2   (for scenario D)
# Each scenario asserts an invariant from docs/failure-model.md and exits non-zero on violation.
set -euo pipefail
cd "$(dirname "$0")/../.."
export OHOH_UID="${OHOH_UID:-$(id -u)}" OHOH_GID="${OHOH_GID:-$(id -g)}"
DC="docker compose -f deploy/docker/compose.yaml"
INGRESS="${OHOH_INGRESS_PORT:-8443}"; ADMIN="${OHOH_EDGE_ADMIN_PORT:-19100}"
CA=.devtls/ca.pem
pass=0; failn=0
ok()  { echo "  PASS: $*"; pass=$((pass+1)); }
bad() { echo "  FAIL: $*"; failn=$((failn+1)); }

host() { $DC logs demo-client 2>&1 | grep -o '[a-z0-9-]*\.127ohoh1\.localhost' | tail -1; }
get()  { curl -sS --max-time 15 --cacert "$CA" --resolve "$1:$INGRESS:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$1:$INGRESS/${2:-}" 2>/dev/null || echo "000"; }
metric() { curl -s "http://127.0.0.1:$ADMIN/metrics" | awk -v m="$1" '$1==m {print $2}'; }
# wait_for N cmd...   re-runs the command (a function name!) up to N times, one second apart.
# Note: never pass a "$(command substitution)" here: it would be expanded once, before the loop.
wait_for() { local n=$1; shift; for _ in $(seq 1 "$n"); do "$@" && return 0; sleep 1; done; return 1; }
cp_reachable()   { [ "$(metric edge_control_plane_reachable)" = 1 ]; }
cp_unreachable() { [ "$(metric edge_control_plane_reachable)" = 0 ]; }
serving()      { [ "$(get "$H")" = 200 ]; }
serving_via_edge2() { [ "$(curl -sS --max-time 15 --cacert "$CA" --resolve "$H:${OHOH_INGRESS2_PORT:-8444}:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$H:${OHOH_INGRESS2_PORT:-8444}/" 2>/dev/null)" = 200 ]; }

H=$(host); [ -n "$H" ] || { echo "demo-client has not exposed a URL yet; is the stack up?"; exit 2; }
echo "tenant host: $H"
[ "$(get "$H")" = 200 ] && ok "baseline request through the tunnel" || bad "baseline"

echo "== A. control plane outage (docker pause): established tunnel must keep serving from cached policy"
$DC pause control-plane >/dev/null
# A *paused* (hung) dependency is detected only when an in-flight call times out (change-feed long poll
# ~30 s or a refresh timeout), unlike a refused connection which fails immediately. Wait for detection.
wait_for 90 cp_unreachable && ok "outage detected by the edge (edge_control_plane_reachable=0)" || bad "outage never detected: edge_control_plane_reachable=$(metric edge_control_plane_reachable)"
codes=""; for i in 1 2 3 4 5; do codes="$codes $(get "$H" "during-outage-$i")"; done
[ "$(echo $codes | tr ' ' '\n' | sort -u)" = 200 ] && ok "5/5 requests served during the outage" || bad "requests failed during the outage: $codes"
$DC unpause control-plane >/dev/null
wait_for 60 cp_reachable && ok "recovered automatically" || bad "did not recover"
[ "$(get "$H")" = 200 ] && ok "serving after recovery, same tunnel" || bad "post-recovery request"

echo "== B. edge restart: client must reconnect and the same name must serve again"
$DC restart edge >/dev/null
wait_for 90 serving && ok "same hostname serving again after an edge restart" || bad "hostname did not come back"

echo "== C. Redis unavailable (docker pause): local traffic must be unaffected"
$DC pause redis >/dev/null
sleep 3
[ "$(get "$H" c1)" = 200 ] && ok "local request served while Redis is paused" || bad "local routing broke without Redis"
$DC unpause redis >/dev/null

echo "== D. multi-edge: a request to the wrong edge is forwarded to the owner (needs the multi-edge profile)"
if $DC ps --status running --services 2>/dev/null | grep -qx edge-2; then
  P2="${OHOH_INGRESS2_PORT:-8444}"
  wait_for 40 serving_via_edge2 \
    && ok "edge-2 forwarded to the owning edge-1" || bad "cross-edge request failed"
  hop=$(curl -sSI --cacert "$CA" --resolve "$H:$P2:127.0.0.1" "https://$H:$P2/" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="x-127ohoh1-hop"{print $2}')
  [ "$hop" = 1 ] && ok "response marked with X-127ohoh1-Hop: 1" || bad "missing hop header (got '$hop')"
else
  echo "  SKIP: edge-2 is not running (start it with --profile multi-edge)"
fi

echo; echo "passed=$pass failed=$failn"; [ "$failn" = 0 ]
