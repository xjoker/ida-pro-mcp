#!/usr/bin/env bash
# v1.5 smoke test driver — automates the validation flow.
#
# Usage:
#   bash tests/smoke/verify.sh           # full flow (build + up + probe + down)
#   bash tests/smoke/verify.sh up        # build & start
#   bash tests/smoke/verify.sh probe     # send requests, check responses
#   bash tests/smoke/verify.sh down      # stop & remove containers

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.smoke.yml"

COORDINATOR_URL="http://127.0.0.1:9000"
WAIT_TIMEOUT_SEC=60

color() {
    local color_code="$1"; shift
    printf '\033[%sm%s\033[0m\n' "${color_code}" "$*"
}
log()   { color "1;36" "[smoke] $*"; }
ok()    { color "1;32" "[ ok ] $*"; }
fail()  { color "1;31" "[fail] $*" >&2; }

wait_for_url() {
    local url="$1" deadline=$(( $(date +%s) + WAIT_TIMEOUT_SEC ))
    while [[ $(date +%s) -lt $deadline ]]; do
        if curl -sf -o /dev/null --max-time 3 "$url"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

cmd_up() {
    log "Building images & starting services…"
    docker compose -f "$COMPOSE_FILE" up -d --build
    log "Waiting for coordinator at $COORDINATOR_URL/coordinator/health …"
    if wait_for_url "$COORDINATOR_URL/coordinator/health"; then
        ok "Coordinator reachable"
    else
        fail "Coordinator did not become healthy within ${WAIT_TIMEOUT_SEC}s"
        docker compose -f "$COMPOSE_FILE" logs --tail=50 coordinator
        return 1
    fi
}

cmd_probe() {
    log "=== Probe 1: coordinator health ==="
    curl -sf "$COORDINATOR_URL/coordinator/health" | python3 -m json.tool

    log "=== Probe 2: list workers (should see 2 mock workers) ==="
    local workers
    workers=$(curl -sf "$COORDINATOR_URL/coordinator/health" | python3 -c "import json,sys;d=json.load(sys.stdin);print(len(d.get('workers',[])))")
    if [[ "$workers" -ge 2 ]]; then
        ok "Found ${workers} workers in registry"
    else
        fail "Expected ≥2 workers, found ${workers}"
        return 1
    fi

    log "=== Probe 3: tools/list via coordinator (forwards to a worker) ==="
    local resp
    resp=$(curl -sf -X POST "$COORDINATOR_URL/mcp" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    echo "$resp" | python3 -m json.tool

    if echo "$resp" | grep -q "mock_decompile"; then
        ok "tools/list forwarded successfully; mock_decompile present"
    else
        fail "tools/list response missing expected mock_decompile tool"
        return 1
    fi

    log "=== Probe 4: IDB affinity routing ==="
    log "  Calling tools/call with arguments.database=/demo/sample.idb"
    log "  Expecting routing to mock-worker-1 (which simulates loaded_idb=/demo/sample.idb)"
    resp=$(curl -sf -X POST "$COORDINATOR_URL/mcp" \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mock_decompile","arguments":{"database":"/demo/sample.idb","ea":"0x401000"}}}')
    echo "$resp" | python3 -m json.tool

    if echo "$resp" | grep -q "mock-worker"; then
        ok "tools/call routed and returned worker-tagged response"
    else
        fail "tools/call did not return expected mock response"
        return 1
    fi

    log "=== Probe 5: container resource snapshot ==="
    docker stats --no-stream --format \
        "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" \
        $(docker compose -f "$COMPOSE_FILE" ps -q) || true
}

cmd_down() {
    log "Stopping services & removing containers / volumes…"
    docker compose -f "$COMPOSE_FILE" down -v
    ok "Cleaned up"
}

cmd_logs() {
    docker compose -f "$COMPOSE_FILE" logs --tail=100 -f "${1:-}"
}

main() {
    local cmd="${1:-all}"
    case "$cmd" in
        up)     cmd_up ;;
        probe)  cmd_probe ;;
        down)   cmd_down ;;
        logs)   shift || true; cmd_logs "$@" ;;
        all|"")
            cmd_up
            sleep 8  # let workers register + heartbeat at least once
            cmd_probe
            log "Smoke flow PASSED. Tearing down… (use 'up' next time to keep running)"
            cmd_down
            ;;
        *)
            cat <<EOF
Usage: $0 {up|probe|down|logs [svc]|all}
  up     — build & start
  probe  — run validation requests against running stack
  down   — stop & remove
  logs   — tail logs (optional service name)
  all    — up + probe + down (default)
EOF
            exit 1
            ;;
    esac
}

main "$@"
