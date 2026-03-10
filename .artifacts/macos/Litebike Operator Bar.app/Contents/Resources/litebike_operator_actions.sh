#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="${LITEBIKE_REPO_ROOT:-$DEFAULT_REPO_ROOT}"

cd "$REPO_ROOT"

ensure_repo() {
    if [[ ! -d "$REPO_ROOT/.git" ]]; then
        echo "litebike workspace not found at $REPO_ROOT" >&2
        exit 1
    fi
}

resolve_host() {
    if [[ -n "${LB_HOST:-}" ]]; then
        printf '%s\n' "$LB_HOST"
        return
    fi
    if [[ -n "${TERMUX_HOST:-}" ]]; then
        printf '%s\n' "$TERMUX_HOST"
        return
    fi
    route get default 2>/dev/null | awk '/gateway:/{print $2; exit}' || true
}

resolve_user() {
    printf '%s\n' "${LB_USER:-${TERMUX_USER:-u0_a471}}"
}

resolve_port() {
    printf '%s\n' "${LB_SSH_PORT:-${TERMUX_PORT:-8022}}"
}

require_remote_host() {
    local host
    host="$(resolve_host)"
    if [[ -z "$host" ]]; then
        echo "Set LB_HOST or TERMUX_HOST before running remote actions." >&2
        exit 1
    fi
    printf '%s\n' "$host"
}

build_release() {
    ensure_repo
    echo "[build-release] repo=$REPO_ROOT"
    cargo build --release
}

git_push_current() {
    ensure_repo
    local branch
    branch="$(git rev-parse --abbrev-ref HEAD)"
    echo "[git-push-current] branch=$branch"
    git push -u origin "$branch"
}

sync_termux() {
    ensure_repo
    echo "[sync-termux] repo=$REPO_ROOT"
    "$REPO_ROOT/scripts/sync_termux.sh"
}

proxy_status() {
    ensure_repo
    echo "[proxy-status] repo=$REPO_ROOT"
    "$REPO_ROOT/s/proxy-bridge" status
}

proxy_stop() {
    ensure_repo
    echo "[proxy-stop] repo=$REPO_ROOT"
    "$REPO_ROOT/s/proxy-bridge" stop
}

proxy_ssh() {
    ensure_repo
    local host user port
    host="$(require_remote_host)"
    user="$(resolve_user)"
    port="$(resolve_port)"
    echo "[proxy-ssh] host=$host user=$user port=$port"
    "$REPO_ROOT/s/proxy-bridge" ssh "$host" "$user" "$port"
}

deploy_remote() {
    ensure_repo
    local host user port branch lb_dir remote_build_cmd remote_after_build_cmd
    host="$(require_remote_host)"
    user="$(resolve_user)"
    port="$(resolve_port)"
    branch="$(git rev-parse --abbrev-ref HEAD)"
    lb_dir="${LB_DIR:-/opt/litebike}"
    remote_build_cmd="${LB_REMOTE_BUILD_CMD:-cargo build --release}"
    remote_after_build_cmd="${LB_REMOTE_AFTER_BUILD_CMD:-}"

    echo "[deploy-remote] pushing branch=$branch"
    git push -u origin "$branch"

    echo "[deploy-remote] host=$host user=$user port=$port dir=$lb_dir"
    ssh -A -p "$port" -o StrictHostKeyChecking=accept-new \
        "$user@$host" \
        BRANCH="$branch" \
        LB_DIR="$lb_dir" \
        REMOTE_BUILD_CMD="$remote_build_cmd" \
        REMOTE_AFTER_BUILD_CMD="$remote_after_build_cmd" \
        'bash -s' <<'REMOTE'
set -euo pipefail

mkdir -p "$LB_DIR"
if [[ -d "$LB_DIR/.git" ]]; then
    cd "$LB_DIR"
    git fetch --all --prune
    git checkout "$BRANCH"
    git pull --ff-only origin "$BRANCH"
else
    git clone --depth=1 https://github.com/jnorthrup/litebike "$LB_DIR"
    cd "$LB_DIR"
    git checkout "$BRANCH" || true
    git pull --ff-only origin "$BRANCH" || true
fi

eval "$REMOTE_BUILD_CMD"

if [[ -n "${REMOTE_AFTER_BUILD_CMD:-}" ]]; then
    eval "$REMOTE_AFTER_BUILD_CMD"
fi
REMOTE
}

open_ssh_terminal() {
    ensure_repo
    local host user port command escaped_command
    host="$(require_remote_host)"
    user="$(resolve_user)"
    port="$(resolve_port)"
    printf -v command 'cd %q; ssh -A -p %q -o StrictHostKeyChecking=accept-new %q' \
        "$REPO_ROOT" "$port" "$user@$host"
    escaped_command="$(printf '%s' "$command" | sed 's/\\/\\\\/g; s/"/\\"/g')"

    echo "[open-ssh-terminal] host=$host user=$user port=$port"
    /usr/bin/osascript <<OSA
tell application "Terminal"
    activate
    do script "$escaped_command"
end tell
OSA
}

show_help() {
    cat <<'EOF'
Usage: litebike_operator_actions.sh <action>

Actions:
  build-release      Build the litebike workspace in release mode
  git-push-current   Push the current branch to origin with upstream tracking
  deploy-remote      Push the current branch and build the repo on the remote host
  proxy-status       Show proxy-bridge status
  proxy-ssh          Start the remote proxy over SSH using proxy-bridge
  proxy-stop         Stop local proxy-bridge services
  sync-termux        Fetch the termux remote into local tracking branches
  open-ssh-terminal  Open an interactive SSH session in Terminal.app

Environment:
  LITEBIKE_REPO_ROOT        Override the workspace root
  LB_HOST / TERMUX_HOST     Remote host for SSH actions
  LB_USER / TERMUX_USER     Remote SSH username
  LB_SSH_PORT / TERMUX_PORT Remote SSH port
  LB_DIR                    Remote litebike checkout path
  LB_REMOTE_BUILD_CMD       Remote build command for deploy-remote
  LB_REMOTE_AFTER_BUILD_CMD Optional follow-up command after remote build
EOF
}

case "${1:-help}" in
    build-release)
        build_release
        ;;
    git-push-current)
        git_push_current
        ;;
    deploy-remote)
        deploy_remote
        ;;
    proxy-status)
        proxy_status
        ;;
    proxy-ssh)
        proxy_ssh
        ;;
    proxy-stop)
        proxy_stop
        ;;
    sync-termux)
        sync_termux
        ;;
    open-ssh-terminal)
        open_ssh_terminal
        ;;
    help|--help|-h|*)
        show_help
        ;;
esac
