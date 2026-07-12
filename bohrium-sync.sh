#!/usr/bin/env bash
# 将本地最新代码同步到 Bohrium，并在 50000 端口以 Docker 方式运行验收。
# 依赖：本机 termark CLI、已配置资产 "Bohrium"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ASSET_ID="${BOHRIUM_ASSET_ID:-CVUp6HKjbry42uzd}"
REMOTE_DIR="${BOHRIUM_DIR:-/opt/vps-probe}"
HOST_PORT="${BOHRIUM_PORT:-50000}"

echo "[1/5] 上传文件 -> Bohrium:${REMOTE_DIR}"
termark upload "$ASSET_ID" "$ROOT/probe.py" "$REMOTE_DIR/probe.py"
termark upload "$ASSET_ID" "$ROOT/requirements.txt" "$REMOTE_DIR/requirements.txt"
termark upload "$ASSET_ID" "$ROOT/Dockerfile" "$REMOTE_DIR/Dockerfile"
termark upload "$ASSET_ID" "$ROOT/.dockerignore" "$REMOTE_DIR/.dockerignore"

echo "[2/5] 停止旧进程 / 容器"
termark exec "$ASSET_ID" "docker rm -f vps-probe 2>/dev/null || true; pkill -f '/opt/vps-probe/probe' 2>/dev/null || true; sleep 1; true"

echo "[3/5] 构建镜像"
termark exec "$ASSET_ID" "cd $REMOTE_DIR && docker build -t vps-probe . > /tmp/vps-docker-build.log 2>&1; tail -5 /tmp/vps-docker-build.log; grep -q 'naming to docker.io/library/vps-probe' /tmp/vps-docker-build.log || grep -q 'Successfully tagged' /tmp/vps-docker-build.log || (tail -40 /tmp/vps-docker-build.log; exit 1)"

echo "[4/5] 启动容器 :${HOST_PORT}->8080"
termark exec "$ASSET_ID" "docker run -d --name vps-probe --restart unless-stopped -p ${HOST_PORT}:8080 vps-probe && sleep 4 && docker ps --filter name=vps-probe --format '{{.Status}} {{.Ports}}'"

echo "[5/5] 验收"
termark exec "$ASSET_ID" "curl -sS --max-time 5 http://127.0.0.1:${HOST_PORT}/health; echo; curl -sS --max-time 5 http://127.0.0.1:${HOST_PORT}/api/status | python3 -c 'import sys,json;d=json.load(sys.stdin);print(\"version\",d.get(\"version\"),\"collect_ms\",d.get(\"collect_ms\"),\"host\",(d.get(\"system\") or {}).get(\"hostname\"))'"

echo "完成: http://<Bohrium-IP>:${HOST_PORT}/"
