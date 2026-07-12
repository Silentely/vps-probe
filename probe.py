#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPS Probe — 极简单页 VPS 探针监控
零配置、零数据库、内嵌前端，默认监听 0.0.0.0:8080
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
import traceback
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Deque, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import psutil
except ImportError:
    print("缺少依赖 psutil，请执行: pip3 install -r requirements.txt")
    raise SystemExit(1)

# ---------------------------------------------------------------------------
# 内置常量（无环境变量、无配置文件）
# ---------------------------------------------------------------------------
VERSION = "1.0.0"
HOST = "0.0.0.0"
PORT = 8080

METRICS_INTERVAL = 2.0          # 系统指标采集间隔（秒）
PING_INTERVAL = 10.0            # Ping 调度间隔（秒）
PING_TIMEOUT = 2                # 单次 Ping 超时（秒）
PING_HISTORY_SIZE = 30          # 每目标保留的延迟样本数
EVENT_MAX = 100                 # 事件最多保留条数
EVENT_DEDUP_WINDOW = 60.0       # 相同异常限频窗口（秒）
WARN_USAGE = 80.0               # 使用率警告阈值 %
DANGER_USAGE = 90.0             # 使用率危险阈值 %
WARN_LATENCY_MS = 100.0
DANGER_LATENCY_MS = 300.0
WARN_LOSS = 20.0
DANGER_LOSS = 50.0

PING_TARGETS: List[Dict[str, str]] = [
    {"id": "cf_dns", "name": "Cloudflare DNS", "host": "1.1.1.1"},
    {"id": "google_dns", "name": "Google DNS", "host": "8.8.8.8"},
    {"id": "quad9", "name": "Quad9 DNS", "host": "9.9.9.9"},
    {"id": "cf_web", "name": "Cloudflare", "host": "cloudflare.com"},
    {"id": "google_web", "name": "Google", "host": "google.com"},
    {"id": "github", "name": "GitHub", "host": "github.com"},
]

# ---------------------------------------------------------------------------
# 全局状态（单进程、锁保护；后台任务只启动一次）
# ---------------------------------------------------------------------------
_state_lock = threading.RLock()
_start_time = time.time()
_workers_started = False
_workers_lock = threading.Lock()

_metrics: Dict[str, Any] = {}
_metrics_collect_ms = 0.0
_metrics_updated_at = 0.0
_prev_net: Optional[Tuple[int, int, float]] = None  # bytes_sent, bytes_recv, ts

_ping_available: Optional[bool] = None
_ping_results: Dict[str, Dict[str, Any]] = {}
_ping_history: Dict[str, Deque[float]] = {
    t["id"]: deque(maxlen=PING_HISTORY_SIZE) for t in PING_TARGETS
}
_ping_prev_online: Dict[str, Optional[bool]] = {t["id"]: None for t in PING_TARGETS}
_ping_updated_at = 0.0

_events: Deque[Dict[str, Any]] = deque(maxlen=EVENT_MAX)
_event_last: Dict[str, float] = {}  # key -> last emit ts

_prev_alerts: Dict[str, bool] = {
    "cpu": False,
    "load": False,
    "mem": False,
    "disk": False,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _level_ok(level: str) -> str:
    level = (level or "INFO").upper()
    if level not in ("INFO", "OK", "WARN", "ERROR"):
        return "INFO"
    return level


def add_event(level: str, message: str, dedup_key: Optional[str] = None) -> None:
    """追加事件；相同 dedup_key 在限频窗口内不重复写入（含 OK）。

    恢复类事件应使用与告警不同的 dedup_key（如 xxx_ok），
    从而在状态翻转时仍能立即输出一次恢复消息。
    """
    level = _level_ok(level)
    key = dedup_key or f"{level}:{message}"
    now = time.time()
    with _state_lock:
        last = _event_last.get(key)
        if last is not None and (now - last) < EVENT_DEDUP_WINDOW:
            return
        _event_last[key] = now
        _events.appendleft(
            {
                "ts": _now_iso(),
                "level": level,
                "message": message,
            }
        )


def _status_from_pct(pct: Optional[float]) -> str:
    if pct is None:
        return "unknown"
    if pct >= DANGER_USAGE:
        return "danger"
    if pct >= WARN_USAGE:
        return "warn"
    return "ok"


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# 系统指标采集
# ---------------------------------------------------------------------------
def _read_os_release() -> Tuple[str, str]:
    name, version = "Linux", ""
    path = "/etc/os-release"
    try:
        if os.path.isfile(path):
            data: Dict[str, str] = {}
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    data[k] = v.strip().strip('"')
            name = data.get("PRETTY_NAME") or data.get("NAME") or name
            version = data.get("VERSION_ID") or data.get("VERSION") or ""
            return name, version
    except OSError:
        pass
    # macOS / 其他
    system = platform.system() or "Unknown"
    release = platform.release() or ""
    if system == "Darwin":
        try:
            out = subprocess.run(
                ["sw_vers", "-productVersion"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                return "macOS", out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return "macOS", release
    return system, release


def _cpu_model() -> str:
    try:
        if platform.system() == "Linux" and os.path.isfile("/proc/cpuinfo"):
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        return line.split(":", 1)[1].strip()
                    if line.lower().startswith("hardware") and "model name" not in line.lower():
                        # 部分 ARM
                        val = line.split(":", 1)[1].strip()
                        if val:
                            return val
        # macOS
        if platform.system() == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return platform.processor() or "Unknown"


def collect_metrics() -> Tuple[Dict[str, Any], float]:
    """从当前主机真实读取系统数据，返回 (指标字典, 采集耗时毫秒)。"""
    global _prev_net

    t0 = time.perf_counter()
    os_name, os_version = _read_os_release()
    boot_ts = psutil.boot_time()
    uptime_sec = max(0, int(time.time() - boot_ts))

    # CPU
    try:
        cpu_percent = float(psutil.cpu_percent(interval=0.15))
    except Exception:
        cpu_percent = 0.0
    try:
        physical = psutil.cpu_count(logical=False) or 0
        logical = psutil.cpu_count(logical=True) or 0
    except Exception:
        physical, logical = 0, 0

    # Load
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = 0.0

    # Memory / Swap
    try:
        vm = psutil.virtual_memory()
        mem_total = int(vm.total)
        mem_used = int(vm.used)
        mem_available = int(vm.available)
        mem_percent = float(vm.percent)
    except Exception:
        mem_total = mem_used = mem_available = 0
        mem_percent = 0.0

    try:
        sm = psutil.swap_memory()
        swap_total = int(sm.total)
        swap_used = int(sm.used)
        swap_percent = float(sm.percent)
    except Exception:
        swap_total = swap_used = 0
        swap_percent = 0.0

    # Disk (root)
    try:
        du = psutil.disk_usage("/")
        disk_total = int(du.total)
        disk_used = int(du.used)
        disk_free = int(du.free)
        disk_percent = float(du.percent)
    except Exception:
        disk_total = disk_used = disk_free = 0
        disk_percent = 0.0

    # Users / processes
    try:
        users = len(psutil.users())
    except Exception:
        users = 0
    try:
        processes = len(psutil.pids())
    except Exception:
        processes = 0

    # Network totals + rates
    net_sent = net_recv = 0
    up_rate = down_rate = 0.0
    try:
        io = psutil.net_io_counters()
        if io is not None:
            net_sent = int(io.bytes_sent)
            net_recv = int(io.bytes_recv)
            now = time.time()
            if _prev_net is not None:
                ps, pr, pt = _prev_net
                dt = max(now - pt, 1e-6)
                # 计数器重置时避免负速率
                if net_sent >= ps:
                    up_rate = (net_sent - ps) / dt
                if net_recv >= pr:
                    down_rate = (net_recv - pr) / dt
            _prev_net = (net_sent, net_recv, now)
    except Exception:
        pass

    collect_ms = (time.perf_counter() - t0) * 1000.0

    data = {
        "hostname": socket.gethostname(),
        "os_name": os_name,
        "os_version": os_version,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": _cpu_model(),
        "cpu_physical_cores": physical,
        "cpu_logical_cores": logical,
        "cpu_percent": round(cpu_percent, 1),
        "cpu_status": _status_from_pct(cpu_percent),
        "load_1": round(load1, 2),
        "load_5": round(load5, 2),
        "load_15": round(load15, 2),
        "memory_total": mem_total,
        "memory_used": mem_used,
        "memory_available": mem_available,
        "memory_percent": round(mem_percent, 1),
        "memory_status": _status_from_pct(mem_percent),
        "swap_total": swap_total,
        "swap_used": swap_used,
        "swap_percent": round(swap_percent, 1),
        "swap_status": _status_from_pct(swap_percent if swap_total else 0),
        "disk_total": disk_total,
        "disk_used": disk_used,
        "disk_free": disk_free,
        "disk_percent": round(disk_percent, 1),
        "disk_status": _status_from_pct(disk_percent),
        "boot_time": datetime.fromtimestamp(boot_ts).astimezone().isoformat(timespec="seconds"),
        "uptime_seconds": uptime_sec,
        "users": users,
        "processes": processes,
        "net_bytes_sent": net_sent,
        "net_bytes_recv": net_recv,
        "net_up_rate": round(up_rate, 1),
        "net_down_rate": round(down_rate, 1),
    }

    # 告警事件（状态边沿 + 限频）
    _emit_metric_alerts(data)
    return data, collect_ms


def _emit_metric_alerts(data: Dict[str, Any]) -> None:
    cpu = _safe_float(data.get("cpu_percent"))
    mem = _safe_float(data.get("memory_percent"))
    disk = _safe_float(data.get("disk_percent"))
    load1 = _safe_float(data.get("load_1"))
    cores = max(int(data.get("cpu_logical_cores") or 1), 1)
    load_ratio = (load1 / cores) * 100.0

    checks = [
        ("cpu", cpu >= WARN_USAGE, "WARN" if cpu < DANGER_USAGE else "ERROR",
         f"CPU 使用率过高: {cpu:.1f}%", "cpu_high"),
        ("mem", mem >= WARN_USAGE, "WARN" if mem < DANGER_USAGE else "ERROR",
         f"内存使用率过高: {mem:.1f}%", "mem_high"),
        ("disk", disk >= WARN_USAGE, "WARN" if disk < DANGER_USAGE else "ERROR",
         f"磁盘空间不足: {disk:.1f}%", "disk_high"),
        ("load", load_ratio >= WARN_USAGE, "WARN" if load_ratio < DANGER_USAGE else "ERROR",
         f"系统负载过高: load1={load1:.2f} (核数 {cores})", "load_high"),
    ]
    for key, bad, level, msg, dkey in checks:
        was = _prev_alerts.get(key, False)
        if bad and not was:
            add_event(level, msg, dedup_key=dkey)
            _prev_alerts[key] = True
        elif bad and was:
            add_event(level, msg, dedup_key=dkey)  # 限频
        elif not bad and was:
            add_event("OK", msg.replace("过高", "已恢复").replace("不足", "已恢复"), dedup_key=f"{dkey}_ok")
            _prev_alerts[key] = False


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------
def _detect_ping() -> bool:
    return shutil.which("ping") is not None


def _ping_command(host: str) -> List[str]:
    """固定参数列表，禁止字符串拼接注入。"""
    system = platform.system()
    if system == "Darwin":
        # macOS: -W 为毫秒
        return ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT * 1000)), host]
    # Linux 常见: -W 为秒（iputils）
    return ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), host]


_RTT_RE = re.compile(
    r"(?:time[=<]|rtt min/avg/max/(?:mdev|stddev) = )"
    r"([\d.]+)",
    re.IGNORECASE,
)
_RTT_LINE_RE = re.compile(r"time[=<]([\d.]+)\s*ms", re.IGNORECASE)


def _parse_rtt_ms(stdout: str) -> Optional[float]:
    m = _RTT_LINE_RE.search(stdout or "")
    if m:
        return float(m.group(1))
    # 汇总行 backup
    for line in (stdout or "").splitlines():
        if "min/avg/max" in line.lower():
            parts = line.split("=")
            if len(parts) >= 2:
                nums = parts[1].strip().split("/")
                if nums:
                    try:
                        return float(nums[0].split()[0])
                    except ValueError:
                        pass
    return None


def ping_once(host: str) -> Tuple[bool, Optional[float], str]:
    """
    对单个目标执行一次 ping。
    返回 (success, rtt_ms, detail)
    """
    if not _detect_ping():
        return False, None, "ping_not_found"
    cmd = _ping_command(host)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PING_TIMEOUT + 1.5,
            check=False,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode == 0:
            rtt = _parse_rtt_ms(out)
            if rtt is None:
                rtt = 0.0
            return True, rtt, "ok"
        return False, None, "timeout_or_unreachable"
    except subprocess.TimeoutExpired:
        return False, None, "timeout"
    except FileNotFoundError:
        return False, None, "ping_not_found"
    except OSError:
        return False, None, "os_error"


def _latency_status(avg: Optional[float], loss: float, online: bool) -> str:
    if not online:
        return "offline"
    if loss >= DANGER_LOSS or (avg is not None and avg >= DANGER_LATENCY_MS):
        return "danger"
    if loss >= WARN_LOSS or (avg is not None and avg >= WARN_LATENCY_MS):
        return "warn"
    return "ok"


def run_ping_round() -> None:
    """并发 Ping 全部目标，更新缓存与事件。"""
    global _ping_available, _ping_updated_at

    available = _detect_ping()
    with _state_lock:
        _ping_available = available

    if not available:
        add_event("ERROR", "系统未安装 ping，网络延迟检测不可用", dedup_key="ping_missing")
        with _state_lock:
            for t in PING_TARGETS:
                tid = t["id"]
                _ping_results[tid] = {
                    "id": tid,
                    "name": t["name"],
                    "host": t["host"],
                    "online": False,
                    "current_ms": None,
                    "min_ms": None,
                    "max_ms": None,
                    "avg_ms": None,
                    "loss_percent": 100.0,
                    "status": "unavailable",
                    "last_check": _now_iso(),
                    "detail": "ping_not_installed",
                }
            _ping_updated_at = time.time()
        return

    def _job(target: Dict[str, str]) -> Tuple[str, bool, Optional[float], str]:
        ok, rtt, detail = ping_once(target["host"])
        return target["id"], ok, rtt, detail

    results: Dict[str, Tuple[bool, Optional[float], str]] = {}
    with ThreadPoolExecutor(max_workers=len(PING_TARGETS)) as pool:
        futures = {pool.submit(_job, t): t["id"] for t in PING_TARGETS}
        for fut in as_completed(futures):
            try:
                tid, ok, rtt, detail = fut.result()
                results[tid] = (ok, rtt, detail)
            except Exception:
                tid = futures[fut]
                results[tid] = (False, None, "error")

    now_iso = _now_iso()
    with _state_lock:
        for t in PING_TARGETS:
            tid = t["id"]
            ok, rtt, detail = results.get(tid, (False, None, "error"))
            hist = _ping_history[tid]
            if ok and rtt is not None:
                hist.append(rtt)

            # 丢包：用近期样本中失败占比近似；本轮失败则记一次“失败点”
            # 简化：保留成功 rtt；用独立 success 计数
            # 使用滑动窗口：每轮追加成功 rtt；失败时记录 NaN 用 None 标记在侧表
            # 这里用：历史仅成功；loss = 基于最近 rounds 的 success 计数
            # 更稳妥：维护 success/fail 计数 deque
            if not hasattr(run_ping_round, "_sf"):
                run_ping_round._sf = {  # type: ignore[attr-defined]
                    x["id"]: deque(maxlen=PING_HISTORY_SIZE) for x in PING_TARGETS
                }
            sf: Deque[int] = run_ping_round._sf[tid]  # type: ignore[attr-defined]
            sf.append(1 if ok else 0)
            total = len(sf) or 1
            success_n = sum(sf)
            loss = round((1.0 - success_n / total) * 100.0, 1)

            samples = list(hist)
            min_ms = round(min(samples), 2) if samples else None
            max_ms = round(max(samples), 2) if samples else None
            avg_ms = round(sum(samples) / len(samples), 2) if samples else None
            current = round(rtt, 2) if (ok and rtt is not None) else None
            online = bool(ok)
            status = _latency_status(avg_ms, loss, online)

            prev = _ping_prev_online.get(tid)
            if prev is False and online:
                add_event("OK", f"{t['name']} ({t['host']}) 已恢复在线", dedup_key=f"up_{tid}")
            elif prev is True and not online:
                add_event("WARN", f"{t['name']} ({t['host']}) 连接超时或不可达", dedup_key=f"down_{tid}")
            elif online and current is not None and current >= DANGER_LATENCY_MS:
                add_event("WARN", f"{t['name']} 延迟过高: {current:.1f} ms", dedup_key=f"lat_{tid}")
            elif loss >= WARN_LOSS:
                add_event("WARN", f"{t['name']} 丢包率异常: {loss:.1f}%", dedup_key=f"loss_{tid}")

            _ping_prev_online[tid] = online
            _ping_results[tid] = {
                "id": tid,
                "name": t["name"],
                "host": t["host"],
                "online": online,
                "current_ms": current,
                "min_ms": min_ms,
                "max_ms": max_ms,
                "avg_ms": avg_ms,
                "loss_percent": loss,
                "status": status,
                "last_check": now_iso,
                "detail": detail,
            }
        _ping_updated_at = time.time()

    # 与 metrics 一样走限频，避免每轮刷屏
    add_event("INFO", "Ping 检测完成", dedup_key="ping_done")


# ---------------------------------------------------------------------------
# 后台任务
# ---------------------------------------------------------------------------
def _metrics_loop() -> None:
    while True:
        try:
            data, cms = collect_metrics()
            with _state_lock:
                global _metrics, _metrics_collect_ms, _metrics_updated_at
                _metrics = data
                _metrics_collect_ms = cms
                _metrics_updated_at = time.time()
            # 常规刷新不刷屏；仅周期性记一条心跳式成功日志
            add_event("INFO", "系统指标读取完成", dedup_key="metrics_ok")
        except Exception:
            add_event("ERROR", "系统指标采集异常", dedup_key="metrics_err")
        time.sleep(METRICS_INTERVAL)


def _ping_loop() -> None:
    # 启动稍延迟，避免与指标争抢
    time.sleep(0.5)
    while True:
        try:
            run_ping_round()
        except Exception:
            add_event("ERROR", "Ping 调度异常", dedup_key="ping_err")
        time.sleep(PING_INTERVAL)


def _heartbeat_loop() -> None:
    while True:
        time.sleep(60)
        up = int(time.time() - _start_time)
        add_event("INFO", f"定时心跳 — 服务已运行 {up}s", dedup_key="heartbeat")


def start_workers() -> None:
    """确保后台任务全局只启动一次。"""
    global _workers_started
    with _workers_lock:
        if _workers_started:
            return
        _workers_started = True
        add_event("OK", f"探针服务启动 v{VERSION}", dedup_key="boot")
        # 启动时先同步采一次，避免空数据
        try:
            data, cms = collect_metrics()
            with _state_lock:
                global _metrics, _metrics_collect_ms, _metrics_updated_at
                _metrics = data
                _metrics_collect_ms = cms
                _metrics_updated_at = time.time()
            add_event("OK", "系统信息刷新成功", dedup_key="metrics_init")
        except Exception:
            add_event("ERROR", "首次系统指标采集失败", dedup_key="metrics_init_err")

        for target, name in (
            (_metrics_loop, "metrics"),
            (_ping_loop, "ping"),
            (_heartbeat_loop, "heartbeat"),
        ):
            th = threading.Thread(target=target, name=f"probe-{name}", daemon=True)
            th.start()


def build_status_payload() -> Dict[str, Any]:
    with _state_lock:
        targets = []
        for t in PING_TARGETS:
            r = _ping_results.get(t["id"])
            if r:
                targets.append(dict(r))
            else:
                targets.append(
                    {
                        "id": t["id"],
                        "name": t["name"],
                        "host": t["host"],
                        "online": False,
                        "current_ms": None,
                        "min_ms": None,
                        "max_ms": None,
                        "avg_ms": None,
                        "loss_percent": None,
                        "status": "pending",
                        "last_check": None,
                        "detail": "pending",
                    }
                )
        payload = {
            "ok": True,
            "version": VERSION,
            "server_time": _now_iso(),
            "uptime_seconds": int(time.time() - _start_time),
            "collect_ms": round(_metrics_collect_ms, 2),
            "metrics_age_seconds": round(time.time() - _metrics_updated_at, 2)
            if _metrics_updated_at
            else None,
            "ping_age_seconds": round(time.time() - _ping_updated_at, 2)
            if _ping_updated_at
            else None,
            "system": dict(_metrics) if _metrics else {},
            "ping": {
                "available": bool(_ping_available) if _ping_available is not None else None,
                "targets": targets,
            },
            "events": list(_events)[:EVENT_MAX],
        }
    return payload


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class ProbeHandler(BaseHTTPRequestHandler):
    server_version = f"VPSProbe/{VERSION}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # 简洁访问日志到 stdout
        print(f"[{_now_iso()}] {self.address_string()} {fmt % args}")

    def _send_json(self, code: int, obj: Dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _send_html(self, code: int, html: str) -> None:
        body = html.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/":
                self._send_html(200, INDEX_HTML)
            elif path == "/api/status":
                try:
                    payload = build_status_payload()
                    self._send_json(200, payload)
                except Exception:
                    add_event("ERROR", "API 请求异常", dedup_key="api_err")
                    self._send_json(
                        500,
                        {"ok": False, "error": "internal_error", "version": VERSION},
                    )
            elif path == "/health":
                self._send_json(200, {"status": "ok"})
            else:
                self._send_json(404, {"ok": False, "error": "not_found"})
        except Exception:
            try:
                self._send_json(500, {"ok": False, "error": "internal_error"})
            except Exception:
                pass

    def do_POST(self) -> None:  # noqa: N802
        self._send_json(405, {"ok": False, "error": "method_not_allowed"})

    def do_PUT(self) -> None:  # noqa: N802
        self._send_json(405, {"ok": False, "error": "method_not_allowed"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._send_json(405, {"ok": False, "error": "method_not_allowed"})


# ---------------------------------------------------------------------------
# 内嵌单页前端
# ---------------------------------------------------------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<meta name="color-scheme" content="dark" />
<title>VPS Probe · 矩阵终端</title>
<style>
:root {
  --bg: #020604;
  --panel: rgba(0, 18, 8, 0.78);
  --border: #00ff6a;
  --text: #b6ffcb;
  --dim: #3d8f5a;
  --ok: #00ff88;
  --warn: #ffcc00;
  --danger: #ff3355;
  --offline: #666;
  --glow: 0 0 12px rgba(0, 255, 106, 0.35);
  --font: "SF Mono", "Cascadia Code", "Consolas", "Menlo", ui-monospace, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  height: 100%;
  width: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  font-size: 13px;
  line-height: 1.45;
  overflow-x: hidden;
  overflow-y: auto;
}
#rain {
  position: fixed; inset: 0; z-index: 0;
  width: 100%; height: 100%;
  pointer-events: none; opacity: 0.22;
}
.scanlines {
  position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.12) 2px,
    rgba(0, 0, 0, 0.12) 4px
  );
  mix-blend-mode: multiply;
}
.wrap {
  position: relative; z-index: 2;
  min-height: 100%;
  display: flex; flex-direction: column;
  /* 预留多行底栏高度，避免内容被固定页脚遮挡 */
  padding: 12px 14px 88px;
  max-width: 1400px; margin: 0 auto;
  width: 100%;
  box-sizing: border-box;
}
header.app {
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
  gap: 8px; margin-bottom: 12px;
  border: 1px solid rgba(0,255,106,0.35);
  background: var(--panel);
  box-shadow: var(--glow);
  padding: 10px 14px;
  border-radius: 4px;
}
header.app h1 {
  font-size: 15px; letter-spacing: 0.12em; color: var(--ok);
  text-shadow: 0 0 8px rgba(0,255,136,0.6);
}
header.app .sub { color: var(--dim); font-size: 11px; }
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px; border: 1px solid var(--ok); border-radius: 999px;
  color: var(--ok); font-size: 11px;
}
.badge .dot {
  width: 7px; height: 7px; border-radius: 50%; background: var(--ok);
  box-shadow: 0 0 6px var(--ok); animation: pulse 1.6s infinite;
}
.badge.offline { border-color: var(--danger); color: var(--danger); }
.badge.offline .dot { background: var(--danger); box-shadow: 0 0 6px var(--danger); }
@keyframes pulse {
  0%,100% { opacity: 1; } 50% { opacity: 0.35; }
}
.grid {
  display: grid;
  grid-template-columns: 1.2fr 1fr;
  gap: 12px;
  flex: 1;
}
@media (max-width: 960px) {
  .grid { grid-template-columns: 1fr; }
  body { font-size: 12px; }
}
.panel {
  background: var(--panel);
  border: 1px solid rgba(0,255,106,0.4);
  box-shadow: var(--glow);
  border-radius: 4px;
  padding: 12px;
  position: relative;
  overflow: hidden;
}
.panel::before {
  content: "";
  position: absolute; left: 0; right: 0; top: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--ok), transparent);
  opacity: 0.7; animation: scan 3.5s linear infinite;
}
@keyframes scan {
  0% { transform: translateX(-100%); } 100% { transform: translateX(100%); }
}
.panel h2 {
  font-size: 12px; letter-spacing: 0.16em; color: var(--ok);
  margin-bottom: 10px; text-transform: uppercase;
  border-bottom: 1px solid rgba(0,255,106,0.2); padding-bottom: 6px;
}
.kv {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 8px;
}
.kv .item {
  border: 1px solid rgba(0,255,106,0.12);
  background: rgba(0,0,0,0.25);
  padding: 7px 8px; border-radius: 3px;
}
.kv .item .k { color: var(--dim); font-size: 10px; margin-bottom: 2px; }
.kv .item .v { color: var(--text); word-break: break-all; font-size: 12px; }
.meter { margin-top: 10px; }
.meter .row {
  display: grid; grid-template-columns: 72px 1fr 52px;
  gap: 8px; align-items: center; margin-bottom: 8px;
}
.meter .label { color: var(--dim); font-size: 11px; }
.meter .pct { text-align: right; font-variant-numeric: tabular-nums; }
.bar {
  height: 10px; background: rgba(0,40,15,0.8);
  border: 1px solid rgba(0,255,106,0.25); border-radius: 2px; overflow: hidden;
}
.bar > i {
  display: block; height: 100%; width: 0%;
  background: linear-gradient(90deg, #00aa55, var(--ok));
  box-shadow: 0 0 8px rgba(0,255,136,0.5);
  transition: width 0.45s ease, background 0.3s;
}
.bar.warn > i { background: linear-gradient(90deg, #aa8800, var(--warn)); box-shadow: 0 0 8px rgba(255,204,0,0.5); }
.bar.danger > i { background: linear-gradient(90deg, #aa0022, var(--danger)); box-shadow: 0 0 8px rgba(255,51,85,0.5); }
.pct.ok, .st.ok { color: var(--ok); }
.pct.warn, .st.warn { color: var(--warn); }
.pct.danger, .st.danger { color: var(--danger); }
.pct.offline, .st.offline, .st.unavailable, .st.pending { color: var(--offline); }

.ping-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.ping-table th, .ping-table td {
  text-align: left; padding: 6px 4px;
  border-bottom: 1px solid rgba(0,255,106,0.12);
  white-space: nowrap;
}
.ping-table th { color: var(--dim); font-weight: normal; font-size: 10px; }
.ping-table td.host { color: var(--dim); max-width: 110px; overflow: hidden; text-overflow: ellipsis; }
.scroll-x { overflow-x: auto; -webkit-overflow-scrolling: touch; }

.terminal {
  grid-column: 1 / -1;
  min-height: 220px; max-height: 320px;
  display: flex; flex-direction: column;
}
.term-body {
  flex: 1; overflow-y: auto; font-size: 12px;
  background: rgba(0,0,0,0.45);
  border: 1px solid rgba(0,255,106,0.15);
  padding: 8px 10px;
  border-radius: 3px;
}
.term-line { margin-bottom: 3px; white-space: pre-wrap; word-break: break-word; }
.term-line .ts { color: var(--dim); }
.term-line .lv { font-weight: bold; margin: 0 6px; }
.term-line .lv.INFO { color: #7fd4ff; }
.term-line .lv.OK { color: var(--ok); }
.term-line .lv.WARN { color: var(--warn); }
.term-line .lv.ERROR { color: var(--danger); }
.cursor {
  display: inline-block; width: 8px; height: 13px;
  background: var(--ok); margin-left: 2px; vertical-align: text-bottom;
  animation: blink 1s step-end infinite;
}
@keyframes blink { 50% { opacity: 0; } }

footer.bar {
  position: fixed;
  left: 0;
  right: 0;
  bottom: 0;
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
  z-index: 5;
  background: rgba(0, 10, 4, 0.94);
  border-top: 1px solid rgba(0,255,106,0.35);
  backdrop-filter: blur(6px);
  -webkit-backdrop-filter: blur(6px);
  padding: 8px 12px;
  /* 全宽换行展示，避免长状态栏被 overflow 裁成半行 */
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: center;
  gap: 4px 10px;
  font-size: 11px;
  color: var(--dim);
  line-height: 1.5;
  overflow-x: auto;
  overflow-y: hidden;
  -webkit-overflow-scrolling: touch;
}
footer.bar > span {
  flex: 0 1 auto;
  white-space: nowrap;
  max-width: 100%;
}
footer.bar strong {
  color: var(--text);
  font-weight: normal;
  word-break: break-all;
}
footer.bar .sep {
  opacity: 0.35;
  flex: 0 0 auto;
  user-select: none;
}
@media (max-width: 720px) {
  footer.bar {
    font-size: 10px;
    gap: 3px 8px;
    padding: 8px 10px;
    justify-content: flex-start;
  }
  .wrap { padding-bottom: 96px; }
}
.err-banner {
  display: none;
  margin-bottom: 10px; padding: 8px 12px;
  border: 1px solid var(--danger); color: var(--danger);
  background: rgba(40,0,8,0.7); border-radius: 3px;
}
.err-banner.show { display: block; }
</style>
</head>
<body>
<canvas id="rain" aria-hidden="true"></canvas>
<div class="scanlines" aria-hidden="true"></div>
<div class="wrap">
  <header class="app">
    <div>
      <h1>◈ VPS PROBE // MATRIX</h1>
      <div class="sub">只读系统探针 · 无命令执行 · 零配置</div>
    </div>
    <div id="onlineBadge" class="badge"><span class="dot"></span><span id="onlineText">连接中…</span></div>
  </header>
  <div id="errBanner" class="err-banner">与后端连接异常，正在重试并保留最后成功数据…</div>

  <div class="grid">
    <section class="panel" id="sysPanel">
      <h2>01 // 系统性能</h2>
      <div class="kv" id="sysKv"></div>
      <div class="meter" id="sysMeters"></div>
    </section>

    <section class="panel" id="pingPanel">
      <h2>02 // 外部 Ping</h2>
      <div class="scroll-x">
        <table class="ping-table">
          <thead>
            <tr>
              <th>目标</th><th>主机</th><th>当前</th><th>最低</th><th>最高</th>
              <th>平均</th><th>丢包</th><th>状态</th><th>检测时间</th>
            </tr>
          </thead>
          <tbody id="pingBody"></tbody>
        </table>
      </div>
    </section>

    <section class="panel terminal">
      <h2>03 // 事件终端 <span style="color:var(--dim);font-weight:normal;letter-spacing:0">(只读)</span></h2>
      <div class="term-body" id="term" aria-live="polite"></div>
    </section>
  </div>
</div>

<footer class="bar">
  <span>日期 <strong id="fDate">—</strong></span>
  <span class="sep">|</span>
  <span>时间 <strong id="fTime">—</strong></span>
  <span class="sep">|</span>
  <span>请求 <strong id="fReq">—</strong> ms</span>
  <span class="sep">|</span>
  <span>采集 <strong id="fCollect">—</strong> ms</span>
  <span class="sep">|</span>
  <span>数据龄 <strong id="fAge">—</strong> s</span>
  <span class="sep">|</span>
  <span>更新 <strong id="fUpdated">—</strong></span>
  <span class="sep">|</span>
  <span>状态 <strong id="fStatus">—</strong></span>
  <span class="sep">|</span>
  <span>服务运行 <strong id="fUptime">—</strong></span>
  <span class="sep">|</span>
  <span>v<strong id="fVer">—</strong></span>
</footer>

<script>
(function () {
  "use strict";

  var lastOk = null;
  var lastEventsSig = "";
  var pollMs = 2000;
  var timer = null;
  var clockTimer = null;
  var serviceUptimeBase = 0;
  var serviceUptimeAt = 0;

  function $(id) { return document.getElementById(id); }

  function fmtBytes(n) {
    if (n == null || isNaN(n)) return "—";
    var u = ["B","KB","MB","GB","TB","PB"];
    var i = 0; var v = Number(n);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(v >= 10 || i === 0 ? 1 : 2) + " " + u[i];
  }
  function fmtRate(bps) {
    if (bps == null || isNaN(bps)) return "—";
    return fmtBytes(bps) + "/s";
  }
  function fmtUptime(sec) {
    sec = Math.max(0, Math.floor(Number(sec) || 0));
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    if (d > 0) return d + "d " + h + "h " + m + "m";
    if (h > 0) return h + "h " + m + "m " + s + "s";
    if (m > 0) return m + "m " + s + "s";
    return s + "s";
  }
  function fmtMs(v) {
    if (v == null || v === "") return "—";
    return Number(v).toFixed(1) + " ms";
  }
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function setOnline(ok) {
    var b = $("onlineBadge");
    var t = $("onlineText");
    var e = $("errBanner");
    if (ok) {
      b.classList.remove("offline");
      t.textContent = "探针在线";
      e.classList.remove("show");
      $("fStatus").textContent = "ONLINE";
      $("fStatus").style.color = "var(--ok)";
    } else {
      b.classList.add("offline");
      t.textContent = "连接异常";
      e.classList.add("show");
      $("fStatus").textContent = "OFFLINE";
      $("fStatus").style.color = "var(--danger)";
    }
  }

  function meterHtml(label, pct, status) {
    var st = status || "ok";
    var p = Math.max(0, Math.min(100, Number(pct) || 0));
    return '<div class="row"><span class="label">' + esc(label) + '</span>' +
      '<div class="bar ' + esc(st) + '"><i style="width:' + p.toFixed(1) + '%"></i></div>' +
      '<span class="pct ' + esc(st) + '">' + p.toFixed(1) + '%</span></div>';
  }

  function renderSystem(sys) {
    if (!sys || !Object.keys(sys).length) {
      $("sysKv").innerHTML = '<div class="item"><div class="k">状态</div><div class="v">等待首次采集…</div></div>';
      return;
    }
    var items = [
      ["主机名", sys.hostname],
      ["操作系统", sys.os_name],
      ["系统版本", sys.os_version],
      ["内核", sys.kernel],
      ["架构", sys.arch],
      ["CPU 型号", sys.cpu_model],
      ["物理核心", sys.cpu_physical_cores],
      ["逻辑核心", sys.cpu_logical_cores],
      ["负载 1/5/15", [sys.load_1, sys.load_5, sys.load_15].join(" / ")],
      ["内存", fmtBytes(sys.memory_used) + " / " + fmtBytes(sys.memory_total)],
      ["可用内存", fmtBytes(sys.memory_available)],
      ["Swap", fmtBytes(sys.swap_used) + " / " + fmtBytes(sys.swap_total)],
      ["磁盘 /", fmtBytes(sys.disk_used) + " / " + fmtBytes(sys.disk_total)],
      ["磁盘可用", fmtBytes(sys.disk_free)],
      ["启动时间", sys.boot_time],
      ["持续运行", fmtUptime(sys.uptime_seconds)],
      ["登录用户", sys.users],
      ["进程数", sys.processes],
      ["累计上传", fmtBytes(sys.net_bytes_sent)],
      ["累计下载", fmtBytes(sys.net_bytes_recv)],
      ["上传速率", fmtRate(sys.net_up_rate)],
      ["下载速率", fmtRate(sys.net_down_rate)]
    ];
    $("sysKv").innerHTML = items.map(function (it) {
      return '<div class="item"><div class="k">' + esc(it[0]) + '</div><div class="v">' + esc(it[1]) + '</div></div>';
    }).join("");
    $("sysMeters").innerHTML =
      meterHtml("CPU", sys.cpu_percent, sys.cpu_status) +
      meterHtml("内存", sys.memory_percent, sys.memory_status) +
      meterHtml("Swap", sys.swap_percent, sys.swap_status) +
      meterHtml("磁盘", sys.disk_percent, sys.disk_status);
  }

  function renderPing(ping) {
    var body = $("pingBody");
    if (!ping) {
      body.innerHTML = '<tr><td colspan="9">等待数据…</td></tr>';
      return;
    }
    if (ping.available === false) {
      body.innerHTML = '<tr><td colspan="9" class="st danger">系统未安装 ping，延迟检测不可用</td></tr>';
      return;
    }
    var rows = (ping.targets || []).map(function (t) {
      var st = t.status || (t.online ? "ok" : "offline");
      var stLabel = t.online ? "在线" : (st === "unavailable" ? "不可用" : (st === "pending" ? "等待" : "离线"));
      return "<tr>" +
        "<td>" + esc(t.name) + "</td>" +
        '<td class="host" title="' + esc(t.host) + '">' + esc(t.host) + "</td>" +
        "<td>" + esc(t.current_ms != null ? t.current_ms.toFixed(1) + " ms" : "—") + "</td>" +
        "<td>" + esc(t.min_ms != null ? t.min_ms.toFixed(1) : "—") + "</td>" +
        "<td>" + esc(t.max_ms != null ? t.max_ms.toFixed(1) : "—") + "</td>" +
        "<td>" + esc(t.avg_ms != null ? t.avg_ms.toFixed(1) : "—") + "</td>" +
        "<td>" + esc(t.loss_percent != null ? t.loss_percent.toFixed(1) + "%" : "—") + "</td>" +
        '<td class="st ' + esc(st) + '">' + esc(stLabel) + "</td>" +
        "<td>" + esc(t.last_check || "—") + "</td>" +
        "</tr>";
    });
    body.innerHTML = rows.join("") || '<tr><td colspan="9">无目标</td></tr>';
  }

  function renderEvents(events) {
    var term = $("term");
    var list = events || [];
    var sig = list.map(function (e) { return e.ts + e.level + e.message; }).join("|");
    if (sig === lastEventsSig && term.childNodes.length) return;
    lastEventsSig = sig;
    var html = list.slice().reverse().map(function (e) {
      return '<div class="term-line"><span class="ts">[' + esc(e.ts) + ']</span>' +
        '<span class="lv ' + esc(e.level) + '">' + esc(e.level) + '</span>' +
        '<span class="msg">' + esc(e.message) + '</span></div>';
    }).join("");
    term.innerHTML = html + '<div class="term-line"><span class="ts">$</span> <span class="cursor"></span></div>';
    term.scrollTop = term.scrollHeight;
  }

  function tickClock() {
    var now = new Date();
    var y = now.getFullYear();
    var mo = String(now.getMonth() + 1).padStart(2, "0");
    var d = String(now.getDate()).padStart(2, "0");
    var h = String(now.getHours()).padStart(2, "0");
    var mi = String(now.getMinutes()).padStart(2, "0");
    var s = String(now.getSeconds()).padStart(2, "0");
    $("fDate").textContent = y + "-" + mo + "-" + d;
    $("fTime").textContent = h + ":" + mi + ":" + s;
    if (serviceUptimeAt) {
      var elapsed = (Date.now() - serviceUptimeAt) / 1000;
      $("fUptime").textContent = fmtUptime(serviceUptimeBase + elapsed);
    }
  }

  function applyPayload(data, reqMs) {
    lastOk = data;
    serviceUptimeBase = data.uptime_seconds || 0;
    serviceUptimeAt = Date.now();
    $("fVer").textContent = data.version || "—";
    $("fCollect").textContent = data.collect_ms != null ? Number(data.collect_ms).toFixed(1) : "—";
    $("fReq").textContent = reqMs != null ? reqMs.toFixed(1) : "—";
    $("fAge").textContent = data.metrics_age_seconds != null ? Number(data.metrics_age_seconds).toFixed(1) : "—";
    // 压缩时间戳展示，避免底栏单行过长被裁切
    var st = data.server_time || "—";
    if (typeof st === "string" && st.length > 19) {
      st = st.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "").replace(/Z$/, "");
    }
    $("fUpdated").textContent = st;
    renderSystem(data.system);
    renderPing(data.ping);
    renderEvents(data.events);
  }

  function poll() {
    var t0 = performance.now();
    fetch("/api/status", { cache: "no-store" })
      .then(function (r) {
        if (!r.ok) throw new Error("http " + r.status);
        return r.json();
      })
      .then(function (data) {
        var reqMs = performance.now() - t0;
        if (!data || data.ok === false) throw new Error("bad payload");
        setOnline(true);
        applyPayload(data, reqMs);
      })
      .catch(function () {
        setOnline(false);
        if (lastOk) {
          // 保留最后成功数据，仅更新请求失败态
          $("fReq").textContent = (performance.now() - t0).toFixed(1);
        }
      });
  }

  /* ---- Matrix rain ---- */
  var canvas = $("rain");
  var ctx = canvas.getContext("2d");
  var drops = [];
  var cols = 0;
  var fontSize = 14;
  var chars = "01アイウエオカキクケコｱｲｳｴｵﾊﾞｼﾞﾄﾞ01ΨΦλ∑¥$#@";
  var rainActive = true;
  var lastFrame = 0;
  var frameGap = 48;

  function resizeRain() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(window.innerWidth * dpr);
    canvas.height = Math.floor(window.innerHeight * dpr);
    canvas.style.width = window.innerWidth + "px";
    canvas.style.height = window.innerHeight + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var mobile = window.innerWidth < 768;
    fontSize = mobile ? 16 : 14;
    frameGap = mobile ? 70 : 48;
    cols = Math.floor(window.innerWidth / fontSize);
    var density = mobile ? 0.45 : 0.85;
    var n = Math.max(1, Math.floor(cols * density));
    drops = [];
    for (var i = 0; i < n; i++) {
      drops.push({
        x: Math.floor(Math.random() * cols) * fontSize,
        y: Math.random() * -100,
        speed: 0.6 + Math.random() * 1.4
      });
    }
  }

  function drawRain(ts) {
    if (!rainActive) {
      requestAnimationFrame(drawRain);
      return;
    }
    if (ts - lastFrame < frameGap) {
      requestAnimationFrame(drawRain);
      return;
    }
    lastFrame = ts;
    ctx.fillStyle = "rgba(2, 6, 4, 0.18)";
    ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);
    ctx.fillStyle = "#00ff6a";
    ctx.font = fontSize + "px monospace";
    for (var i = 0; i < drops.length; i++) {
      var d = drops[i];
      var ch = chars.charAt(Math.floor(Math.random() * chars.length));
      ctx.globalAlpha = 0.35 + Math.random() * 0.45;
      ctx.fillText(ch, d.x, d.y * fontSize);
      d.y += d.speed;
      if (d.y * fontSize > window.innerHeight && Math.random() > 0.975) {
        d.y = Math.random() * -20;
        d.x = Math.floor(Math.random() * cols) * fontSize;
      }
    }
    ctx.globalAlpha = 1;
    requestAnimationFrame(drawRain);
  }

  document.addEventListener("visibilitychange", function () {
    rainActive = document.visibilityState === "visible";
    if (document.visibilityState === "visible") {
      poll();
    }
  });
  window.addEventListener("resize", function () {
    resizeRain();
  });

  resizeRain();
  requestAnimationFrame(drawRain);
  tickClock();
  clockTimer = setInterval(tickClock, 1000);
  poll();
  timer = setInterval(poll, pollMs);
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main() -> None:
    start_workers()
    server = ThreadingHTTPServer((HOST, PORT), ProbeHandler)

    def _shutdown(*_args: Any) -> None:
        print(f"\n[{_now_iso()}] 收到停止信号，正在关闭…")
        # shutdown 需在其他线程调用
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        import signal

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)
    except Exception:
        pass

    print(f"VPS Probe v{VERSION}")
    print(f"监听 http://{HOST}:{PORT}/")
    print(f"健康检查 http://{HOST}:{PORT}/health")
    print("按 Ctrl+C 停止")
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        print(f"[{_now_iso()}] 服务已停止")


if __name__ == "__main__":
    main()
