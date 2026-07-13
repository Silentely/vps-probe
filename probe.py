#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPS Probe — 极简单页 VPS 探针监控
零配置、零数据库、内嵌前端，默认监听 0.0.0.0:8080
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
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
VERSION = "1.6.3"
SPARK_HISTORY = 20              # 返回前端的延迟样本数（火花图）
SYS_HISTORY_SIZE = 20           # 系统指标历史样本数（CPU/内存/磁盘趋势图）
HOST = "0.0.0.0"
PORT = 8080

METRICS_INTERVAL = 2.0          # 系统指标采集间隔（秒）
PING_INTERVAL = 12.0            # Ping 调度间隔（秒）；目标增多后略放宽
PING_TIMEOUT = 2                # 单次 ICMP 超时（秒）
TCP_TIMEOUT = 1.8               # TCP 回退探测超时（秒）
PING_HISTORY_SIZE = 30          # 每目标保留的延迟样本数
EVENT_MAX = 100                 # 事件最多保留条数
EVENT_DEDUP_WINDOW = 60.0       # 相同异常限频窗口（秒）
EVENT_MSG_MAX = 180             # 单条事件文案最大长度
EVENT_LAST_MAX = 256            # 限频键上限，防止字典无限增长
WARN_USAGE = 80.0               # 使用率警告阈值 %
DANGER_USAGE = 90.0             # 使用率危险阈值 %
WARN_LATENCY_MS = 100.0
DANGER_LATENCY_MS = 300.0
WARN_LOSS = 20.0
DANGER_LOSS = 50.0

# 内置探测目标（客户端不可改）
# group: dns|web；soft_alert: 国内环境易不可达，仅边沿告警、不刷丢包噪音
PING_TARGETS: List[Dict[str, Any]] = [
    {"id": "cf_dns", "name": "Cloudflare DNS", "host": "1.1.1.1", "group": "dns", "soft_alert": False},
    {"id": "cf_dns2", "name": "Cloudflare DNS2", "host": "1.0.0.1", "group": "dns", "soft_alert": False},
    {"id": "google_dns", "name": "Google DNS", "host": "8.8.8.8", "group": "dns", "soft_alert": False},
    {"id": "google_dns2", "name": "Google DNS2", "host": "8.8.4.4", "group": "dns", "soft_alert": False},
    {"id": "quad9", "name": "Quad9 DNS", "host": "9.9.9.9", "group": "dns", "soft_alert": False},
    {"id": "ali_dns", "name": "AliDNS", "host": "223.5.5.5", "group": "dns", "soft_alert": False},
    {"id": "dns114", "name": "114 DNS", "host": "114.114.114.114", "group": "dns", "soft_alert": False},
    {"id": "cf_web", "name": "Cloudflare", "host": "cloudflare.com", "group": "web", "soft_alert": False},
    {"id": "google_web", "name": "Google", "host": "google.com", "group": "web", "soft_alert": True},
    {"id": "github", "name": "GitHub", "host": "github.com", "group": "web", "soft_alert": False},
    {"id": "baidu", "name": "Baidu", "host": "baidu.com", "group": "web", "soft_alert": False},
    {"id": "microsoft", "name": "Microsoft", "host": "microsoft.com", "group": "web", "soft_alert": True},
    {"id": "apple", "name": "Apple", "host": "apple.com", "group": "web", "soft_alert": False},
    {"id": "amazon", "name": "Amazon", "host": "amazon.com", "group": "web", "soft_alert": True},
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
_prev_disk_io: Optional[Tuple[int, int, float]] = None  # read_bytes, write_bytes, ts

# 系统指标历史（趋势图用）
_sys_history: Dict[str, Deque[float]] = {
    "cpu": deque(maxlen=SYS_HISTORY_SIZE),
    "mem": deque(maxlen=SYS_HISTORY_SIZE),
    "swap": deque(maxlen=SYS_HISTORY_SIZE),
    "disk": deque(maxlen=SYS_HISTORY_SIZE),
}

_ping_available: Optional[bool] = None
_ping_results: Dict[str, Dict[str, Any]] = {}
_ping_history: Dict[str, Deque[float]] = {
    t["id"]: deque(maxlen=PING_HISTORY_SIZE) for t in PING_TARGETS
}
_ping_success_flags: Dict[str, Deque[int]] = {
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
_cpu_primed = False
_runtime_mode: Optional[str] = None  # host | container
_html_body: Optional[bytes] = None
_html_etag: Optional[str] = None
_ping_bin_cache: Optional[bool] = None
_ping_fail_streak: Dict[str, int] = {t["id"]: 0 for t in PING_TARGETS}
_ping_pool: Optional[ThreadPoolExecutor] = None


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _tz_label() -> str:
    """本地时区偏移，如 +0800 / UTC。"""
    try:
        off = time.strftime("%z") or ""
        if off in ("", "+0000", "-0000"):
            return "UTC"
        return f"UTC{off[:3]}:{off[3:]}" if len(off) >= 5 else f"UTC{off}"
    except Exception:
        return "unknown"


def detect_runtime() -> str:
    """判断当前为宿主机命名空间还是容器视角。"""
    global _runtime_mode
    if _runtime_mode is not None:
        return _runtime_mode
    mode = "host"
    try:
        if os.path.exists("/.dockerenv"):
            mode = "container"
        else:
            cgroup = "/proc/1/cgroup"
            if os.path.isfile(cgroup):
                with open(cgroup, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
                if any(x in text for x in ("docker", "containerd", "kubepods", "lxc", "podman")):
                    mode = "container"
            # 部分环境 cgroup v2 无关键字，再看 mountinfo
            if mode == "host" and os.path.isfile("/proc/self/mountinfo"):
                with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as f:
                    mi = f.read(4096)
                if "docker" in mi or "overlay" in mi and "containerd" in mi:
                    mode = "container"
    except OSError:
        pass
    _runtime_mode = mode
    return mode


def hostname_display(raw: str, runtime: str) -> str:
    """容器短 ID 主机名转为可读展示。"""
    raw = raw or "unknown"
    if runtime != "container":
        return raw
    if re.fullmatch(r"[0-9a-fA-F]{8,64}", raw):
        return f"容器 {raw[:12].lower()}"
    return f"容器 · {raw}"


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
        # 限制限频表体积：过期键优先清理
        if len(_event_last) > EVENT_LAST_MAX:
            cutoff = now - EVENT_DEDUP_WINDOW * 2
            stale = [k for k, ts in _event_last.items() if ts < cutoff]
            for k in stale:
                _event_last.pop(k, None)
            if len(_event_last) > EVENT_LAST_MAX:
                # 仍过多则丢弃最旧一半
                for k, _ in sorted(_event_last.items(), key=lambda kv: kv[1])[
                    : len(_event_last) // 2
                ]:
                    _event_last.pop(k, None)
        msg = str(message or "")
        if len(msg) > EVENT_MSG_MAX:
            msg = msg[: EVENT_MSG_MAX - 1] + "…"
        _events.appendleft(
            {
                "ts": _now_iso(),
                "level": level,
                "message": msg,
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
    global _prev_net, _cpu_primed

    t0 = time.perf_counter()
    os_name, os_version = _read_os_release()
    boot_ts = psutil.boot_time()
    uptime_sec = max(0, int(time.time() - boot_ts))

    # CPU：首次短阻塞 priming，之后非阻塞采样，避免每轮卡住 150ms
    try:
        if not _cpu_primed:
            cpu_percent = float(psutil.cpu_percent(interval=0.1))
            _cpu_primed = True
        else:
            cpu_percent = float(psutil.cpu_percent(interval=None))
    except Exception:
        cpu_percent = 0.0
    # CPU 每核使用率
    try:
        per_cpu = [round(x, 1) for x in psutil.cpu_percent(interval=None, percpu=True)]
    except Exception:
        per_cpu = []
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

    # Network totals + rates（排除 lo，更接近「外网向」体感）
    net_sent = net_recv = 0
    up_rate = down_rate = 0.0
    top_nic = ""
    try:
        pernic = psutil.net_io_counters(pernic=True) or {}
        top_bytes = -1
        if pernic:
            for name, io in pernic.items():
                n = (name or "").lower()
                if n == "lo" or n.startswith("lo:") or n.startswith("loop"):
                    continue
                s = int(io.bytes_sent)
                r = int(io.bytes_recv)
                net_sent += s
                net_recv += r
                total = s + r
                if total > top_bytes:
                    top_bytes = total
                    top_nic = name
        else:
            io = psutil.net_io_counters()
            if io is not None:
                net_sent = int(io.bytes_sent)
                net_recv = int(io.bytes_recv)
        now = time.time()
        if _prev_net is not None:
            ps, pr, pt = _prev_net
            dt = max(now - pt, 1e-6)
            if net_sent >= ps:
                up_rate = (net_sent - ps) / dt
            if net_recv >= pr:
                down_rate = (net_recv - pr) / dt
        _prev_net = (net_sent, net_recv, now)
    except Exception:
        pass

    # 磁盘 I/O 速率（根设备）
    disk_read_rate = disk_write_rate = 0.0
    try:
        dio = psutil.disk_io_counters(perdisk=False)
        if dio is not None:
            now_d = time.time()
            dr = int(dio.read_bytes)
            dw = int(dio.write_bytes)
            if _prev_disk_io is not None:
                pd_r, pd_w, pd_t = _prev_disk_io
                dt_d = max(now_d - pd_t, 1e-6)
                if dr >= pd_r:
                    disk_read_rate = (dr - pd_r) / dt_d
                if dw >= pd_w:
                    disk_write_rate = (dw - pd_w) / dt_d
            _prev_disk_io = (dr, dw, now_d)
    except Exception:
        pass

    # 根分区 inode（若系统支持）
    inode_total = inode_used = 0
    inode_percent = 0.0
    try:
        stv = os.statvfs("/")
        if stv.f_files > 0:
            inode_total = int(stv.f_files)
            free_inodes = int(stv.f_ffree)
            inode_used = max(0, inode_total - free_inodes)
            inode_percent = round(inode_used * 100.0 / inode_total, 1)
    except (OSError, AttributeError):
        pass

    collect_ms = (time.perf_counter() - t0) * 1000.0

    raw_host = socket.gethostname()
    runtime = detect_runtime()
    load_per_core = round(load1 / max(logical, 1), 2)
    mem_avail_pct = round((mem_available * 100.0 / mem_total), 1) if mem_total else 0.0
    data = {
        "hostname": raw_host,
        "hostname_display": hostname_display(raw_host, runtime),
        "runtime": runtime,
        "os_name": os_name,
        "os_version": os_version,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_model": _cpu_model(),
        "cpu_physical_cores": physical,
        "cpu_logical_cores": logical,
        "cpu_percent": round(cpu_percent, 1),
        "cpu_per_core": per_cpu,
        "cpu_status": _status_from_pct(cpu_percent),
        "load_1": round(load1, 2),
        "load_5": round(load5, 2),
        "load_15": round(load15, 2),
        "load_per_core": load_per_core,
        "load_status": _status_from_pct(min(load_per_core * 100.0, 100.0)),
        "memory_total": mem_total,
        "memory_used": mem_used,
        "memory_available": mem_available,
        "memory_available_percent": mem_avail_pct,
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
        "disk_mount": "/",
        "disk_label": "磁盘 /（根分区）",
        "disk_inode_total": inode_total,
        "disk_inode_used": inode_used,
        "disk_inode_percent": inode_percent,
        "disk_read_rate": round(disk_read_rate, 1),
        "disk_write_rate": round(disk_write_rate, 1),
        "boot_time": datetime.fromtimestamp(boot_ts).astimezone().isoformat(timespec="seconds"),
        "uptime_seconds": uptime_sec,
        "users": users,
        "processes": processes,
        "net_bytes_sent": net_sent,
        "net_bytes_recv": net_recv,
        "net_up_rate": round(up_rate, 1),
        "net_down_rate": round(down_rate, 1),
        "net_top_iface": top_nic or None,
        "net_exclude_loopback": True,
        "timezone": _tz_label(),
    }

    # 记录系统指标历史（趋势图用）
    _sys_history["cpu"].append(round(cpu_percent, 1))
    _sys_history["mem"].append(round(mem_percent, 1))
    _sys_history["swap"].append(round(swap_percent, 1))
    _sys_history["disk"].append(round(disk_percent, 1))

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
    """缓存 which(ping) 结果，避免每轮探测反复扫 PATH。"""
    global _ping_bin_cache
    if _ping_bin_cache is None:
        _ping_bin_cache = shutil.which("ping") is not None
    return bool(_ping_bin_cache)


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
    对单个目标执行一次 ICMP ping。
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
            return True, rtt, "icmp"
        return False, None, "timeout_or_unreachable"
    except subprocess.TimeoutExpired:
        return False, None, "timeout"
    except FileNotFoundError:
        return False, None, "ping_not_found"
    except OSError:
        return False, None, "os_error"


def tcp_probe_ms(host: str, port: int = 443) -> Tuple[bool, Optional[float], str]:
    """固定端口 TCP 连接探测（不执行 shell），作为 ICMP 失败时的回退。"""
    t0 = time.perf_counter()
    tag = f"tcp{port}"
    try:
        # 禁止把用户输入拼进命令；此处 host 仅来自内置列表
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            rtt = (time.perf_counter() - t0) * 1000.0
            return True, round(rtt, 2), tag
    except (socket.timeout, TimeoutError):
        return False, None, f"{tag}_timeout"
    except OSError:
        return False, None, f"{tag}_unreachable"


def probe_target(host: str) -> Tuple[bool, Optional[float], str]:
    """先 ICMP，失败则 TCP/443，再尝试 TCP/80；无 ping 时直接 TCP。"""
    has_ping = _detect_ping()
    last_detail = "unreachable"
    if has_ping:
        ok, rtt, detail = ping_once(host)
        if ok:
            return ok, rtt, detail
        last_detail = detail
    for port in (443, 80):
        ok2, rtt2, detail2 = tcp_probe_ms(host, port)
        if ok2:
            return True, rtt2, detail2
        last_detail = detail2
    if not has_ping:
        return False, None, "ping_not_found_tcp_fail"
    return False, None, last_detail


def _latency_status(avg: Optional[float], loss: float, online: bool) -> str:
    if not online:
        return "offline"
    if loss >= DANGER_LOSS or (avg is not None and avg >= DANGER_LATENCY_MS):
        return "danger"
    if loss >= WARN_LOSS or (avg is not None and avg >= WARN_LATENCY_MS):
        return "warn"
    return "ok"


def run_ping_round() -> None:
    """并发探测全部目标，更新缓存与事件。"""
    global _ping_available, _ping_updated_at

    available = _detect_ping()
    with _state_lock:
        _ping_available = available

    if not available:
        # 无 ping 命令时仍可用 TCP 回退，仅提示一次
        add_event(
            "WARN",
            "未安装 ping，已改用 TCP/443 探测（部分目标可能不准）",
            dedup_key="ping_missing_tcp",
        )

    def _job(target: Dict[str, Any]) -> Tuple[str, bool, Optional[float], str]:
        ok, rtt, detail = probe_target(str(target["host"]))
        return str(target["id"]), ok, rtt, detail

    global _ping_pool
    results: Dict[str, Tuple[bool, Optional[float], str]] = {}
    workers = max(4, min(16, len(PING_TARGETS)))
    if _ping_pool is None:
        _ping_pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ping")
    pool = _ping_pool
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
            tid = str(t["id"])
            ok, rtt, detail = results.get(tid, (False, None, "error"))
            soft = bool(t.get("soft_alert"))
            group = str(t.get("group") or "web")
            hist = _ping_history[tid]
            if ok and rtt is not None:
                hist.append(rtt)

            # 丢包：独立成功/失败滑动窗口（与 RTT 历史分离）
            sf = _ping_success_flags[tid]
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

            if online:
                _ping_fail_streak[tid] = 0
            else:
                _ping_fail_streak[tid] = int(_ping_fail_streak.get(tid, 0)) + 1
            streak = int(_ping_fail_streak.get(tid, 0))

            prev = _ping_prev_online.get(tid)
            if prev is False and online:
                add_event("OK", f"{t['name']} ({t['host']}) 已恢复在线", dedup_key=f"up_{tid}")
            elif prev is True and not online:
                add_event(
                    "WARN",
                    f"{t['name']} ({t['host']}) 不可达",
                    dedup_key=f"down_{tid}",
                )
            elif (not soft) and online and current is not None and current >= DANGER_LATENCY_MS:
                add_event("WARN", f"{t['name']} 延迟过高: {current:.1f} ms", dedup_key=f"lat_{tid}")
            elif (not soft) and loss >= WARN_LOSS and not online and streak >= 2:
                # 持续不可达时的丢包汇总，软目标不刷；连续失败才提示
                add_event("WARN", f"{t['name']} 丢包率偏高: {loss:.1f}%", dedup_key=f"loss_{tid}")

            _ping_prev_online[tid] = online
            _ping_results[tid] = {
                "id": tid,
                "name": t["name"],
                "host": t["host"],
                "group": group,
                "soft_alert": soft,
                "online": online,
                "current_ms": current,
                "min_ms": min_ms,
                "max_ms": max_ms,
                "avg_ms": avg_ms,
                "loss_percent": loss,
                "fail_streak": streak,
                "status": status,
                "last_check": now_iso,
                "detail": detail,
            }
        _ping_updated_at = time.time()


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
        rt = detect_runtime()
        add_event("OK", f"探针服务启动 v{VERSION}（{('容器' if rt == 'container' else '宿主机')}模式）", dedup_key="boot")
        # 启动时采两次：第二次 CPU 非阻塞采样更稳
        try:
            data, cms = collect_metrics()
            time.sleep(0.2)
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
            tid = t["id"]
            r = _ping_results.get(tid)
            hist = list(_ping_history.get(tid, []))[-SPARK_HISTORY:]
            history_ms = [round(float(x), 1) for x in hist]
            if r:
                row = dict(r)
                row["history_ms"] = history_ms
                targets.append(row)
            else:
                targets.append(
                    {
                        "id": tid,
                        "name": t["name"],
                        "host": t["host"],
                        "group": t.get("group") or "web",
                        "soft_alert": bool(t.get("soft_alert")),
                        "online": False,
                        "current_ms": None,
                        "min_ms": None,
                        "max_ms": None,
                        "avg_ms": None,
                        "loss_percent": None,
                        "fail_streak": 0,
                        "status": "pending",
                        "last_check": None,
                        "detail": "pending",
                        "history_ms": history_ms,
                    }
                )
        # 服务端排序：在线优先、延迟升序，前端可覆盖
        targets.sort(
            key=lambda x: (
                0 if x.get("online") else 1,
                float(x["current_ms"]) if x.get("current_ms") is not None else 1e9,
                str(x.get("name") or ""),
            )
        )
        runtime = detect_runtime()
        online_n = sum(1 for t in targets if t.get("online"))
        total_n = len(targets)
        online_avgs = [
            float(t["avg_ms"])
            for t in targets
            if t.get("online") and t.get("avg_ms") is not None
        ]
        online_mins = [
            float(t["min_ms"])
            for t in targets
            if t.get("online") and t.get("min_ms") is not None
        ]
        online_maxs = [
            float(t["max_ms"])
            for t in targets
            if t.get("online") and t.get("max_ms") is not None
        ]
        ratio = (online_n / total_n) if total_n else 0.0
        if ratio >= 0.9:
            quality = "excellent"
        elif ratio >= 0.75:
            quality = "good"
        elif ratio >= 0.5:
            quality = "fair"
        else:
            quality = "poor"
        ping_summary = {
            "total": total_n,
            "online": online_n,
            "offline": max(0, total_n - online_n),
            "avg_ms": round(sum(online_avgs) / len(online_avgs), 1) if online_avgs else None,
            "min_ms": round(min(online_mins), 1) if online_mins else None,
            "max_ms": round(max(online_maxs), 1) if online_maxs else None,
            "online_ratio": round(ratio, 3),
            "quality": quality,
        }
        payload = {
            "ok": True,
            "version": VERSION,
            "runtime": runtime,
            "timezone": _tz_label(),
            "server_time": _now_iso(),
            "started_at": datetime.fromtimestamp(_start_time).astimezone().isoformat(timespec="seconds"),
            "uptime_seconds": int(time.time() - _start_time),
            "collect_ms": round(_metrics_collect_ms, 2),
            "metrics_age_seconds": round(time.time() - _metrics_updated_at, 2)
            if _metrics_updated_at
            else None,
            "ping_age_seconds": round(time.time() - _ping_updated_at, 2)
            if _ping_updated_at
            else None,
            "system": dict(_metrics) if _metrics else {},
            "system_history": {
                "cpu": list(_sys_history["cpu"])[-SPARK_HISTORY:],
                "mem": list(_sys_history["mem"])[-SPARK_HISTORY:],
                "swap": list(_sys_history["swap"])[-SPARK_HISTORY:],
                "disk": list(_sys_history["disk"])[-SPARK_HISTORY:],
            },
            "ping": {
                "available": bool(_ping_available) if _ping_available is not None else None,
                "icmp_available": bool(_ping_available) if _ping_available is not None else None,
                "tcp_fallback": True,
                "summary": ping_summary,
                "targets": targets,
            },
            "events": list(_events)[:EVENT_MAX],
            "event_count": len(_events),
        }
    return payload


def _cached_html() -> Tuple[bytes, str]:
    """首页 HTML 缓存 + 弱 ETag，减轻重复传输。"""
    global _html_body, _html_etag
    if _html_body is None or _html_etag is None:
        _html_body = INDEX_HTML.encode("utf-8")
        _html_etag = '"' + hashlib.sha256(_html_body).hexdigest()[:16] + '"'
    return _html_body, _html_etag


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class ProbeHandler(BaseHTTPRequestHandler):
    server_version = f"VPSProbe/{VERSION}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # 轮询/健康检查降噪，避免刷屏与磁盘 I/O
        try:
            msg = fmt % args if args else str(fmt)
        except Exception:
            msg = str(fmt)
        if " /api/status" in msg or " /health" in msg:
            return
        print(f"[{_now_iso()}] {self.address_string()} {msg}")

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

    def _send_html_cached(self) -> None:
        body, etag = _cached_html()
        inm = self.headers.get("If-None-Match")
        try:
            if inm and inm.strip() == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "public, max-age=30")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=30")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/":
                self._send_html_cached()
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
                with _state_lock:
                    ping_av = _ping_available
                    online_n = sum(1 for r in _ping_results.values() if r.get("online"))
                    total_n = len(PING_TARGETS)
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "version": VERSION,
                        "uptime_seconds": int(time.time() - _start_time),
                        "runtime": detect_runtime(),
                        "ping_available": bool(ping_av) if ping_av is not None else None,
                        "ping_online": online_n,
                        "ping_total": total_n,
                    },
                )
            elif path == "/api/summary":
                # 轻量摘要：多开页面或外部探活可少传数据
                try:
                    full = build_status_payload()
                    ps = (full.get("ping") or {}).get("summary") or {}
                    sysd = full.get("system") or {}
                    self._send_json(
                        200,
                        {
                            "ok": True,
                            "version": full.get("version"),
                            "runtime": full.get("runtime"),
                            "uptime_seconds": full.get("uptime_seconds"),
                            "collect_ms": full.get("collect_ms"),
                            "cpu_percent": sysd.get("cpu_percent"),
                            "memory_percent": sysd.get("memory_percent"),
                            "disk_percent": sysd.get("disk_percent"),
                            "ping_online": ps.get("online"),
                            "ping_total": ps.get("total"),
                            "ping_quality": ps.get("quality"),
                            "ping_avg_ms": ps.get("avg_ms"),
                        },
                    )
                except Exception:
                    self._send_json(500, {"ok": False, "error": "internal_error"})
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
<meta name="description" content="VPS Probe — 极简单页 VPS 探针监控" />
<title>VPS Probe · 矩阵终端</title>
<script>
/* 尽早应用主题，避免首屏布局闪烁 */
(function () {
  try {
    var t = localStorage.getItem("vps-probe-theme");
    if (t === "dashboard") {
      document.documentElement.setAttribute("data-theme", t);
    }
  } catch (e) {}
})();
</script>
<style>
:root {
  --bg: #020604;
  /* 面板半透明，透出矩阵数字雨 */
  --panel: rgba(0, 14, 6, 0.52);
  --panel-solid: rgba(0, 12, 5, 0.72);
  --border: #00ff6a;
  --text: #b6ffcb;
  --dim: #4da86a;
  --ok: #00ff88;
  --warn: #ffcc00;
  --danger: #ff3355;
  --offline: #666;
  --glow: 0 0 6px rgba(0, 255, 106, 0.22);
  --font: "SF Mono", "Cascadia Code", "Consolas", "Menlo", ui-monospace, monospace;
  /* 雨层可见但不抢 GPU；配合低密度绘制 */
  --rain-opacity: 0.38;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html {
  height: 100%;
  /* 避免 overflow-x:hidden 裁切 position:fixed 底栏溢出内容 */
  overflow-x: clip;
  overflow-y: auto;
}
body {
  min-height: 100%;
  width: 100%;
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  font-size: 13px;
  line-height: 1.45;
  overflow-x: clip;
  overflow-y: visible;
}
#rain {
  position: fixed; inset: 0; z-index: 0;
  width: 100%; height: 100%;
  pointer-events: none;
  opacity: var(--rain-opacity);
}
.scanlines {
  position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.05) 2px,
    rgba(0, 0, 0, 0.05) 4px
  );
  mix-blend-mode: multiply;
  opacity: 0.5;
  will-change: auto;
  contain: strict;
}
.wrap {
  position: relative; z-index: 2;
  min-height: 100%;
  display: flex; flex-direction: column;
  /* 预留底栏完整高度，避免内容被挡住 */
  padding: 12px 14px calc(96px + env(safe-area-inset-bottom, 0px));
  max-width: 1400px; margin: 0 auto;
  width: 100%;
  box-sizing: border-box;
  overflow-x: clip;
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
  transition: border-color 0.3s, color 0.3s;
}
.badge .dot {
  width: 7px; height: 7px; border-radius: 50%; background: var(--ok);
  box-shadow: 0 0 4px var(--ok);
  transition: background 0.3s, box-shadow 0.3s;
}
.badge.offline { border-color: var(--danger); color: var(--danger); }
.badge.offline .dot { background: var(--danger); box-shadow: 0 0 4px var(--danger); }
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
  transition: border-color 0.3s;
}
.panel:hover {
  border-color: rgba(0,255,106,0.6);
}
.panel::before {
  content: "";
  position: absolute; left: 0; right: 0; top: 0; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(0,255,106,0.55), transparent);
  opacity: 0.65;
  /* 去掉无限位移动画，减轻主线程/合成压力 */
}
.panel h2 {
  font-size: 12px; letter-spacing: 0.16em; color: var(--ok);
  margin-bottom: 10px; text-transform: uppercase;
  border-bottom: 1px solid rgba(0,255,106,0.2); padding-bottom: 6px;
  display: flex; align-items: center; gap: 8px;
  text-shadow: 0 0 6px rgba(0,255,136,0.3);
}
.panel h2::before {
  content: "▸";
  font-size: 10px;
  opacity: 0.6;
}
.kv {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 8px;
}
.kv .item {
  border: 1px solid rgba(0,255,106,0.12);
  background: rgba(0, 0, 0, 0.18);
  padding: 7px 8px; border-radius: 3px;
  transition: background 0.2s, border-color 0.2s;
}
.kv .item:hover {
  background: rgba(0, 255, 106, 0.06);
  border-color: rgba(0,255,106,0.25);
}
/* CPU 每核使用率：与 CPU/内存/Swap/磁盘同一套 meter 行样式 */
#sysCores.meter { margin-top: 0; }
#sysCores.meter .row { margin-bottom: 6px; }
#sysCores.meter .row:last-child { margin-bottom: 0; }
/* 磁盘 I/O 速率 */
.io-row {
  display: flex; gap: 12px; margin-top: 8px;
  font-size: 11px; color: var(--dim);
}
.io-row .io-item {
  display: flex; align-items: center; gap: 4px;
}
.io-row .io-arrow { font-size: 10px; }
.io-row .io-arrow.read { color: var(--ok); }
.io-row .io-arrow.write { color: var(--warn); }
/* 仪表盘默认：标签在上、值在下 */
.kv .item .k {
  display: block;
  color: var(--dim);
  font-size: 10px;
  margin-bottom: 2px;
}
.kv .item .v {
  display: block;
  color: var(--text);
  word-break: break-all;
  font-size: 12px;
}
.meter { margin-top: 10px; }
.meter .row {
  display: grid; grid-template-columns: 72px 1fr 52px 60px;
  gap: 8px; align-items: center; margin-bottom: 8px;
}
.meter-spark {
  display: flex; align-items: center; justify-content: flex-end;
}
.meter-spark svg { display: block; }
.meter .label { color: var(--dim); font-size: 11px; white-space: nowrap; }
.meter .pct { text-align: right; font-variant-numeric: tabular-nums; min-width: 42px; }
/* 进度条专用，类名 meter-bar，避免与底栏冲突 */
.meter-bar {
  height: 10px; background: rgba(0,40,15,0.8);
  border: 1px solid rgba(0,255,106,0.25); border-radius: 2px; overflow: hidden;
}
.meter-bar > i {
  display: block; height: 100%; width: 0%;
  background: linear-gradient(90deg, #00aa55, var(--ok));
  box-shadow: 0 0 8px rgba(0,255,136,0.5);
  transition: width 0.25s linear;
}
.meter-bar.warn > i { background: linear-gradient(90deg, #aa8800, var(--warn)); box-shadow: 0 0 8px rgba(255,204,0,0.5); }
.meter-bar.danger > i { background: linear-gradient(90deg, #aa0022, var(--danger)); box-shadow: 0 0 8px rgba(255,51,85,0.5); }
.pct.ok, .st.ok { color: var(--ok); }
.pct.warn, .st.warn { color: var(--warn); }
.pct.danger, .st.danger { color: var(--danger); }
.pct.offline, .st.offline, .st.unavailable, .st.pending { color: var(--offline); }

.ping-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.ping-table th, .ping-table td {
  text-align: left; padding: 6px 4px;
  border-bottom: 1px solid rgba(0,255,106,0.12);
  white-space: nowrap;
  transition: background 0.15s;
}
.ping-table tbody tr:hover {
  background: rgba(0,255,106,0.04);
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
  background: rgba(0, 0, 0, 0.32);
  border: 1px solid rgba(0,255,106,0.15);
  padding: 8px 10px;
  border-radius: 3px;
  scrollbar-width: thin;
  scrollbar-color: rgba(0,255,106,0.25) rgba(0,0,0,0.2);
}
.term-body::-webkit-scrollbar {
  width: 6px;
}
.term-body::-webkit-scrollbar-track {
  background: rgba(0,0,0,0.2);
  border-radius: 3px;
}
.term-body::-webkit-scrollbar-thumb {
  background: rgba(0,255,106,0.25);
  border-radius: 3px;
}
.term-body::-webkit-scrollbar-thumb:hover {
  background: rgba(0,255,106,0.4);
}
.term-line {
  margin-bottom: 3px;
  white-space: pre-wrap;
  word-break: break-word;
  padding: 2px 4px;
  border-radius: 2px;
  transition: background 0.15s;
}
.term-line:hover {
  background: rgba(0,255,106,0.06);
}
.term-line .ts { color: var(--dim); }
.term-line .lv { font-weight: bold; margin: 0 6px; }
.term-line .lv.INFO { color: #7fd4ff; }
.term-line .lv.OK { color: var(--ok); }
.term-line .lv.WARN { color: var(--warn); }
.term-line .lv.ERROR { color: var(--danger); }
/* 状态指示器过渡动画 */
.st.ok, .st.warn, .st.danger, .st.offline {
  transition: color 0.3s ease;
}
.pct.ok, .pct.warn, .pct.danger {
  transition: color 0.3s ease;
}
.cursor {
  display: inline-block; width: 8px; height: 13px;
  background: var(--ok); margin-left: 2px; vertical-align: text-bottom;
  animation: blink 1s step-end infinite;
}
@keyframes blink { 50% { opacity: 0; } }

/* 底栏 class 禁止使用 .bar —— 会与进度条 .bar{height:10px} 冲突导致底栏被压扁裁切 */
footer.status-bar {
  position: fixed;
  left: 0;
  right: 0;
  bottom: 0;
  width: auto;
  box-sizing: border-box;
  z-index: 100;
  margin: 0;
  padding: 0;
  border: 0;
  height: auto;
  min-height: 0;
  max-height: none;
  background: rgba(0, 8, 4, 0.96);
  border-top: 1px solid rgba(0, 255, 106, 0.45);
  box-shadow: 0 -4px 12px rgba(0, 0, 0, 0.35);
  overflow: visible;
  font-size: 11px;
  color: var(--dim);
}
footer.status-bar .footer-inner {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: center; /* 底栏信息水平居中 */
  gap: 6px 8px;
  width: 100%;
  box-sizing: border-box;
  padding: 10px 12px calc(10px + env(safe-area-inset-bottom, 0px));
  min-height: 44px;
}
footer.status-bar .f-item {
  display: inline-flex;
  align-items: center;
  flex: 0 0 auto;
  white-space: nowrap;
  height: 26px;
  line-height: 1;
  background: rgba(0, 28, 12, 0.72);
  border: 1px solid rgba(0, 255, 106, 0.22);
  border-radius: 4px;
  padding: 0 9px;
  box-sizing: border-box;
}
footer.status-bar strong {
  color: var(--text);
  font-weight: normal;
  margin-left: 2px;
}
@media (max-width: 720px) {
  footer.status-bar { font-size: 10px; }
  footer.status-bar .footer-inner {
    gap: 5px 6px;
    padding: 8px 8px calc(8px + env(safe-area-inset-bottom, 0px));
    justify-content: center;
  }
  footer.status-bar .f-item { height: 24px; padding: 0 7px; flex: 0 1 auto; }
  .wrap { padding-bottom: calc(120px + env(safe-area-inset-bottom, 0px)); }
}
@media (max-width: 480px) {
  footer.status-bar .footer-inner {
    gap: 4px 5px;
    padding: 6px 6px calc(6px + env(safe-area-inset-bottom, 0px));
  }
  footer.status-bar .f-item {
    height: 22px;
    padding: 0 6px;
    font-size: 9px;
  }
}
.err-banner {
  display: none;
  margin-bottom: 10px; padding: 8px 12px;
  border: 1px solid var(--danger); color: var(--danger);
  background: rgba(40,0,8,0.7); border-radius: 3px;
  font-size: 12px;
  animation: banner-pulse 2s ease-in-out infinite;
}
@keyframes banner-pulse {
  0%, 100% { border-color: rgba(255,51,85,0.5); box-shadow: 0 0 4px rgba(255,51,85,0.15); }
  50% { border-color: rgba(255,51,85,0.9); box-shadow: 0 0 8px rgba(255,51,85,0.3); }
}
.err-banner.show { display: block; }
.err-banner::before {
  content: "⚠ ";
  font-weight: bold;
}

/* ---- 顶栏操作区 ---- */
.header-actions {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
}
.icon-btn {
  appearance: none; cursor: pointer;
  font-family: var(--font); font-size: 11px;
  color: var(--ok);
  background: rgba(0, 30, 12, 0.7);
  border: 1px solid rgba(0,255,106,0.45);
  border-radius: 999px;
  padding: 4px 12px;
  box-shadow: 0 0 8px rgba(0,255,106,0.15);
  letter-spacing: 0.06em;
  transition: background 0.2s, border-color 0.2s, box-shadow 0.2s, opacity 0.2s;
}
.icon-btn {
  min-width: 32px;
  padding: 4px 10px;
  line-height: 1;
}
.icon-btn:hover {
  background: rgba(0, 50, 20, 0.85);
  border-color: var(--ok);
  box-shadow: 0 0 12px rgba(0,255,136,0.35);
}
.icon-btn:active {
  transform: scale(0.96);
  box-shadow: 0 0 4px rgba(0,255,106,0.2);
}
.icon-btn:focus-visible {
  outline: 1px solid var(--ok);
  outline-offset: 2px;
}
.icon-btn.busy { opacity: 0.55; pointer-events: none; }
.ver-chip {
  font-size: 10px;
  color: var(--ok);
  border: 1px solid rgba(0,255,106,0.35);
  border-radius: 999px;
  padding: 2px 10px;
  letter-spacing: 0.04em;
  background: rgba(0,255,106,0.08);
  box-shadow: 0 0 6px rgba(0,255,106,0.12);
}
.mode-chip {
  font-size: 10px;
  margin-left: 6px;
  color: var(--warn);
  border: 1px solid rgba(255,204,0,0.35);
  border-radius: 999px;
  padding: 2px 10px;
  background: rgba(255,204,0,0.08);
}
.mode-chip.host {
  color: var(--ok);
  border-color: rgba(0,255,106,0.35);
  background: rgba(0,255,106,0.08);
}
.toolbar {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  margin-bottom: 10px;
  padding: 8px 10px;
  border: 1px solid rgba(0,255,106,0.2);
  background: rgba(0, 12, 6, 0.4);
  border-radius: 4px;
}
.toolbar label {
  display: inline-flex; align-items: center; gap: 6px;
  color: var(--dim); font-size: 11px; cursor: pointer; user-select: none;
}
.toolbar select {
  font-family: var(--font); font-size: 11px;
  color: var(--text);
  background: rgba(0,0,0,0.4);
  border: 1px solid rgba(0,255,106,0.3);
  border-radius: 4px;
  padding: 3px 6px;
}
.toolbar .hint { color: var(--dim); font-size: 10px; margin-left: auto; max-width: 46%; }
@media (max-width: 720px) {
  .toolbar .hint { max-width: 100%; margin-left: 0; }
}
.ping-summary {
  display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px;
  font-size: 11px; color: var(--dim);
}
.ping-summary .ps {
  border: 1px solid rgba(0,255,106,0.2);
  background: rgba(0,0,0,0.25);
  border-radius: 4px;
  padding: 4px 8px;
  transition: border-color 0.2s;
}
.ping-summary .ps:hover {
  border-color: rgba(0,255,106,0.4);
}
.ping-summary .ps strong { color: var(--text); font-weight: normal; }
.ping-summary .ps.ok strong { color: var(--ok); }
.ping-summary .ps.warn strong { color: var(--warn); }
.ping-summary .ps.danger strong { color: var(--danger); }
/* 桌面用表格；分组卡片仅移动端展示，避免桌面残留「DNS · N / 网站 · N」空标题行 */
.ping-groups { display: none; flex-direction: column; gap: 12px; }
/* 分组折叠 */
.ping-group-header {
  display: flex; align-items: center; gap: 8px;
  cursor: pointer; user-select: none;
  padding: 4px 0;
}
.ping-group-header h3 {
  margin: 0;
  border-bottom: none;
  padding-bottom: 0;
}
.ping-group-header .fold-icon {
  font-size: 10px; color: var(--dim);
  transition: transform 0.2s;
  display: inline-block;
}
.ping-group.collapsed .fold-icon { transform: rotate(-90deg); }
.ping-group.collapsed .ping-cards { display: none !important; }
.ping-group.collapsed .ping-table-wrap { display: none !important; }
/* 探测筛选按钮组 */
.ping-filter-bar {
  display: flex; gap: 6px; align-items: center;
  margin-bottom: 8px;
}
.ping-filter-btn {
  appearance: none; cursor: pointer;
  font-family: var(--font); font-size: 10px;
  color: var(--dim);
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid rgba(0,255,106,0.2);
  border-radius: 999px;
  padding: 3px 10px;
  transition: all 0.15s;
}
.ping-filter-btn:hover {
  border-color: rgba(0,255,106,0.4);
  color: var(--text);
}
.ping-filter-btn.active {
  color: var(--ok);
  border-color: rgba(0,255,106,0.6);
  background: rgba(0,255,106,0.1);
}
.ping-card .soft {
  display: inline-block; margin-left: 4px; font-size: 9px;
  color: var(--warn); border: 1px solid rgba(255,204,0,0.3);
  border-radius: 3px; padding: 0 4px; vertical-align: middle;
}
.ping-table thead th {
  position: sticky; top: 0; background: rgba(0, 12, 6, 0.95); z-index: 1;
}
/* 焦点可见样式：键盘导航 */
:focus-visible {
  outline: 2px solid var(--ok);
  outline-offset: 2px;
}
button:focus-visible, select:focus-visible {
  outline: 2px solid var(--ok);
  outline-offset: 2px;
  box-shadow: 0 0 8px rgba(0,255,106,0.3);
}
/* 移动端触摸优化 */
.ping-card, .icon-btn, .f-item {
  touch-action: manipulation;
  -webkit-tap-highlight-color: transparent;
}
.kbd {
  font-size: 10px; color: var(--dim);
  border: 1px solid rgba(0,255,106,0.25);
  border-radius: 3px; padding: 0 4px; margin: 0 2px;
}
.spark {
  display: block;
  margin-top: 6px;
  width: 100%;
  max-width: 96px;
  height: 22px;
  opacity: 0.9;
}
.spark-cell { min-width: 80px; }
.quality-chip {
  font-size: 10px; margin-left: 6px;
  border-radius: 999px; padding: 2px 8px;
  border: 1px solid rgba(0,255,106,0.3); color: var(--ok);
}
.quality-chip.good { color: var(--ok); }
.quality-chip.fair { color: var(--warn); border-color: rgba(255,204,0,0.35); }
.quality-chip.poor { color: var(--danger); border-color: rgba(255,51,85,0.4); }
.quality-chip.excellent { color: var(--ok); box-shadow: 0 0 6px rgba(0,255,136,0.25); }
.copy-btn {
  margin-left: 6px; cursor: pointer; font-size: 10px;
  color: var(--dim); border: 1px solid rgba(0,255,106,0.25);
  background: transparent; border-radius: 3px; padding: 0 5px;
  font-family: var(--font);
}
.copy-btn:hover { color: var(--ok); border-color: var(--ok); }
.stale-banner {
  display: none; margin-bottom: 10px; padding: 6px 10px;
  border: 1px solid var(--warn); color: var(--warn);
  background: rgba(40, 30, 0, 0.55); border-radius: 3px; font-size: 11px;
}
.stale-banner.show { display: block; }
.ping-table tbody tr:nth-child(even) { background: rgba(0, 255, 106, 0.03); }
.ping-card .streak {
  font-size: 9px; color: var(--danger); margin-left: 4px;
}
.help-pop {
  display: none; position: fixed; right: 14px; bottom: 72px; z-index: 80;
  width: min(320px, calc(100vw - 28px));
  background: rgba(0, 12, 6, 0.96);
  border: 1px solid rgba(0,255,106,0.35);
  border-radius: 6px; padding: 12px 14px;
  font-size: 11px; color: var(--text); line-height: 1.55;
  box-shadow: 0 8px 24px rgba(0,0,0,0.45);
}
.help-pop.show { display: block; }
.help-pop h3 { color: var(--ok); font-size: 12px; margin-bottom: 6px; letter-spacing: 0.08em; }
.help-pop .row { color: var(--dim); margin: 3px 0; }
.help-pop .row strong { color: var(--text); font-weight: normal; }
body.perf-mode .scanlines { display: none !important; }
body.perf-mode #rain { display: none !important; opacity: 0 !important; }
body.perf-mode .panel { box-shadow: none; }
body.perf-mode .spark { display: none; }
body.perf-mode .toolbar .hint .kbd { display: none; }
body.compact-footer .status-bar .f-item:nth-child(n+7) { display: none; }
.icon-btn, .theme-btn, .toolbar label, .toolbar select { min-height: 28px; }
.icon-btn:focus-visible, .theme-btn:focus-visible, .toolbar input:focus-visible,
.toolbar select:focus-visible, .copy-btn:focus-visible {
  outline: 1px solid var(--ok); outline-offset: 2px;
}
@media print {
  #rain, .scanlines, .toolbar, .status-bar { display: none !important; }
  body { background: #fff; color: #000; }
  .panel { box-shadow: none; border-color: #999; }
}
.ping-group h3 {
  font-size: 11px; color: var(--ok); letter-spacing: 0.08em;
  margin-bottom: 6px; font-weight: normal;
  padding-bottom: 4px;
  border-bottom: 1px solid rgba(0,255,106,0.15);
}
.ping-cards {
  display: none;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 8px;
}
.ping-card {
  border: 1px solid rgba(0,255,106,0.18);
  background: rgba(0,0,0,0.22);
  border-radius: 4px;
  padding: 10px;
  font-size: 11px;
  transition: border-color 0.15s, box-shadow 0.15s;
}
.ping-card:hover {
  border-color: rgba(0,255,106,0.35);
  box-shadow: 0 0 6px rgba(0,255,106,0.12);
}
.ping-card .name { color: var(--text); margin-bottom: 2px; }
.ping-card .host { color: var(--dim); font-size: 10px; margin-bottom: 6px; word-break: break-all; }
.ping-card .ms { font-size: 16px; color: var(--ok); }
.ping-card .meta { color: var(--dim); margin-top: 4px; font-size: 10px; }
.ping-card.offline .ms { color: var(--offline); }
.ping-card.warn .ms { color: var(--warn); }
.ping-card.danger .ms { color: var(--danger); }
@media (max-width: 960px) {
  .ping-table-wrap { display: none; }
  .ping-groups { display: flex; }
  .ping-cards { display: grid; }
}
.event-filters { display: inline-flex; gap: 6px; align-items: center; }
.v-long {
  display: inline-block; max-width: 100%;
  word-break: break-word;
  overflow-wrap: anywhere;
}

</style>
</head>
<body data-theme="dashboard">
<script>
(function () {
  try {
    var t = document.documentElement.getAttribute("data-theme");
    if (t === "dashboard") document.body.setAttribute("data-theme", t);
  } catch (e) {}
})();
</script>
<canvas id="rain" aria-hidden="true"></canvas>
<div class="scanlines" aria-hidden="true"></div>
<div class="wrap">
  <header class="app">
    <div>
      <h1>◈ VPS PROBE // MATRIX <span class="ver-chip" id="hdrVer">v—</span></h1>
      <div class="sub">只读系统探针 · 无命令执行 · 零配置</div>
    </div>
    <div class="header-actions">
      <button type="button" id="refreshBtn" class="icon-btn" title="立即刷新数据 (R)" aria-label="立即刷新数据">↻</button>
      <div id="onlineBadge" class="badge"><span class="dot"></span><span id="onlineText">连接中…</span></div>
    </div>
  </header>
  <div id="errBanner" class="err-banner">与后端连接异常，正在重试并保留最后成功数据…</div>

  <div class="toolbar" id="toolbar">
    <label title="关闭动画、放慢刷新，适合低配/卡顿时"><input type="checkbox" id="perfToggle" /> 性能模式</label>
    <label title="关闭可进一步降低卡顿"><input type="checkbox" id="rainToggle" checked /> 背景动画</label>
    <label title="底栏仅保留关键项"><input type="checkbox" id="compactFooter" /> 紧凑底栏</label>
    <label class="event-filters">事件
      <select id="eventFilter" title="过滤事件等级">
        <option value="all">全部</option>
        <option value="warn" selected>告警+</option>
        <option value="error">仅错误</option>
      </select>
    </label>
    <label class="event-filters">刷新
      <select id="pollInterval" title="前端轮询间隔">
        <option value="3000">3s</option>
        <option value="5000">5s</option>
        <option value="10000">10s</option>
      </select>
    </label>
    <button type="button" id="exportBtn" class="icon-btn" title="导出当前状态 JSON">⬇</button>
    <button type="button" id="helpBtn" class="icon-btn" title="快捷键帮助 (?)">?</button>
    <span class="hint" id="runtimeHint">运行模式检测中… · <span class="kbd">A</span>动画 <span class="kbd">P</span>性能 <span class="kbd">R</span>刷新 <span class="kbd">?</span>帮助</span>
  </div>
  <div id="staleBanner" class="stale-banner">数据偏旧，正在重试连接…</div>
  <div id="helpPop" class="help-pop" role="dialog" aria-label="快捷键帮助">
    <h3>快捷键</h3>
    <div class="row"><strong>R</strong> 立即刷新</div>
    <div class="row"><strong>A</strong> 背景动画</div>
    <div class="row"><strong>P</strong> 性能模式</div>
    <div class="row"><strong>C</strong> 紧凑底栏</div>
    <div class="row"><strong>E</strong> 导出 JSON</div>
    <div class="row"><strong>?</strong> 打开/关闭本帮助</div>
    <div class="row">双击主机名可复制</div>
  </div>

  <div class="grid">
    <section class="panel" id="sysPanel">
      <h2>01 // 系统性能 <span class="mode-chip host" id="runtimeChip" style="display:none"></span></h2>
      <div class="kv" id="sysKv"><div class="item"><span class="k">状态</span><span class="v">加载中…</span></div></div>
      <div class="meter" id="sysMeters"></div>
      <div class="meter" id="sysCores"></div>
      <div id="sysIo"></div>
    </section>

    <section class="panel" id="pingPanel">
      <h2 id="pingTitle">02 // 外部探测 <span class="quality-chip" id="qualityChip" style="display:none"></span></h2>
      <div class="ping-filter-bar" id="pingFilterBar">
        <button type="button" class="ping-filter-btn active" data-filter="all">全部</button>
        <button type="button" class="ping-filter-btn" data-filter="dns">仅 DNS</button>
        <button type="button" class="ping-filter-btn" data-filter="web">仅网站</button>
      </div>
      <div class="ping-summary" id="pingSummary"></div>
      <div class="ping-groups" id="pingGroups"></div>
      <div class="scroll-x ping-table-wrap">
        <table class="ping-table">
          <thead>
            <tr>
              <th>分组</th><th>目标</th><th>主机</th><th>当前</th><th>趋势</th><th>最低</th><th>最高</th>
              <th>平均</th><th>丢包</th><th>状态</th><th>方式</th><th>检测时间</th>
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

<footer class="status-bar" id="statusBar">
  <div class="footer-inner">
    <span class="f-item" title="浏览器本地日期">日期 <strong id="fDate">—</strong></span>
    <span class="f-item" title="浏览器本地时间">时间 <strong id="fTime">—</strong></span>
    <span class="f-item" title="浏览器请求接口往返耗时">请求 <strong id="fReq">—</strong> ms</span>
    <span class="f-item" title="服务端采集系统指标耗时">采集 <strong id="fCollect">—</strong> ms</span>
    <span class="f-item" title="系统指标距上次采集已过秒数">指标距今 <strong id="fAge">—</strong> s</span>
    <span class="f-item" title="Ping 结果距上次检测已过秒数">探测距今 <strong id="fPingAge">—</strong> s</span>
    <span class="f-item" title="服务端最近一次成功返回时间（服务端时区）">更新于 <strong id="fUpdated">—</strong></span>
    <span class="f-item" title="服务端时区；日期/时间为浏览器本地时区">时区 <strong id="fTz">—</strong></span>
    <span class="f-item" title="与后端连接状态">状态 <strong id="fStatus">—</strong></span>
    <span class="f-item" title="探针服务持续运行时间">服务运行 <strong id="fUptime">—</strong></span>
    <span class="f-item" title="探针版本">v<strong id="fVer">—</strong></span>
  </div>
</footer>

<script>
(function () {
  "use strict";

  var lastOk = null;
  var lastEventsSig = "";
  var lastSysSig = "";
  var lastPingSig = "";
  var PING_FILTER_KEY = "vps-probe-ping-filter";
  var PING_FOLD_KEY = "vps-probe-ping-fold";
  var pingGroupFilter = "all";
  var pingFolded = { dns: false, web: false };
  try {
    var _pf = localStorage.getItem(PING_FILTER_KEY);
    if (_pf === "dns" || _pf === "web" || _pf === "all") pingGroupFilter = _pf;
    var _pfd = localStorage.getItem(PING_FOLD_KEY);
    if (_pfd) { var _f = JSON.parse(_pfd); if (_f && typeof _f === "object") pingFolded = _f; }
  } catch (e) {}
  var pollMs = 3000;
  var pollMsHidden = 8000;
  var timer = null;
  var clockTimer = null;
  var serviceUptimeBase = 0;
  var serviceUptimeAt = 0;
  var metricsAgeBase = null;
  var pingAgeBase = null;
  var agesAt = 0;
  var RAIN_KEY = "vps-probe-rain";
  var EVENT_FILTER_KEY = "vps-probe-event-filter";
  var PERF_KEY = "vps-probe-perf";
  var COMPACT_KEY = "vps-probe-compact-footer";
  var POLL_KEY = "vps-probe-poll-ms";
  var reducedMotion = false;
  var rainEnabled = true;
  var perfMode = false;
  var compactFooter = false;
  var eventFilter = "warn";
  var lastEventsRaw = [];
  var rainRaf = 0;
  var resizeTimer = 0;
  var pollMsNormal = 3000;
  var pollMsPerf = 5000;
  var userPollMs = 3000;
  try {
    reducedMotion = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  } catch (e) {}
  /* 批量读取 localStorage，减少独立 try-catch 开销 */
  try {
    var _lsRain = localStorage.getItem(RAIN_KEY);
    if (_lsRain === "0") rainEnabled = false;
    else if (_lsRain === "1") rainEnabled = true;
    var _lsEf = localStorage.getItem(EVENT_FILTER_KEY);
    if (_lsEf === "all" || _lsEf === "warn" || _lsEf === "error") eventFilter = _lsEf;
    var _lsPf = localStorage.getItem(PERF_KEY);
    if (_lsPf === "1") perfMode = true;
    else if (_lsPf === "0") perfMode = false;
    else {
      var cores = navigator.hardwareConcurrency || 4;
      var saveData = !!(navigator.connection && navigator.connection.saveData);
      var battLow = false;
      try {
        if (navigator.getBattery) {
          /* 异步补判；首次仍用 cores/saveData */
        }
      } catch (e2) {}
      if (cores <= 2 || saveData || reducedMotion || battLow) perfMode = true;
    }
    compactFooter = localStorage.getItem(COMPACT_KEY) === "1";
    var _lsPoll = parseInt(localStorage.getItem(POLL_KEY) || "0", 10);
    if (_lsPoll === 3000 || _lsPoll === 5000 || _lsPoll === 10000) userPollMs = _lsPoll;
  } catch (e) {}
  if (perfMode) {
    rainEnabled = false;
    pollMs = Math.max(userPollMs, pollMsPerf);
  } else {
    pollMs = userPollMs || pollMsNormal;
  }
  if (compactFooter) {
    try { document.body.classList.add("compact-footer"); } catch (e) {}
  }

  function $(id) { return document.getElementById(id); }

  function setRainEnabled(on, skipStore) {
    rainEnabled = !!on;
    if (!skipStore) {
      try { localStorage.setItem(RAIN_KEY, rainEnabled ? "1" : "0"); } catch (e) {}
    }
    var tg = $("rainToggle");
    if (tg) {
      tg.checked = rainEnabled;
      tg.disabled = !!(perfMode || reducedMotion);
    }
    if (!rainEnabled || reducedMotion || perfMode) {
      stopRainLoop();
      if (canvas && ctx) {
        try {
          ctx.globalAlpha = 1;
          ctx.fillStyle = "#020604";
          ctx.fillRect(0, 0, canvas.width || 1, canvas.height || 1);
        } catch (e) {}
      }
      if (canvas) canvas.style.opacity = "0";
    } else {
      if (canvas) {
        canvas.style.display = "";
        canvas.style.opacity = "";
      }
      resizeRain();
      if (document.visibilityState === "visible") startRainLoop();
    }
  }

  function setPerfMode(on) {
    perfMode = !!on;
    try { localStorage.setItem(PERF_KEY, perfMode ? "1" : "0"); } catch (e) {}
    document.body.classList.toggle("perf-mode", perfMode);
    var pt = $("perfToggle");
    if (pt) pt.checked = perfMode;
    pollMs = perfMode ? Math.max(userPollMs, pollMsPerf) : userPollMs;
    resetPollTimer();
    if (perfMode) {
      setRainEnabled(false, true);
    } else {
      // 退出性能模式：恢复用户动画偏好（未显式关过则开启）
      var wantRain = true;
      try {
        var rs2 = localStorage.getItem(RAIN_KEY);
        if (rs2 === "0") wantRain = false;
      } catch (e) {}
      if (!reducedMotion) setRainEnabled(wantRain, true);
    }
  }

  function setCompactFooter(on) {
    compactFooter = !!on;
    try { localStorage.setItem(COMPACT_KEY, compactFooter ? "1" : "0"); } catch (e) {}
    document.body.classList.toggle("compact-footer", compactFooter);
    var cf = $("compactFooter");
    if (cf) cf.checked = compactFooter;
  }

  function setUserPollMs(ms) {
    ms = parseInt(ms, 10);
    if (ms !== 3000 && ms !== 5000 && ms !== 10000) ms = 3000;
    userPollMs = ms;
    try { localStorage.setItem(POLL_KEY, String(ms)); } catch (e) {}
    pollMs = perfMode ? Math.max(userPollMs, pollMsPerf) : userPollMs;
    resetPollTimer();
    var sel = $("pollInterval");
    if (sel) sel.value = String(userPollMs);
  }

  function toggleHelp() {
    var hp = $("helpPop");
    if (!hp) return;
    hp.classList.toggle("show");
  }

  function exportStatusJson() {
    if (!lastOk) return;
    try {
      var blob = new Blob([JSON.stringify(lastOk, null, 2)], { type: "application/json" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "vps-probe-status-" + Date.now() + ".json";
      document.body.appendChild(a);
      a.click();
      setTimeout(function () {
        URL.revokeObjectURL(a.href);
        a.remove();
      }, 500);
    } catch (e) {}
  }

  function copyText(text) {
    text = String(text || "");
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(function () {});
      return;
    }
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    } catch (e) {}
  }

  function updateQualityChip(summary) {
    var chip = $("qualityChip");
    if (!chip) return;
    var q = (summary && summary.quality) || "";
    var map = {
      excellent: "网络优",
      good: "网络良",
      fair: "网络一般",
      poor: "网络差"
    };
    if (!q || !map[q]) {
      chip.style.display = "none";
      return;
    }
    chip.style.display = "inline";
    chip.className = "quality-chip " + q;
    chip.textContent = map[q];
    chip.title = "在线率 " + ((summary.online_ratio != null ? (summary.online_ratio * 100).toFixed(0) : "—") + "%");
  }

  function updateStaleBanner(data, online) {
    var b = $("staleBanner");
    if (!b) return;
    var age = data && data.metrics_age_seconds != null ? Number(data.metrics_age_seconds) : 0;
    var show = !online || age > 15;
    b.classList.toggle("show", !!show);
    if (!online) b.textContent = "连接异常，保留最后成功数据并自动重试…";
    else if (age > 15) b.textContent = "指标数据偏旧（" + age.toFixed(0) + "s），请检查采集线程…";
  }

  var sparkCache = {};
  var sparkCacheKeys = [];
  var SPARK_CACHE_MAX = 20;
  function sparklineSvg(arr) {
    arr = (arr || []).map(Number).filter(function (x) { return !isNaN(x) && x >= 0; });
    if (arr.length < 2) {
      return '<span class="spark-empty" style="color:var(--dim);font-size:10px">—</span>';
    }
    var cacheKey = arr.join(",");
    if (sparkCache[cacheKey]) return sparkCache[cacheKey];
    var w = 72, h = 20, pad = 1.5;
    var min = Math.min.apply(null, arr);
    var max = Math.max.apply(null, arr);
    if (max <= min) max = min + 1;
    var pts = [];
    for (var i = 0; i < arr.length; i++) {
      var x = pad + (i / (arr.length - 1)) * (w - pad * 2);
      var y = h - pad - ((arr[i] - min) / (max - min)) * (h - pad * 2);
      pts.push(x.toFixed(1) + "," + y.toFixed(1));
    }
    var last = arr[arr.length - 1];
    var color = last >= 300 ? "#ff3355" : (last >= 100 ? "#ffcc00" : "#00ff88");
    var fillId = "sf" + Math.random().toString(36).slice(2, 8);
    var areaPts = pts.join(" ") + " " + (w - pad).toFixed(1) + "," + (h - pad).toFixed(1) + " " + pad.toFixed(1) + "," + (h - pad).toFixed(1);
    var result = '<svg class="spark" viewBox="0 0 ' + w + " " + h + '" width="' + w + '" height="' + h +
      '" aria-hidden="true">' +
      '<defs><linearGradient id="' + fillId + '" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="' + color + '" stop-opacity="0.3"/>' +
      '<stop offset="100%" stop-color="' + color + '" stop-opacity="0"/>' +
      '</linearGradient></defs>' +
      '<polygon fill="url(#' + fillId + ')" points="' + areaPts + '"/>' +
      '<polyline fill="none" stroke="' + color +
      '" stroke-width="1.4" stroke-linejoin="round" stroke-linecap="round" points="' +
      pts.join(" ") + '"/></svg>';
    sparkCache[cacheKey] = result;
    sparkCacheKeys.push(cacheKey);
    if (sparkCacheKeys.length > SPARK_CACHE_MAX) {
      delete sparkCache[sparkCacheKeys.shift()];
    }
    return result;
  }

  function fmtBytes(n) {
    if (n == null || isNaN(n)) return "—";
    var u = ["B","KB","MB","GB","TB","PB"];
    var i = 0; var v = Number(n);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    /* 自适应精度：大值保留 1 位小数，小值保留 2 位 */
    if (i === 0) return v + " B";
    return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + " " + u[i];
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

  function meterHtml(label, pct, status, sparkArr) {
    var st = status || "ok";
    var p = Math.max(0, Math.min(100, Number(pct) || 0));
    var spark = sparkArr ? sysSparklineSvg(sparkArr, st) : "";
    return '<div class="row"><span class="label">' + esc(label) + '</span>' +
      '<div class="meter-bar ' + esc(st) + '"><i style="width:' + p.toFixed(1) + '%"></i></div>' +
      '<span class="pct ' + esc(st) + '">' + p.toFixed(1) + '%</span>' +
      '<span class="meter-spark">' + spark + '</span></div>';
  }

  /* 系统指标趋势图：固定 0-100% 范围，颜色跟随状态 */
  var sysSparkCache = {};
  var sysSparkCacheKeys = [];
  var SYS_SPARK_CACHE_MAX = 10;
  function sysSparklineSvg(arr, status) {
    arr = (arr || []).map(Number).filter(function (x) { return !isNaN(x) && x >= 0; });
    if (arr.length < 2) return "";
    var cacheKey = arr.join(",") + "|" + status;
    if (sysSparkCache[cacheKey]) return sysSparkCache[cacheKey];
    var w = 56, h = 16, pad = 1;
    var pts = [];
    for (var i = 0; i < arr.length; i++) {
      var x = pad + (i / (arr.length - 1)) * (w - pad * 2);
      var y = h - pad - (Math.min(arr[i], 100) / 100) * (h - pad * 2);
      pts.push(x.toFixed(1) + "," + y.toFixed(1));
    }
    var color = status === "danger" ? "#ff3355" : (status === "warn" ? "#ffcc00" : "#00ff88");
    var fillId = "sy" + Math.random().toString(36).slice(2, 8);
    var areaPts = pts.join(" ") + " " + (w - pad).toFixed(1) + "," + (h - pad).toFixed(1) + " " + pad.toFixed(1) + "," + (h - pad).toFixed(1);
    var result = '<svg viewBox="0 0 ' + w + " " + h + '" width="' + w + '" height="' + h +
      '" aria-hidden="true">' +
      '<defs><linearGradient id="' + fillId + '" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="' + color + '" stop-opacity="0.3"/>' +
      '<stop offset="100%" stop-color="' + color + '" stop-opacity="0"/>' +
      '</linearGradient></defs>' +
      '<polygon fill="url(#' + fillId + ')" points="' + areaPts + '"/>' +
      '<polyline fill="none" stroke="' + color +
      '" stroke-width="1.2" stroke-linejoin="round" stroke-linecap="round" points="' +
      pts.join(" ") + '"/></svg>';
    sysSparkCache[cacheKey] = result;
    sysSparkCacheKeys.push(cacheKey);
    if (sysSparkCacheKeys.length > SYS_SPARK_CACHE_MAX) {
      delete sysSparkCache[sysSparkCacheKeys.shift()];
    }
    return result;
  }

  function compactTime(s) {
    if (!s || typeof s !== "string") return "—";
    // 2026-07-12T20:49:44+08:00 → 20:49:44
    var m = s.match(/T(\d{2}:\d{2}:\d{2})/);
    return m ? m[1] : s;
  }

  function relativeAge(sec) {
    if (sec == null || isNaN(sec)) return "—";
    sec = Math.max(0, Number(sec));
    if (sec < 1.5) return "刚刚";
    if (sec < 60) return sec.toFixed(0) + " 秒前";
    if (sec < 3600) return Math.floor(sec / 60) + " 分前";
    return (sec / 3600).toFixed(1) + " 时前";
  }

  function sortTargets(list) {
    return (list || []).slice().sort(function (a, b) {
      if (!!a.online !== !!b.online) return a.online ? -1 : 1;
      var aa = a.current_ms != null ? Number(a.current_ms) : 1e9;
      var bb = b.current_ms != null ? Number(b.current_ms) : 1e9;
      if (aa !== bb) return aa - bb;
      return String(a.name || "").localeCompare(String(b.name || ""));
    });
  }

  function renderSystem(sys, sysHist) {
    if (!sys || !Object.keys(sys).length) {
      $("sysKv").innerHTML = '<div class="item"><span class="k">状态</span><span class="v">等待首次采集…</span></div>';
      lastSysSig = "";
      return;
    }
    var hostShow = sys.hostname_display || sys.hostname || "—";
    var diskLabel = sys.disk_label || "磁盘 /（根分区）";
    var cpuModel = sys.cpu_model || "—";
    var loadLine = [sys.load_1, sys.load_5, sys.load_15].join(" / ");
    if (sys.load_per_core != null) {
      loadLine += "（每核 " + sys.load_per_core + "）";
    }
    // 界面不展示：系统版本 / 架构 / 物理核心 / 逻辑核心
    var memAvail = fmtBytes(sys.memory_available);
    if (sys.memory_available_percent != null) {
      memAvail += "（" + sys.memory_available_percent + "%）";
    }
    var diskFree = fmtBytes(sys.disk_free);
    if (sys.disk_inode_percent != null && sys.disk_inode_total) {
      diskFree += " · inode " + sys.disk_inode_percent + "%";
    }
    var netUp = fmtBytes(sys.net_bytes_sent);
    var netDown = fmtBytes(sys.net_bytes_recv);
    if (sys.net_exclude_loopback) {
      netUp += "（不含回环）";
      netDown += "（不含回环）";
    }
    var items = [
      ["主机名", hostShow],
      ["操作系统", sys.os_name],
      ["内核", sys.kernel],
      ["CPU 型号", cpuModel],
      ["负载 1/5/15", loadLine],
      ["内存", fmtBytes(sys.memory_used) + " / " + fmtBytes(sys.memory_total)],
      ["可用内存", memAvail],
      ["Swap", fmtBytes(sys.swap_used) + " / " + fmtBytes(sys.swap_total)],
      [diskLabel, fmtBytes(sys.disk_used) + " / " + fmtBytes(sys.disk_total)],
      ["磁盘可用", diskFree],
      ["启动时间", sys.boot_time],
      ["持续运行", fmtUptime(sys.uptime_seconds)],
      ["登录用户", sys.users],
      ["进程数", sys.processes],
      ["累计上传", netUp],
      ["累计下载", netDown],
      ["上传速率", fmtRate(sys.net_up_rate)],
      ["下载速率", fmtRate(sys.net_down_rate)]
    ];
    if (sys.net_top_iface) {
      items.push(["主网卡", sys.net_top_iface]);
    }
    var hSig = sysHist ? (sysHist.cpu.join(",") + "|" + sysHist.mem.join(",") + "|" + sysHist.swap.join(",") + "|" + sysHist.disk.join(",")) : "";
    var coreSig = (sys.cpu_per_core || []).join(",");
    var ioSig = (sys.disk_read_rate || 0) + "," + (sys.disk_write_rate || 0);
    var sig = items.map(function (it) { return it[0] + "=" + it[1]; }).join("|") +
      "|" + sys.cpu_percent + "|" + sys.memory_percent + "|" + sys.swap_percent + "|" + sys.disk_percent +
      "|" + (sys.runtime || "") + "|" + hSig + "|" + coreSig + "|" + ioSig;
    if (sig === lastSysSig) return;
    lastSysSig = sig;
    var frag = document.createDocumentFragment();
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      var div = document.createElement("div");
      div.className = "item";
      var longCls = (it[0] === "CPU 型号" || String(it[1]).length > 28) ? "v v-long" : "v";
      var extra = "";
      if (it[0] === "主机名") {
        extra = ' <button type="button" class="copy-btn" data-copy="' + esc(it[1]) + '" title="复制主机名">复制</button>';
      }
      div.innerHTML = '<span class="k">' + esc(it[0]) + '</span><span class="' + longCls + '" title="' + esc(it[1]) + '">' + esc(it[1]) + extra + '</span>';
      frag.appendChild(div);
    }
    $("sysKv").innerHTML = "";
    $("sysKv").appendChild(frag);
    // 复制按钮 / 双击复制
    var copyBtns = $("sysKv").querySelectorAll(".copy-btn");
    for (var bi = 0; bi < copyBtns.length; bi++) {
      copyBtns[bi].addEventListener("click", function (ev) {
        ev.preventDefault();
        copyText(this.getAttribute("data-copy") || "");
        this.textContent = "已复制";
        var self = this;
        setTimeout(function () { self.textContent = "复制"; }, 1200);
      });
    }
    var hostVal = $("sysKv").querySelector(".item .v");
    if (hostVal) {
      hostVal.addEventListener("dblclick", function () {
        copyText(hostShow);
      });
    }
    $("sysMeters").innerHTML =
      meterHtml("CPU", sys.cpu_percent, sys.cpu_status, sysHist ? sysHist.cpu : null) +
      meterHtml("内存", sys.memory_percent, sys.memory_status, sysHist ? sysHist.mem : null) +
      meterHtml("Swap", sys.swap_percent, sys.swap_status, sysHist ? sysHist.swap : null) +
      meterHtml("磁盘", sys.disk_percent, sys.disk_status, sysHist ? sysHist.disk : null);
    /* CPU 每核使用率：与上方仪表盘同一行布局（标签 + 进度条 + 百分比） */
    var coreEl = $("sysCores");
    if (coreEl) {
      var perCpu = sys.cpu_per_core || [];
      if (perCpu.length > 0) {
        coreEl.innerHTML = perCpu.map(function (pct, i) {
          var st = pct >= 90 ? "danger" : (pct >= 80 ? "warn" : "ok");
          return meterHtml("C" + i, pct, st, null);
        }).join("");
      } else {
        coreEl.innerHTML = "";
      }
    }
    /* 磁盘 I/O 速率 */
    var ioEl = $("sysIo");
    if (ioEl) {
      var readR = sys.disk_read_rate;
      var writeR = sys.disk_write_rate;
      if ((readR && readR > 0) || (writeR && writeR > 0)) {
        ioEl.innerHTML = '<div class="io-row">' +
          '<span class="io-item"><span class="io-arrow read">▼</span> 读 ' + fmtRate(readR) + '</span>' +
          '<span class="io-item"><span class="io-arrow write">▲</span> 写 ' + fmtRate(writeR) + '</span>' +
          '</div>';
      } else {
        ioEl.innerHTML = "";
      }
    }
  }

  function methodLabel(detail) {
    if (!detail) return "—";
    if (detail === "icmp" || detail === "ok") return "ICMP";
    if (detail === "tcp443") return "TCP443";
    if (detail === "tcp80") return "TCP80";
    if (String(detail).indexOf("tcp") === 0) return "TCP";
    if (detail === "pending") return "等待";
    return "—";
  }

  function renderPingSummary(ping) {
    var el = $("pingSummary");
    if (!el) return;
    var s = (ping && ping.summary) || {};
    var total = s.total != null ? s.total : ((ping && ping.targets) || []).length;
    var online = s.online != null ? s.online : 0;
    var offline = s.offline != null ? s.offline : Math.max(0, total - online);
    var avg = s.avg_ms != null ? Number(s.avg_ms).toFixed(1) + " ms" : "—";
    var ratio = s.online_ratio != null ? s.online_ratio : (total ? online / total : 0);
    var cls = ratio >= 0.85 ? "ok" : (ratio >= 0.5 ? "warn" : "danger");
    var globalMin = s.min_ms != null ? Number(s.min_ms).toFixed(1) + " ms" : "—";
    var globalMax = s.max_ms != null ? Number(s.max_ms).toFixed(1) + " ms" : "—";
    var qmap = { excellent: "优", good: "良", fair: "一般", poor: "差" };
    var q = s.quality && qmap[s.quality] ? qmap[s.quality] : "—";
    updateQualityChip(s);
    el.innerHTML =
      '<span class="ps ' + cls + '">在线 <strong>' + online + "/" + total + "</strong></span>" +
      '<span class="ps">离线 <strong>' + offline + "</strong></span>" +
      '<span class="ps ' + cls + '">质量 <strong>' + esc(q) + "</strong></span>" +
      '<span class="ps">均延迟 <strong>' + esc(avg) + "</strong></span>" +
      '<span class="ps">最低 <strong>' + esc(globalMin) + "</strong></span>" +
      '<span class="ps">最高 <strong>' + esc(globalMax) + "</strong></span>" +
      (ping && ping.icmp_available === false
        ? '<span class="ps warn">模式 <strong>TCP 回退</strong></span>'
        : '<span class="ps">模式 <strong>ICMP+TCP</strong></span>');
  }

  function renderPing(ping) {
    var body = $("pingBody");
    var groupsEl = $("pingGroups");
    if (!ping) {
      body.innerHTML = '<tr><td colspan="12">等待数据…</td></tr>';
      if (groupsEl) groupsEl.innerHTML = "";
      if ($("pingSummary")) $("pingSummary").innerHTML = "";
      lastPingSig = "";
      return;
    }
    var targets = sortTargets(ping.targets || []);
    /* 前端筛选：仅 DNS / 仅网站 */
    if (pingGroupFilter === "dns") {
      targets = targets.filter(function (t) { return t.group === "dns"; });
    } else if (pingGroupFilter === "web") {
      targets = targets.filter(function (t) { return t.group !== "dns"; });
    }
    renderPingSummary(ping);
    if ($("pingTitle")) {
      var onlineN = targets.filter(function (t) { return t.online; }).length;
      var mode = ping.icmp_available === false ? " · TCP 回退" : "";
      $("pingTitle").textContent = "02 // 外部探测 · " + onlineN + "/" + targets.length + " 在线" + mode;
    }
    var sig = targets.map(function (t) {
      return [t.id, t.online, t.current_ms, t.min_ms, t.max_ms, t.avg_ms, t.loss_percent, t.status, t.detail, t.fail_streak, t.last_check, (t.history_ms || []).join(",")].join(":");
    }).join("|");
    if (sig === lastPingSig) return;
    lastPingSig = sig;

    var ms = function (v) { return v != null ? Number(v).toFixed(1) : "—"; };
    var rows = targets.map(function (t) {
      var st = t.status || (t.online ? "ok" : "offline");
      var stLabel = t.online ? "在线" : (st === "unavailable" ? "不可用" : (st === "pending" ? "等待" : "不可达"));
      var g = t.group === "dns" ? "DNS" : "网站";
      var soft = t.soft_alert ? " · 弱网" : "";
      var streak = t.fail_streak > 1 ? (" · 连败" + t.fail_streak) : "";
      return "<tr>" +
        "<td>" + esc(g) + "</td>" +
        "<td>" + esc(t.name) + (t.soft_alert ? ' <span class="soft">弱网</span>' : "") + "</td>" +
        '<td class="host" title="' + esc(t.host) + '">' + esc(t.host) + "</td>" +
        "<td>" + esc(t.current_ms != null ? Number(t.current_ms).toFixed(1) + " ms" : "—") + "</td>" +
        '<td class="spark-cell">' + (perfMode ? "—" : sparklineSvg(t.history_ms)) + "</td>" +
        "<td>" + esc(ms(t.min_ms)) + "</td>" +
        "<td>" + esc(ms(t.max_ms)) + "</td>" +
        "<td>" + esc(ms(t.avg_ms)) + "</td>" +
        "<td>" + esc(t.loss_percent != null ? Number(t.loss_percent).toFixed(1) + "%" : "—") + "</td>" +
        '<td class="st ' + esc(st) + '">' + esc(stLabel) + streak + "</td>" +
        "<td>" + esc(methodLabel(t.detail)) + esc(soft) + "</td>" +
        "<td title=\"" + esc(t.last_check || "") + "\">" + esc(compactTime(t.last_check)) + "</td>" +
        "</tr>";
    });
    body.innerHTML = rows.join("") || '<tr><td colspan="12">无目标</td></tr>';

    if (groupsEl) {
      var buckets = { dns: [], web: [] };
      targets.forEach(function (t) {
        var g = t.group === "dns" ? "dns" : "web";
        buckets[g].push(t);
      });
      var html = ["dns", "web"].filter(function (g) {
        return buckets[g].length > 0;
      }).map(function (g) {
        var title = g === "dns" ? "DNS" : "网站";
        var folded = pingFolded[g] ? " collapsed" : "";
        var cards = buckets[g].map(function (t) {
          var st = t.status || (t.online ? "ok" : "offline");
          var cls = "ping-card " + (t.online ? (st === "warn" || st === "danger" ? st : "ok") : "offline");
          var cur = t.current_ms != null ? Number(t.current_ms).toFixed(1) + " ms" : (t.online ? "—" : "不可达");
          var soft = t.soft_alert ? '<span class="soft">弱网</span>' : "";
          var streak = (t.fail_streak > 1) ? '<span class="streak">连败' + t.fail_streak + "</span>" : "";
          return '<div class="' + cls + '"><div class="name">' + esc(t.name) + soft + streak + '</div>' +
            '<div class="host">' + esc(t.host) + '</div>' +
            '<div class="ms">' + esc(cur) + '</div>' +
            (perfMode ? "" : sparklineSvg(t.history_ms)) +
            '<div class="meta">丢包 ' + esc(t.loss_percent != null ? Number(t.loss_percent).toFixed(0) + "%" : "—") +
            " · " + esc(methodLabel(t.detail)) +
            " · " + esc(relativeAge(t._age)) + "</div></div>";
        }).join("");
        return '<div class="ping-group' + folded + '" data-group="' + g + '">' +
          '<div class="ping-group-header" data-group="' + g + '">' +
          '<span class="fold-icon">▾</span>' +
          '<h3>' + title + '</h3>' +
          '</div><div class="ping-cards">' + cards + "</div></div>";
      }).join("");
      groupsEl.innerHTML = html;
    }
  }

  function filterEvents(list) {
    list = list || [];
    if (eventFilter === "all") return list;
    if (eventFilter === "error") {
      return list.filter(function (e) { return e.level === "ERROR"; });
    }
    // warn+：WARN / ERROR / OK（恢复）
    return list.filter(function (e) {
      return e.level === "WARN" || e.level === "ERROR" || e.level === "OK";
    });
  }

  function renderEvents(events) {
    var term = $("term");
    lastEventsRaw = events || [];
    var list = filterEvents(lastEventsRaw);
    var sig = eventFilter + "|" + list.map(function (e) { return e.ts + e.level + e.message; }).join("|");
    if (sig === lastEventsSig && term.childNodes.length) return;
    lastEventsSig = sig;
    var nearBottom = (term.scrollHeight - term.scrollTop - term.clientHeight) < 48;
    var frag = document.createDocumentFragment();
    var reversed = list.slice().reverse();
    if (!reversed.length) {
      var emptyDiv = document.createElement("div");
      emptyDiv.className = "term-line";
      emptyDiv.innerHTML = '<span class="ts">#</span><span class="msg"> 当前过滤下无事件</span>';
      frag.appendChild(emptyDiv);
    }
    for (var i = 0; i < reversed.length; i++) {
      var e = reversed[i];
      var div = document.createElement("div");
      div.className = "term-line";
      var icon = e.level === "ERROR" ? "✗" : e.level === "WARN" ? "⚠" : e.level === "OK" ? "✓" : "●";
      div.innerHTML = '<span class="ts">[' + esc(e.ts) + ']</span>' +
        '<span class="lv ' + esc(e.level) + '">' + icon + ' ' + esc(e.level) + '</span>' +
        '<span class="msg">' + esc(e.message) + '</span>';
      frag.appendChild(div);
    }
    var cursorDiv = document.createElement("div");
    cursorDiv.className = "term-line";
    cursorDiv.innerHTML = '<span class="ts">$</span> <span class="cursor"></span>';
    frag.appendChild(cursorDiv);
    term.innerHTML = "";
    term.appendChild(frag);
    if (nearBottom || term.scrollTop === 0) {
      term.scrollTop = term.scrollHeight;
    }
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
    tickAges();
  }

  function applyRuntimeUi(data) {
    var runtime = data.runtime || (data.system && data.system.runtime) || "";
    var chip = $("runtimeChip");
    var hint = $("runtimeHint");
    if (chip) {
      if (runtime === "container") {
        chip.style.display = "inline";
        chip.className = "mode-chip";
        chip.textContent = "容器视角";
        chip.title = "Docker/容器内指标，不等于完整宿主机";
      } else if (runtime === "host") {
        chip.style.display = "inline";
        chip.className = "mode-chip host";
        chip.textContent = "宿主机";
        chip.title = "直接运行在宿主机命名空间";
      } else {
        chip.style.display = "none";
      }
    }
    if (hint) {
      if (runtime === "container") {
        hint.textContent = "容器模式：主机名多为容器 ID；指标为容器视角";
      } else if (runtime === "host") {
        hint.textContent = "宿主机模式 · 日期/时间为浏览器本地时区";
      } else {
        hint.textContent = "日期/时间为浏览器本地时区 · 更新于为服务端时间";
      }
    }
  }

  function applyPayload(data, reqMs) {
    lastOk = data;
    serviceUptimeBase = data.uptime_seconds || 0;
    serviceUptimeAt = Date.now();
    metricsAgeBase = data.metrics_age_seconds != null ? Number(data.metrics_age_seconds) : null;
    pingAgeBase = data.ping_age_seconds != null ? Number(data.ping_age_seconds) : null;
    agesAt = Date.now();
    $("fVer").textContent = data.version || "—";
    if ($("hdrVer")) $("hdrVer").textContent = "v" + (data.version || "—");
    var disp = (data.system && (data.system.hostname_display || data.system.hostname)) || "";
    if (disp) document.title = "VPS Probe · " + disp;
    applyRuntimeUi(data);
    $("fCollect").textContent = data.collect_ms != null ? Number(data.collect_ms).toFixed(1) : "—";
    $("fReq").textContent = reqMs != null ? reqMs.toFixed(1) : "—";
    tickAges();
    if ($("fTz")) {
      $("fTz").textContent = data.timezone || (data.system && data.system.timezone) || "—";
    }
    // 压缩时间戳展示，避免底栏单行过长被裁切
    var st = data.server_time || "—";
    if (typeof st === "string" && st.length > 19) {
      st = st.replace("T", " ").replace(/\+\d{2}:\d{2}$/, "").replace(/Z$/, "");
    }
    $("fUpdated").textContent = st;
    updateStaleBanner(data, true);
    renderSystem(data.system || {}, data.system_history || null);
    // 卡片相对时间：用 ping_age 作统一参考
    if (data.ping && data.ping.targets) {
      var pa = data.ping_age_seconds != null ? Number(data.ping_age_seconds) : null;
      data.ping.targets.forEach(function (t) { t._age = pa; });
    }
    renderPing(data.ping);
    renderEvents(data.events);
  }

  function tickAges() {
    if (!agesAt) return;
    var elapsed = (Date.now() - agesAt) / 1000;
    if (metricsAgeBase != null && $("fAge")) {
      $("fAge").textContent = (metricsAgeBase + elapsed).toFixed(1);
    }
    if (pingAgeBase != null && $("fPingAge")) {
      $("fPingAge").textContent = (pingAgeBase + elapsed).toFixed(1);
    }
  }

  var pollInFlight = false;
  var pollFailCount = 0;
  function poll() {
    if (pollInFlight) return;
    pollInFlight = true;
    var t0 = performance.now();
    var ctrl = new AbortController();
    var tid = setTimeout(function () { ctrl.abort(); }, 8000);
    fetch("/api/status", { cache: "no-store", signal: ctrl.signal })
      .then(function (r) {
        clearTimeout(tid);
        if (!r.ok) throw new Error("http " + r.status);
        return r.json();
      })
      .then(function (data) {
        var reqMs = performance.now() - t0;
        if (!data || data.ok === false) throw new Error("bad payload");
        pollFailCount = 0;
        setOnline(true);
        applyPayload(data, reqMs);
      })
      .catch(function () {
        clearTimeout(tid);
        pollFailCount++;
        setOnline(false);
        updateStaleBanner(lastOk, false);
        if (lastOk) {
          $("fReq").textContent = (performance.now() - t0).toFixed(1);
        }
        // 连续失败退避：临时拉长轮询
        if (pollFailCount >= 2) {
          var backoff = Math.min(30000, pollMs * Math.min(pollFailCount, 4));
          if (timer) clearInterval(timer);
          timer = setInterval(poll, backoff);
        }
      })
      .then(function () {
        pollInFlight = false;
        if (pollFailCount === 0) resetPollTimer();
      });
  }

  /* ---- Matrix rain（性能优先：低 DPR、限数量、低帧率、少随机） ---- */
  var canvas = $("rain");
  var ctx = canvas ? canvas.getContext("2d", { alpha: false }) : null;
  var drops = [];
  var cols = 0;
  var fontSize = 16;
  var chars = "01ﾊﾞｼﾞﾄﾞﾄﾞﾉﾒﾘﾔﾕﾗﾜﾝ0101ABCDEF";
  var rainActive = true;
  var lastFrame = 0;
  var frameGap = 66; /* ~15fps */
  var rainW = 0;
  var rainH = 0;

  function pickDropX() {
    return Math.floor(Math.random() * Math.max(1, cols)) * fontSize;
  }

  function resizeRain() {
    if (reducedMotion || !canvas || !ctx) return;
    var dpr = 1;
    rainW = window.innerWidth || 1;
    rainH = window.innerHeight || 1;
    canvas.width = rainW;
    canvas.height = rainH;
    canvas.style.width = rainW + "px";
    canvas.style.height = rainH + "px";
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    var mobile = rainW < 768;
    fontSize = mobile ? 18 : 16;
    frameGap = mobile ? 100 : 66;
    cols = Math.floor(rainW / fontSize) || 1;
    var n = mobile ? 22 : 40;
    n = Math.min(n, Math.max(12, Math.floor(cols * 0.28)));
    drops = [];
    for (var i = 0; i < n; i++) {
      drops.push({
        x: pickDropX(),
        y: Math.random() * -80,
        speed: 0.9 + Math.random() * 1.2,
        ch: chars.charAt(i % chars.length),
        alpha: 0.45 + (i % 5) * 0.08
      });
    }
  }

  function stopRainLoop() {
    if (rainRaf) {
      cancelAnimationFrame(rainRaf);
      rainRaf = 0;
    }
  }

  function startRainLoop() {
    if (reducedMotion || !rainEnabled || !ctx || rainRaf) return;
    rainRaf = requestAnimationFrame(drawRain);
  }

  /* 预渲染字符到离屏 canvas，减少每帧 fillText 调用；限制缓存大小 */
  var charCache = {};
  var charCacheKeys = [];
  var CHAR_CACHE_MAX = 40;
  function getCharCanvas(ch) {
    var key = ch + "_" + fontSize;
    if (charCache[key]) return charCache[key];
    var c = document.createElement("canvas");
    c.width = fontSize + 2;
    c.height = fontSize + 2;
    var cx = c.getContext("2d");
    cx.fillStyle = "#00ff6a";
    cx.font = fontSize + "px monospace";
    cx.textBaseline = "top";
    cx.fillText(ch, 1, 1);
    charCache[key] = c;
    charCacheKeys.push(key);
    if (charCacheKeys.length > CHAR_CACHE_MAX) {
      delete charCache[charCacheKeys.shift()];
    }
    return c;
  }

  function drawRain(ts) {
    rainRaf = 0;
    if (reducedMotion || !ctx || !rainEnabled) return;
    if (!rainActive) return; /* 页不可见时彻底停环，不空转 rAF */
    if (ts - lastFrame < frameGap) {
      rainRaf = requestAnimationFrame(drawRain);
      return;
    }
    lastFrame = ts;
    var w = rainW;
    var h = rainH;

    // 残影一笔带过
    ctx.globalAlpha = 1;
    ctx.fillStyle = "rgba(2, 6, 4, 0.18)";
    ctx.fillRect(0, 0, w, h);

    var i, d, yy, cc;
    for (i = 0; i < drops.length; i++) {
      d = drops[i];
      ctx.globalAlpha = d.alpha;
      cc = getCharCanvas(d.ch);
      ctx.drawImage(cc, d.x, d.y * fontSize);
      d.y += d.speed;
      yy = d.y * fontSize;
      if (yy > h) {
        d.y = Math.random() * -12;
        d.x = pickDropX();
        // 偶发换字符，避免每帧 random
        if ((i + (ts | 0)) % 7 === 0) {
          d.ch = chars.charAt((i + (ts | 0)) % chars.length);
        }
      }
    }
    ctx.globalAlpha = 1;
    rainRaf = requestAnimationFrame(drawRain);
  }

  function scheduleResizeRain() {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      resizeTimer = 0;
      resizeRain();
    }, 180);
  }

  function resetPollTimer() {
    if (timer) clearInterval(timer);
    var ms = document.visibilityState === "visible" ? pollMs : pollMsHidden;
    timer = setInterval(poll, ms);
  }

  document.addEventListener("visibilitychange", function () {
    rainActive = document.visibilityState === "visible";
    if (rainActive) {
      startRainLoop();
      poll();
    } else {
      stopRainLoop();
    }
    resetPollTimer();
  });
  window.addEventListener("resize", scheduleResizeRain, { passive: true });

  // 工具栏：本地偏好，无配置文件
  var refreshBtn = $("refreshBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", function () {
      refreshBtn.classList.add("busy");
      poll();
      setTimeout(function () { refreshBtn.classList.remove("busy"); }, 400);
    });
  }
  var rainToggle = $("rainToggle");
  if (rainToggle) {
    rainToggle.checked = rainEnabled && !reducedMotion && !perfMode;
    if (reducedMotion) {
      rainToggle.disabled = true;
      rainToggle.parentElement && (rainToggle.parentElement.title = "系统已开启「减少动态效果」");
    }
    rainToggle.addEventListener("change", function () {
      if (perfMode) {
        rainToggle.checked = false;
        return;
      }
      setRainEnabled(rainToggle.checked);
    });
  }
  var perfToggle = $("perfToggle");
  if (perfToggle) {
    perfToggle.checked = perfMode;
    perfToggle.addEventListener("change", function () {
      setPerfMode(perfToggle.checked);
    });
  }
  // 应用初始性能/动画状态
  document.body.classList.toggle("perf-mode", perfMode);
  if (perfMode || reducedMotion || !rainEnabled) {
    setRainEnabled(false, true);
  }
  var eventFilterEl = $("eventFilter");
  if (eventFilterEl) {
    eventFilterEl.value = eventFilter;
    eventFilterEl.addEventListener("change", function () {
      eventFilter = eventFilterEl.value || "warn";
      try { localStorage.setItem(EVENT_FILTER_KEY, eventFilter); } catch (e) {}
      lastEventsSig = "";
      renderEvents(lastEventsRaw);
    });
  }
  /* 探测分组筛选按钮 */
  var pingFilterBar = $("pingFilterBar");
  if (pingFilterBar) {
    var filterBtns = pingFilterBar.querySelectorAll(".ping-filter-btn");
    filterBtns.forEach(function (btn) {
      if (btn.getAttribute("data-filter") === pingGroupFilter) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
      btn.addEventListener("click", function () {
        pingGroupFilter = btn.getAttribute("data-filter") || "all";
        try { localStorage.setItem(PING_FILTER_KEY, pingGroupFilter); } catch (e) {}
        filterBtns.forEach(function (b) { b.classList.toggle("active", b === btn); });
        lastPingSig = "";
        if (lastOk) renderPing(lastOk.ping);
      });
    });
  }
  /* 探测分组折叠事件委托 */
  var pingGroupsEl = $("pingGroups");
  if (pingGroupsEl) {
    pingGroupsEl.addEventListener("click", function (ev) {
      var hdr = ev.target.closest(".ping-group-header");
      if (!hdr) return;
      var grp = hdr.getAttribute("data-group");
      if (!grp) return;
      pingFolded[grp] = !pingFolded[grp];
      try { localStorage.setItem(PING_FOLD_KEY, JSON.stringify(pingFolded)); } catch (e) {}
      var groupEl = hdr.parentElement;
      if (groupEl) groupEl.classList.toggle("collapsed", !!pingFolded[grp]);
    });
  }
  var compactEl = $("compactFooter");
  if (compactEl) {
    compactEl.checked = compactFooter;
    compactEl.addEventListener("change", function () {
      setCompactFooter(compactEl.checked);
    });
  }
  var pollEl = $("pollInterval");
  if (pollEl) {
    pollEl.value = String(userPollMs);
    pollEl.addEventListener("change", function () {
      setUserPollMs(pollEl.value);
    });
  }
  var exportBtn = $("exportBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", exportStatusJson);
  }
  var helpBtn = $("helpBtn");
  if (helpBtn) {
    helpBtn.addEventListener("click", toggleHelp);
  }
  // 快捷键：R 刷新 / A 动画 / P 性能 / C 紧凑 / E 导出 / ? 帮助
  document.addEventListener("keydown", function (ev) {
    if (ev.defaultPrevented || ev.altKey || ev.ctrlKey || ev.metaKey) return;
    var tag = (ev.target && ev.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    if (ev.key === "r" || ev.key === "R") {
      poll();
    } else if (ev.key === "a" || ev.key === "A") {
      if (!reducedMotion && !perfMode) setRainEnabled(!rainEnabled);
    } else if (ev.key === "p" || ev.key === "P") {
      setPerfMode(!perfMode);
    } else if (ev.key === "c" || ev.key === "C") {
      setCompactFooter(!compactFooter);
    } else if (ev.key === "e" || ev.key === "E") {
      exportStatusJson();
    } else if (ev.key === "?" || ev.key === "/") {
      toggleHelp();
    } else if (ev.key === "Escape") {
      var hp = $("helpPop");
      if (hp) hp.classList.remove("show");
    }
  });

  // 电池电量低时建议性能模式（不强制覆盖用户已选 0）
  try {
    if (navigator.getBattery && localStorage.getItem(PERF_KEY) === null) {
      navigator.getBattery().then(function (b) {
        if (b && b.level < 0.2 && !b.charging && !perfMode) {
          setPerfMode(true);
        }
      }).catch(function () {});
    }
  } catch (e) {}

  if (!reducedMotion && rainEnabled && !perfMode) {
    resizeRain();
    startRainLoop();
  } else if (canvas) {
    if (reducedMotion || perfMode) canvas.style.display = "none";
    else canvas.style.opacity = "0";
  }
  tickClock();
  clockTimer = setInterval(tickClock, 1000);
  poll();
  resetPollTimer();
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
class _ReuseThreadingHTTPServer(ThreadingHTTPServer):
    """支持地址复用，便于快速重启；daemon 线程不阻塞退出。"""

    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    start_workers()
    server = _ReuseThreadingHTTPServer((HOST, PORT), ProbeHandler)

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

    print(f"VPS Probe v{VERSION} pid={os.getpid()}")
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
