# VPS Probe

<p align="center">
  <strong>极简 · 轻量 · 开箱即用的单页 VPS 探针</strong><br/>
  一个 Python 文件，看清机器性能、外网延迟与运行事件
</p>

<p align="center">
  <a href="#快速开始"><img src="https://img.shields.io/badge/快速开始-一键启动-00ff88?style=for-the-badge" alt="快速开始" /></a>
  <a href="#docker-启动"><img src="https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" /></a>
  <a href="https://github.com/Silentely/vps-probe/blob/main/probe.py"><img src="https://img.shields.io/badge/单文件-probe.py-b6ffcb?style=for-the-badge" alt="单文件" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/依赖-仅%20psutil-0A0A0A?logo=python&logoColor=white" alt="psutil" />
  <img src="https://img.shields.io/badge/配置-零%20env%20/%20零%20config-00aa55" alt="零配置" />
  <img src="https://img.shields.io/badge/前端-无%20Node%20/%20无构建-111" alt="无前端构建" />
  <img src="https://img.shields.io/badge/默认端口-8080-00ff6a" alt="8080" />
  <img src="https://img.shields.io/github/license/Silentely/vps-probe?label=License" alt="License" />
</p>

---

## 目录

- [项目简介](#项目简介)
- [特性](#特性)
- [页面效果](#页面效果)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [访问地址](#访问地址)
- [接口说明](#接口说明)
- [生产部署](#生产部署)
- [Docker 与宿主机差异](#docker-与宿主机差异)
- [安全说明](#安全说明)
- [项目结构](#项目结构)
- [常见问题](#常见问题)
- [卸载](#卸载)
- [许可证](#许可证)

---

## 项目简介

**VPS Probe** 是面向 Linux VPS 的只读监控单页：

| 原则 | 说明 |
|------|------|
| 部署极简 | 无需环境变量、配置文件、数据库、Node.js 或前端构建 |
| 资源占用低 | 标准库 HTTP + 唯一依赖 `psutil` |
| 数据真实 | 指标来自当前机器；Ping 目标写死在源码中 |
| 开箱即用 | `python3 probe.py` 或一条 Docker 命令即可 |

默认监听 **`0.0.0.0:8080`**。

---

## 特性

### 三大区域

| 区域 | 内容 |
|------|------|
| **系统性能** | 主机名、OS / 版本 / 内核 / 架构、CPU 型号与物理/逻辑核心、使用率与负载、内存 / Swap / 磁盘、启动与运行时间、用户数、进程数、网络累计流量与实时速率 |
| **外部 Ping** | 内置 Cloudflare / Google / Quad9 DNS 与网站等目标；并发检测延迟、丢包、在线状态与历史统计 |
| **事件终端** | 只读模拟终端：启动、采集、告警与恢复等事件（不可输入、不执行命令） |

### 其它能力

- 使用率 / 延迟阈值着色（约 **80% 警告** / **90% 危险**）
- **主题切换**：仪表盘布局 ↔ 竖向居中滚动布局（键值横向排列）
- 后端定时采集并缓存；多浏览器打开 **不会** 重复狂 Ping
- 异常时页面保留最后一次成功数据，并显示连接状态

---

## 页面效果

- **风格**：黑客帝国 / 赛博朋克 — 深色背景、荧光绿、半透明卡片与辉光
- **数字雨**：轻量 Canvas 动画；移动端降密度；页面不可见时暂停
- **布局**：桌面与手机自适应；底栏显示日期时间、请求耗时、采集耗时、数据龄、在线状态、服务运行时间、版本号

> 截图可自行补充到本仓库 `docs/` 或 Issues 中展示。

---

## 系统要求

| 项目 | 要求 |
|------|------|
| Python 直跑 | Python **3.9+**；推荐 Debian 12 / Ubuntu 22.04 等常见 Linux VPS（macOS 可本地预览） |
| 系统包 | 建议安装 `ping`（Debian/Ubuntu：`iputils-ping`）；未安装时延迟区显示不可用 |
| Docker | Docker 20+ |
| 权限 | **普通用户即可**，不强制 root |

---

## 快速开始

### Python 启动

```bash
git clone https://github.com/Silentely/vps-probe.git
cd vps-probe
pip3 install -r requirements.txt
python3 probe.py
```

一键：

```bash
pip3 install -r requirements.txt && python3 probe.py
```

浏览器打开：

```text
http://服务器IP:8080/
```

### Docker 启动

```bash
git clone https://github.com/Silentely/vps-probe.git
cd vps-probe
docker build -t vps-probe . && docker run -d \
  --name vps-probe \
  --restart unless-stopped \
  -p 8080:8080 \
  vps-probe
```

一键：

```bash
docker build -t vps-probe . && \
docker run -d --name vps-probe --restart unless-stopped -p 8080:8080 vps-probe
```

映射其它端口示例（如 `50000`）：

```bash
docker run -d --name vps-probe --restart unless-stopped -p 50000:8080 vps-probe
```

---

## 访问地址

| 项 | 默认值 |
|----|--------|
| 监听 | `0.0.0.0:8080` |
| 首页 | `http://<主机>:8080/` |
| 状态 API | `http://<主机>:8080/api/status` |
| 健康检查 | `http://<主机>:8080/health` |

### 健康检查

```bash
curl -sS http://127.0.0.1:8080/health
# → {"status":"ok"}

curl -sS http://127.0.0.1:8080/api/status | head -c 200
```

Docker：

```bash
docker inspect --format='{{.State.Health.Status}}' vps-probe
```

---

## 接口说明

| 路径 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 完整单页（HTML/CSS/JS 内嵌） |
| `/api/status` | GET | 系统指标、Ping 结果、事件、采集耗时等 JSON |
| `/health` | GET | 健康状态，仅返回必要字段 |

- 前端使用原生 `fetch` 轮询，**不整页刷新**
- 系统指标与 Ping 后台线程独立调度；HTTP 只读缓存
- 错误响应不暴露堆栈与内部路径

---

## 生产部署

### Nginx 反向代理

```nginx
server {
    listen 80;
    server_name probe.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

HTTPS 可用 certbot 等为该 `server` 配置证书。

### systemd 服务

项目目录示例：`/opt/vps-probe`  
单元文件：`/etc/systemd/system/vps-probe.service`

```ini
[Unit]
Description=VPS Probe single-page monitor
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=/opt/vps-probe
ExecStart=/usr/bin/python3 /opt/vps-probe/probe.py
Restart=on-failure
RestartSec=3

# 若 nobody 无系统包，可改用 venv：
# ExecStart=/opt/vps-probe/.venv/bin/python /opt/vps-probe/probe.py

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vps-probe
sudo systemctl status vps-probe
```

---

## Docker 与宿主机差异

| 部署方式 | 指标含义 |
|----------|----------|
| `python3 probe.py` | 当前系统命名空间的**宿主机**数据 |
| Docker 默认运行 | **容器视角**可见的 CPU / 内存 / 磁盘 / 网络，**不等于**完整宿主机面板 |

- 默认 **非 root** 容器、**非特权**、不挂载宿主机敏感目录  
- 需要宿主机级监控时，请用 Python 直跑，或自行评估特权 / 挂载风险（项目不默认开启）

---

## 安全说明

本项目是 **只读探针**：

- 无登录、无用户输入框、无真实终端  
- 无命令执行 / 文件读写 / 上传 / 系统修改接口  
- Ping 目标仅源码内置，客户端不可指定  
- 系统调用使用固定参数列表，避免命令注入  
- 错误响应不返回 Python 堆栈或服务器内部路径  

---

## 项目结构

```text
vps-probe/
├── probe.py            # 后端 + 内嵌 HTML / CSS / JS（主题切换在此）
├── requirements.txt    # 仅 psutil
├── Dockerfile          # 轻量镜像、非 root、HEALTHCHECK
├── LICENSE             # MIT
├── .dockerignore
├── .gitignore
└── README.md
```

---

## 常见问题

<details>
<summary><strong>页面空白或连不上？</strong></summary>

检查防火墙是否放行端口，以及进程是否在监听：

```bash
ss -lntp | grep 8080
```
</details>

<details>
<summary><strong>Ping 全部显示不可用？</strong></summary>

安装 ping：

```bash
sudo apt-get install -y iputils-ping
```

Docker 镜像已预装 `iputils-ping`。
</details>

<details>
<summary><strong>内存 / 磁盘和 htop、df 不完全一致？</strong></summary>

不同工具对 cache / buffer、挂载点统计口径可能不同。本项目使用 `psutil`，磁盘统计根路径 `/`。
</details>

<details>
<summary><strong>多开浏览器会不会重复狂 Ping？</strong></summary>

不会。Ping 由进程内后台任务定时执行并缓存，HTTP 请求只读缓存。
</details>

<details>
<summary><strong>主题如何切换？会丢吗？</strong></summary>

页面右上角可在 **仪表盘** 与 **竖向主题** 间切换。偏好保存在浏览器 `localStorage`，刷新后保留。
</details>

<details>
<summary><strong>依赖有哪些？</strong></summary>

仅 **`psutil`**（见 `requirements.txt`）。HTTP 服务与并发使用 Python 标准库。
</details>

---

## 卸载

### Python

```bash
# 若使用 systemd
sudo systemctl disable --now vps-probe
sudo rm -f /etc/systemd/system/vps-probe.service
sudo systemctl daemon-reload

rm -rf /path/to/vps-probe
pip3 uninstall -y psutil   # 可选，确认无其它项目使用时再卸
```

### Docker

```bash
docker rm -f vps-probe
docker rmi vps-probe
# 可选：docker builder prune
```

---

## 许可证

本项目采用 [MIT License](./LICENSE) 开源。

```text
Copyright (c) 2026 Silentely
```

可自由使用、修改、分发与商用；分发时请保留许可证与版权声明。

---

<p align="center">
  <sub>MIT · Made for simple VPS ops · No config · No database · One file</sub>
</p>
