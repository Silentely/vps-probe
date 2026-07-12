# VPS Probe

极简、轻量、开箱即用的单页 VPS 探针。用一个 Python 文件展示当前机器的系统性能、外部网络延迟和运行事件。

- **无需** 环境变量、配置文件、数据库、Node.js 或前端构建
- **一条命令** 即可启动（Python 或 Docker）
- 默认监听 `0.0.0.0:8080`

## 功能说明

| 区域 | 内容 |
|------|------|
| 系统性能 | 主机名、OS/内核/架构、CPU、负载、内存/Swap/磁盘、启动与运行时间、用户数、进程数、网络流量与速率 |
| 外部 Ping | Cloudflare / Google / Quad9 DNS 与网站等内置目标的并发延迟、丢包、在线状态 |
| 事件终端 | 只读模拟终端，展示启动、采集、告警与恢复等事件（不可输入、不执行命令） |

使用率与延迟超过阈值时以进度条颜色与事件告警提示（约 80% 警告 / 90% 危险）。

## 页面效果

- 黑客帝国 / 赛博朋克风格：深色背景、荧光绿文字、半透明卡片与辉光
- 轻量 Canvas 数字雨（移动端降密度，页面不可见时暂停）
- 桌面与手机自适应布局
- 底部状态栏：日期时间、请求耗时、后端采集耗时、数据龄、在线状态、服务运行时间、版本号

## 系统要求

- **Python 直接运行**：Python 3.9+，Linux 推荐 Debian 12 / Ubuntu 22.04 及常见 VPS；macOS 也可用于本地预览
- **系统包**：建议安装 `ping`（Debian/Ubuntu：`iputils-ping`）；未安装时页面会显示延迟检测不可用
- **Docker**：Docker 20+ 即可
- **权限**：普通用户即可，不强制 root

## Python 启动

```bash
cd vps-probe
pip3 install -r requirements.txt
python3 probe.py
```

浏览器访问：

```text
http://服务器IP:8080/
```

## Docker 启动

```bash
cd vps-probe
docker build -t vps-probe . && docker run -d \
  --name vps-probe \
  --restart unless-stopped \
  -p 8080:8080 \
  vps-probe
```

## 一键运行命令

**Python：**

```bash
pip3 install -r requirements.txt && python3 probe.py
```

**Docker：**

```bash
docker build -t vps-probe . && docker run -d --name vps-probe --restart unless-stopped -p 8080:8080 vps-probe
```

## 默认访问地址与端口

| 项 | 值 |
|----|-----|
| 监听地址 | `0.0.0.0` |
| 端口 | `8080` |
| 首页 | `http://<主机>:8080/` |
| 状态 API | `http://<主机>:8080/api/status` |
| 健康检查 | `http://<主机>:8080/health` |

## Nginx 反向代理示例

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

HTTPS 请自行用 certbot 等为该 `server` 配置证书。

## systemd 服务示例

将项目放在例如 `/opt/vps-probe`，创建 `/etc/systemd/system/vps-probe.service`：

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

# 可选：若 nobody 无 pip 用户包，请用 venv 的 python 路径
# ExecStart=/opt/vps-probe/.venv/bin/python /opt/vps-probe/probe.py

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vps-probe
sudo systemctl status vps-probe
```

## 健康检查方法

```bash
curl -sS http://127.0.0.1:8080/health
# 期望: {"status":"ok"}

curl -sS http://127.0.0.1:8080/api/status | head -c 200
```

Docker 镜像已内置 `HEALTHCHECK`，也可用：

```bash
docker inspect --format='{{.State.Health.Status}}' vps-probe
```

## Docker 与宿主机指标差异说明

| 部署方式 | 指标含义 |
|----------|----------|
| `python3 probe.py` 直接运行 | 读取**宿主机**（当前系统命名空间）真实数据 |
| Docker 默认运行 | 读取**容器视角**可见的 CPU/内存/磁盘/网络等，**不等于**完整宿主机面板 |

本项目**默认不使用**特权模式、不挂载宿主机敏感目录、不以 root 运行容器。若需要宿主机级监控，请使用 Python 直接部署，或自行评估特权/挂载风险（项目不默认启用）。

## 安全说明（只读探针）

- 无登录、无用户输入框、无真实终端
- 无命令执行 / 文件读写 / 上传 / 系统修改接口
- Ping 目标固定写在源码中，客户端不可指定
- 系统调用使用固定参数列表，避免命令注入
- 错误响应不返回 Python 堆栈或内部路径

## 常见问题

**Q: 页面打开空白或连不上？**  
检查防火墙是否放行 8080，以及进程是否在监听：`ss -lntp | grep 8080`。

**Q: Ping 全部显示不可用？**  
安装 ping：`sudo apt-get install -y iputils-ping`（Debian/Ubuntu）。Docker 镜像已预装。

**Q: 内存或磁盘数值和 `htop`/`df` 不完全一致？**  
不同工具对 cache/buffer、挂载点的统计口径可能不同；本项目使用 `psutil` 与根路径 `/` 磁盘统计。

**Q: 多浏览器同时打开会不会重复狂 ping？**  
不会。Ping 由进程内后台任务定时执行并缓存，HTTP 请求只读缓存。

**Q: 依赖只有哪些？**  
仅 `psutil`（见 `requirements.txt`）。标准库提供 HTTP 服务与并发。

## 完整卸载方法

**Python 部署：**

```bash
# 停止进程（若用 systemd）
sudo systemctl disable --now vps-probe
sudo rm -f /etc/systemd/system/vps-probe.service
sudo systemctl daemon-reload

# 删除项目目录
rm -rf /path/to/vps-probe

# 可选：卸载依赖（若无其他项目使用）
pip3 uninstall -y psutil
```

**Docker 部署：**

```bash
docker rm -f vps-probe
docker rmi vps-probe
# 如需清理构建缓存可再执行: docker builder prune
```

## 项目结构

```text
vps-probe/
├── probe.py           # 后端 + 内嵌 HTML/CSS/JS
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── .gitignore
└── README.md
```

## 许可证

按需自用；可自由修改与分发。
