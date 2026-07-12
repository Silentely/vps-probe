# VPS Probe · Agent 协作说明

本文档供在本仓库继续开发、打磨、测试与推送的 AI / 人类 agent 使用。  
实现以代码为准；若与本文冲突，以当前 `probe.py`、`README.md` 与用户最新指示为准。

## 1. 项目定位（不可偏离）

极简、轻量、开箱即用的**单页 VPS 探针**。

强制约束：

- 后端 **Python**；优先 **单文件 `probe.py`**（后端 + 内嵌 HTML/CSS/JS）
- **零环境变量、零配置文件、零数据库、零 Node/前端构建**
- 依赖尽量只有 `psutil`（见 `requirements.txt`）
- 默认监听 `0.0.0.0:8080`
- 系统数据从当前机器真实读取；Ping 目标**仅源码内置**，客户端不可指定
- 只读探针：无登录、无命令执行、无文件读写/上传、无真实终端
- Docker：非 root、非特权、含最小 `iputils-ping`、HEALTHCHECK
- 文档与必要注释：**简体中文**
- 提交/PR：**不要**出现 Claude / AI 工具署名类字样

## 2. 仓库结构（保持精简）

```text
vps-probe/
├── probe.py
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── .gitignore
├── LICENSE          # MIT
├── README.md
└── AGENTS.md        # 本文件：agent 续作约定
```

- **不要**把本地运维脚本提交进仓库：`bohrium-sync.sh`、`_remote_*.sh`、`_footer_inspect*.js`、`images/` 等应在 `.gitignore` / `.dockerignore` 中排除
- 除非确有必要，不要加配置文件、Compose、前端工程目录、管理后台

## 3. 当前能力基线（改前先读代码）

实现以 `probe.py` 为准，典型能力包括：

- 三大区：系统性能 / 外部探测 / 事件终端
- 主题：横向仪表盘 ↔ 竖向居中（键值横向排列）
- 容器/宿主机识别、主机名美化（避免裸容器 ID 误解）
- ICMP + TCP/443 回退；DNS/网站分组；软目标降噪
- 性能模式、背景动画开关、事件过滤（localStorage）
- 探测汇总 + `history_ms` 延迟火花图
- 底栏：请求/采集/指标距今/探测距今/时区等（`status-bar`，禁止用 class `bar` 以免与进度条冲突）
- 首页 ETag；`/api/status` 与 `/health` 访问日志降噪

版本号在 `probe.py` 的 `VERSION`。功能发版时同步 bump。

## 4. 打磨 / 迭代工作方式

### 4.1 原则

1. **先检索后改动**：读 `probe.py`、`README.md`、`Dockerfile`，用证据说话，禁止假设
2. **小步可验证**：每次改动可编译、可运行、可测
3. **克制范围**：优先体验、性能、可观测、文档；不要破坏零配置
4. **安全边界不破**：不引入用户指定 Ping 目标、不把客户端参数拼进 shell、错误不回堆栈/路径

### 4.2 推荐迭代方向（按需挑选）

- 体验：文案、布局、移动端、容器提示、时区说明
- 性能：数字雨、轮询、DOM 重绘、CSS 动画/毛玻璃、日志量
- 探测：告警降噪、分组展示、历史趋势、失败提示
- 数据：网络口径、CPU 首采、根分区说明
- 文档：README FAQ、Docker 示例（`--hostname`、端口映射）
- **避免**：数据库历史、登录后台、可配置目标、Node 构建、默认特权 Docker

### 4.3 已知坑（必记）

1. **footer 禁止 `class="bar"`**：进度条用 `.meter-bar`；历史 `.bar{height:10px}` 会把底栏压成 10px 裁切
2. Docker 主机名常为容器 ID：展示要用 `hostname_display` / 运行模式徽章
3. 底栏「日期/时间」= 浏览器本地；「更新于/时区」= 服务端（容器常 UTC）
4. 数字雨过密/高 DPR 会卡：性能模式、低帧率、限雨滴、页不可见停 rAF
5. 本地测试脚本、截图证据默认不要提交仓库

## 5. 测试要求（必须可复现）

### 5.1 每次改动至少做

1. **语法**：`python3 -m py_compile probe.py`
2. **静态特征**（按改动点断言）：`VERSION`、关键 UI 文案、关键 API 字段
3. **接口**（服务起来后）：
   - `GET /health` → `status=ok`，含 `version`；宜含 `runtime`、`ping_available`
   - `GET /` → 200，HTML 完整
   - `GET /api/status` → `ok=true`，含 `system` / `ping.targets` / `events`
4. **回归清单**：
   - [ ] 系统数据非随机模拟
   - [ ] 界面不展示：系统版本、架构、物理/逻辑核心（若产品仍要求隐藏）
   - [ ] Ping 单目标失败不拖垮整接口
   - [ ] 事件列表有上限，不无限增长
   - [ ] 多客户端不会重复启动多套 Ping 后台任务
   - [ ] 底栏信息完整可见（居中、不被裁切）
   - [ ] 竖向主题键值**横向**排列；主题按钮文案「竖向主题 / 横向主题」
   - [ ] Docker 非特权、非 root 用户

### 5.2 远程验收（若环境有 Termark + Bohrium）

- 资产名通常为 **Bohrium**；验收端口常用 **50000**（映射 `50000:8080`）
- **流程**：上传最新 `probe.py`（及 Dockerfile 如有变）→ 重建镜像/重启容器 → 验 `/health` 与 `/api/status` 的 `version` 已更新
- **禁止**只改本地不部署却声称「已在 Bohrium 验证」
- 用户要求不在本地起网页端口时，优先用远程 Bohrium
- 可用 `termark` 上传/exec；Docker 长构建注意超时，宜 `nohup`/`setsid` 后台

### 5.3 可选 UI 验收（Browser Relay）

- 打开部署地址硬刷新
- 检查底栏元素是否 fullyVisible（避免被裁切）
- 切换主题 / 性能模式 / 关动画
- 截图仅作本地证据；默认不要提交 `images/`

### 5.4 失败处理

- 连续三次同路径失败：停手，换方案，写清根因
- 未通过测试：**不得**声称完成，**不得**把未验收改动当「已验收」推送

## 6. 推送 / Git 要求

### 6.1 分支与远程

- 主分支：**main**
- 远程：`https://github.com/Silentely/vps-probe.git`（或仓库已配置的 `origin`）
- 完成后：`git push origin main`（或按用户指定分支）

### 6.2 提交规范

- 有意义的中文或英文完整句 commit message
- 只提交相关文件；不提交密钥、`.env`、本地脚本、临时文件
- **禁止** `Co-Authored-By: Claude` / 任何 AI 工具署名
- 类型建议：`feat` / `fix` / `perf` / `docs` / `chore`

### 6.3 推送前检查

```bash
python3 -m py_compile probe.py
git status
git diff
git log -3 --oneline
# 功能发版时确认 VERSION 已 bump
git add <相关文件>
git commit -m "..."
git push origin main
```

### 6.4 版本号

- 功能/体验发版：递增 `probe.py` 中 `VERSION`（如 `1.4.2` → `1.4.3` / `1.5.0`）
- 纯文档/忽略规则：可不改 VERSION，但 commit 要写清

## 7. 交付输出格式（给用户）

完成后用简短结构回复：

1. **版本号**与主要改动列表  
2. **测试证据**：命令 + 关键结果（health/status 字段、Bohrium 是否已同步）  
3. **访问方式**：默认 `http://<IP>:8080/`；若 Bohrium 则写清端口  
4. **Git**：commit hash / 是否已 push  
5. 未做事项与风险（如有）

## 8. 单次任务默认流程

1. 读 `probe.py` / `README.md` / 最近 git log，确认基线 `VERSION`  
2. 明确本次打磨目标（小步，可测）  
3. 实现 → `py_compile` → 本地或 Bohrium 起服务验收  
4. 确认 `VERSION` 与远程 `/health.version` 一致（若做了远程部署）  
5. 更新 `README.md`（若用户可见行为变化）  
6. commit + push `main`  
7. 按第 7 节格式汇报  

## 9. 一句话总则

**零配置、单文件、真数据、可复现测试、Bohrium 与代码同步、干净 commit 推 main；先证据后结论。**
