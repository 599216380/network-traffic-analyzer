# Network Traffic Analyzer（网络流量分析平台）

一个基于 **FastAPI + 异步SQLAlchemy + SQLite** 的离线网络流量分析平台，用于导入/解析 PCAP 文件，聚合会话（Flow），并结合内置检测规则生成安全告警，同时提供前端仪表盘与报表导出。

> 适合：流量回溯分析、检测规则原型验证、教学/课程项目。

## 目录

- [技术栈](#技术栈)
- [功能一览](#功能一览)
- [页面与交互](#页面与交互)
- [快速开始](#快速开始)
- [默认账号](#默认账号)
- [API 概览](#api-概览)
- [配置项](#配置项)
- [项目结构](#项目结构)
- [安全说明](#安全说明)
- [常见问题](#常见问题)

## 技术栈

### 后端

- **Python**：3.10+
- **Web 框架**：FastAPI + Uvicorn
- **ORM**：SQLAlchemy 2.x（异步） + aiosqlite（SQLite 驱动）
- **数据校验**：Pydantic v2 + pydantic-settings
- **文件上传**：python-multipart
- **模板/导出**：Jinja2（HTML 报告）、openpyxl（Excel 导出依赖）

### 解析与数据处理

- **PCAP 解析**：dpkt + scapy
- **数据分析**：pandas + numpy

### 前端

- **UI 框架**：Bootstrap 5
- **图标**：Bootstrap Icons
- **交互**：Vanilla JavaScript



## 功能一览

### 1) 登录与会话

- 访问根路径 `/` 默认进入登录页（静态页面）
- 登录后将 token 存储在 `localStorage`（记住我）或 `sessionStorage`
- 前端在进入主页面时会调用 `GET /api/v1/auth/verify` 验证 token
- 侧边栏底部展示当前用户，并支持退出登录

> 当前鉴权为“前端保护 + 后端 token 校验接口”的轻量实现。

### 2) 数据集（Dataset）管理

- **导入 PCAP**：拖拽/选择文件上传，支持 `.pcap/.pcapng/.cap`
- **任务状态展示**：pending/running/done/failed 与进度
- **数据集列表**：分页/筛选（后端支持 `status` 过滤）
- **数据集详情弹窗**：展示统计、协议分布、Top talkers/ports 等
- **删除数据集**：同时删除磁盘文件与数据库记录

### 3) 流量聚合与检索（Flow）

- 会话聚合：按五元组/时间窗口聚合为双向会话
- 支持筛选：数据集、源/目的 IP、目的端口、协议等
- 前端表格展示：时间、IP:Port、协议、字节/包、状态、应用层协议（如 HTTP/DNS/TLS/SSH 等）

### 4) DNS 事件分析

- DNS 查询列表
- 支持筛选：数据集、域名、类型、响应码等
- 展示关键指标：子域层级、域名长度、熵值等（用于隧道检测的特征）

### 5) HTTP / TLS 事件（API 层）

- 提供 HTTP / TLS 相关事件的 API（用于流量与证书/JA3/SNI 分析）
- 前端目前以“核心页面”为主，HTTP/TLS 可通过 API 与报表查看

### 6) 安全告警（Alert）管理

- 告警列表
- 过滤条件：严重级别、类型
- 操作：关闭告警、标记误报
- 仪表盘统计：按类型/严重程度聚合

### 7) 检测规则（Detection Rules）

- 内置规则（示例）：
     - 端口扫描（Port Scan）
     - 暴力破解（Brute Force）
     - DNS 隧道（DNS Tunnel）
     - C2 Beacon（周期性回连）
- 规则开关：启用/禁用
- **新增规则（UI + API）**：可在页面新增一条“自定义规则”（当前为占位规则：注册到引擎，但 detect 返回空）

### 8) 仪表盘与可视化

- 总览统计：数据集数、总会话数、总流量、告警数
- 协议分布、告警分布
- Top 源 IP / Top 域名
- 支持选择数据集查看（过滤仪表盘数据）

### 9) 报表与导出

- HTML 分析报告导出：按数据集生成
- CSV/JSON 导出：flows/dns/alerts 等（详见 API）



## 页面与交互

- 登录页：`/static/login.html`
- 主界面：`/static/index.html`
- 页面导航：仪表盘 / 数据集 / 流量查询 / DNS 事件 / 安全告警 / 检测规则
- 交互亮点：
     - 仪表盘选择数据集过滤
     - 数据集详情弹窗（统计与 Top 列表）
     - 规则页面“新增规则”弹窗

## 快速开始

### 1) 安装依赖

```bash
pip install -r requirements.txt
```

### 2) 可选：配置 `.env`

项目使用 pydantic-settings 读取环境变量（默认会读根目录 `.env`）：

```env
DEBUG=true
DATABASE_URL=sqlite+aiosqlite:data/traffic_analyzer.db
MAX_UPLOAD_SIZE=524288000
FLOW_IDLE_TIMEOUT=60
FLOW_ACTIVE_TIMEOUT=3600
```

> 如果不配置，默认数据库为 `data/traffic_analyzer.db`。

### 3) 启动服务

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

或直接：

```bash
python main.py
```

### 4) 访问

- 登录入口：`http://localhost:8000/`
- 交互页面：`http://localhost:8000/static/index.html`
- API 文档：`http://localhost:8000/docs`

## 默认账号

- 用户名：`admin`
- 密码：`admin`

## API 概览

### Auth

- `POST /api/v1/auth/login`：登录，返回 token
- `GET /api/v1/auth/verify`：验证 token
- `POST /api/v1/auth/logout`：登出
- `GET /api/v1/auth/me`：当前用户信息

### Datasets

- `POST /api/v1/datasets/import`：上传导入 PCAP（multipart/form-data）
- `GET /api/v1/datasets`：数据集列表（`skip/limit/status`）
- `GET /api/v1/datasets/{dataset_id}`：数据集详情
- `GET /api/v1/datasets/{dataset_id}/stats`：数据集统计
- `DELETE /api/v1/datasets/{dataset_id}`：删除数据集

### Flows / DNS / HTTP / TLS

- `GET /api/v1/flows`：Flow 检索（多条件过滤）
- `GET /api/v1/dns`：DNS 事件检索
- `GET /api/v1/http`：HTTP 事件检索
- `GET /api/v1/tls`：TLS 事件检索

### Alerts

- `GET /api/v1/alerts`：告警列表（按严重程度/类型过滤）
- `POST /api/v1/alerts/{alert_id}/close`：关闭告警
- `POST /api/v1/alerts/{alert_id}/false-positive`：标记误报

### Dashboard / Export

- `GET /api/v1/dashboard`：仪表盘统计（可选 `dataset_id`）
- `GET /api/v1/export/report/{dataset_id}/html`：导出 HTML 报告
- `GET /api/v1/export/flows/{dataset_id}/csv`：导出 flows CSV
- `GET /api/v1/export/flows/{dataset_id}/json`：导出 flows JSON
- `GET /api/v1/export/dns/{dataset_id}/csv`：导出 DNS CSV
- `GET /api/v1/export/alerts/{dataset_id}/csv`：导出 alerts CSV

### Rules

- `GET /api/v1/rules`：规则列表
- `POST /api/v1/rules`：新增规则（占位规则，不执行检测逻辑）
- `POST /api/v1/rules/{rule_id}/enable`：启用规则
- `POST /api/v1/rules/{rule_id}/disable`：禁用规则
- `PATCH /api/v1/rules/{rule_id}`：更新规则配置

## 配置项

配置位于 `config/settings.py`（可通过环境变量覆盖）：

- 上传与路径
  - `MAX_UPLOAD_SIZE`
  - `ALLOWED_EXTENSIONS`
  - `DATASETS_DIR/UPLOADS_DIR/EXPORTS_DIR`
- 聚合
  - `FLOW_IDLE_TIMEOUT`
  - `FLOW_ACTIVE_TIMEOUT`
- 检测阈值（示例）
  - 端口扫描：`PORTSCAN_TIME_WINDOW`、`PORTSCAN_MIN_PORTS`、`PORTSCAN_MIN_HOSTS`
  - 暴力破解：`BRUTEFORCE_TIME_WINDOW`、`BRUTEFORCE_MIN_ATTEMPTS`、`BRUTEFORCE_PORTS`
  - DNS 隧道：`DNS_TUNNEL_MIN_QNAME_LENGTH`、`DNS_TUNNEL_MIN_ENTROPY`、`DNS_TUNNEL_MIN_SUBDOMAIN_LEVELS`、`DNS_TUNNEL_NXDOMAIN_RATIO`
  - C2 Beacon：`BEACON_TIME_WINDOW`、`BEACON_MIN_CONNECTIONS`、`BEACON_INTERVAL_VARIANCE_THRESHOLD`、`BEACON_MIN_REGULARITY_SCORE`

## 项目结构

```text
network-traffic-analyzer/
├── main.py                 # ✅ 实际启动入口（挂载路由、静态资源、演示数据）
├── api/
│   ├── auth.py             # 登录/登出/验证
│   ├── datasets.py         # 数据集导入/统计/删除
│   ├── flows.py            # Flow/DNS/HTTP/TLS 查询
│   ├── alerts.py           # 告警管理
│   ├── dashboard.py        # 仪表盘与导出路由
│   └── rules.py            # 规则管理 + 新增规则
├── config/
│   └── settings.py         # 配置（.env / 环境变量）
├── detection/
│   ├── base.py             # 检测规则基类
│   ├── port_scan.py
│   ├── brute_force.py
│   ├── dns_tunnel.py
│   └── c2_beacon.py
├── models/
│   ├── database.py         # ORM 模型（Dataset/Flow/DnsEvent/...）
│   ├── schemas.py          # Pydantic 响应模型
│   └── db_session.py       # 异步 Session / init_db
├── parsers/
│   ├── pcap_parser.py
│   └── flow_aggregator.py
├── services/
│   ├── import_service.py   # 导入/解析任务
│   ├── export_service.py   # 导出（CSV/JSON/HTML报告）
│   └── demo_data.py        # 启动时演示数据注入
└── static/
     ├── login.html         # 登录页
     ├── index.html         # 主界面
     └── app.js             # 前端逻辑
```

