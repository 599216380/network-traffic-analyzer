# 部署说明

## 生产环境部署

### 1. 使用 Docker 部署

创建 `Dockerfile`:

```dockerfile
FROM python:3.10-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建数据目录
RUN mkdir -p /app/data/pcap

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["python", "main.py"]
```

创建 `docker-compose.yml`:

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - DATABASE_URL=sqlite+aiosqlite:///./data/traffic.db
      - MAX_UPLOAD_SIZE=524288000
    restart: unless-stopped
```

启动服务:
```bash
docker-compose up -d
```

### 2. 使用 Nginx 反向代理

安装 Nginx:
```bash
sudo apt-get install nginx
```

配置文件 `/etc/nginx/sites-available/traffic-analyzer`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    client_max_body_size 500M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /static {
        alias /app/static;
        expires 30d;
    }
}
```

启用配置:
```bash
sudo ln -s /etc/nginx/sites-available/traffic-analyzer /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 3. 配置 HTTPS (Let's Encrypt)

安装 Certbot:
```bash
sudo apt-get install certbot python3-certbot-nginx
```

获取证书:
```bash
sudo certbot --nginx -d your-domain.com
```

自动续期:
```bash
sudo certbot renew --dry-run
```

### 4. 使用 Systemd 管理服务

创建服务文件 `/etc/systemd/system/traffic-analyzer.service`:

```ini
[Unit]
Description=Network Traffic Analyzer
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/app/network-traffic-analyzer
Environment="PATH=/app/network-traffic-analyzer/venv/bin"
ExecStart=/app/network-traffic-analyzer/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

管理服务:
```bash
# 启动服务
sudo systemctl start traffic-analyzer

# 开机自启
sudo systemctl enable traffic-analyzer

# 查看状态
sudo systemctl status traffic-analyzer

# 查看日志
sudo journalctl -u traffic-analyzer -f
```

### 5. 数据库优化

对于大量数据,考虑使用 PostgreSQL:

1. 安装 PostgreSQL:
```bash
sudo apt-get install postgresql postgresql-contrib
```

2. 创建数据库:
```sql
CREATE DATABASE traffic_db;
CREATE USER traffic_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE traffic_db TO traffic_user;
```

3. 更新配置:
```python
DATABASE_URL = "postgresql+asyncpg://traffic_user:your_password@localhost/traffic_db"
```

4. 安装驱动:
```bash
pip install asyncpg
```

### 6. 性能优化

**数据库索引:**
```sql
CREATE INDEX idx_flow_dataset_time ON flow(dataset_id, ts_start);
CREATE INDEX idx_flow_src_ip ON flow(src_ip);
CREATE INDEX idx_flow_dst_ip ON flow(dst_ip);
CREATE INDEX idx_alert_dataset_severity ON alert(dataset_id, severity);
```

**应用配置:**
```python
# config/settings.py
WORKERS = 4  # CPU 核心数
MAX_CONNECTIONS = 100
POOL_SIZE = 10
POOL_TIMEOUT = 30
```

**启动多进程:**
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 7. 监控和日志

**配置日志:**
```python
# config/logging.py
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/traffic-analyzer/app.log'),
        logging.StreamHandler()
    ]
)
```

**使用 Prometheus 监控:**
```bash
pip install prometheus-fastapi-instrumentator
```

```python
# main.py
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI()
Instrumentator().instrument(app).expose(app)
```

### 8. 备份策略

**数据库备份脚本:**
```bash
#!/bin/bash
BACKUP_DIR="/backup/traffic-analyzer"
DATE=$(date +%Y%m%d_%H%M%S)

# 备份数据库
sqlite3 /app/data/traffic.db ".backup '$BACKUP_DIR/traffic_$DATE.db'"

# 保留最近 7 天的备份
find $BACKUP_DIR -name "traffic_*.db" -mtime +7 -delete
```

**定时任务:**
```bash
# 每天凌晨 2 点备份
0 2 * * * /usr/local/bin/backup_traffic.sh
```

### 9. 安全加固

**配置防火墙:**
```bash
# 只允许 HTTP/HTTPS 访问
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

**限制文件上传:**
```python
# config/settings.py
MAX_UPLOAD_SIZE = 500 * 1024 * 1024  # 500MB
ALLOWED_EXTENSIONS = ['.pcap', '.pcapng']
```

**API 速率限制:**
```bash
pip install slowapi
```

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/v1/datasets/import")
@limiter.limit("5/minute")
async def import_dataset(...):
    ...
```

### 10. 故障排查

**常见问题:**

1. 端口被占用:
```bash
lsof -i :8000
kill -9 <PID>
```

2. 数据库锁定:
```bash
# 检查锁定进程
fuser /app/data/traffic.db

# 重启服务
sudo systemctl restart traffic-analyzer
```

3. 内存不足:
```bash
# 增加 swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

4. 查看应用日志:
```bash
tail -f /var/log/traffic-analyzer/app.log
```

### 11. 升级和维护

**滚动更新:**
```bash
# 拉取最新代码
git pull origin main

# 安装依赖
pip install -r requirements.txt

# 重启服务
sudo systemctl restart traffic-analyzer
```

**数据库迁移:**
```bash
# 使用 Alembic
alembic upgrade head
```

### 12. 性能基准测试

**压力测试:**
```bash
# 使用 ab
ab -n 1000 -c 10 http://localhost:8000/api/v1/dashboard

# 使用 wrk
wrk -t12 -c400 -d30s http://localhost:8000/api/v1/flows
```

---

## 快速部署命令汇总

```bash
# 1. 克隆项目
git clone <repo-url> && cd network-traffic-analyzer

# 2. 创建虚拟环境
python3 -m venv venv && source venv/bin/activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 运行测试
python test_system.py

# 5. 启动服务
python main.py

# 6. 使用 Docker
docker-compose up -d
```

项目已部署至: http://localhost:8000
