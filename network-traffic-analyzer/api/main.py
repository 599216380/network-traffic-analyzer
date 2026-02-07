"""
FastAPI应用主入口
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import os

from config.settings import get_settings
from models import init_db
from api.routes import (
    datasets_router, flows_router, dns_router, http_router, tls_router,
    alerts_router, dashboard_router, export_router, rules_router
)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # 启动时初始化数据库
    await init_db()
    print(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} 启动成功")
    yield
    # 关闭时清理
    print("👋 应用关闭")


# 创建FastAPI应用
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="网络流量分析平台 - 支持PCAP导入、流量解析、威胁检测",
    lifespan=lifespan
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册API路由
app.include_router(datasets_router, prefix=settings.API_PREFIX)
app.include_router(flows_router, prefix=settings.API_PREFIX)
app.include_router(dns_router, prefix=settings.API_PREFIX)
app.include_router(http_router, prefix=settings.API_PREFIX)
app.include_router(tls_router, prefix=settings.API_PREFIX)
app.include_router(alerts_router, prefix=settings.API_PREFIX)
app.include_router(dashboard_router, prefix=settings.API_PREFIX)
app.include_router(export_router, prefix=settings.API_PREFIX)
app.include_router(rules_router, prefix=settings.API_PREFIX)


# 静态文件服务（前端）
static_path = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/")
async def root():
    """根路径 - 返回前端页面或API信息"""
    index_path = os.path.join(static_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "api": settings.API_PREFIX
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy"}


@app.get("/api")
async def api_info():
    """API信息"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "endpoints": {
            "datasets": f"{settings.API_PREFIX}/datasets",
            "flows": f"{settings.API_PREFIX}/flows",
            "dns": f"{settings.API_PREFIX}/dns",
            "http": f"{settings.API_PREFIX}/http",
            "tls": f"{settings.API_PREFIX}/tls",
            "alerts": f"{settings.API_PREFIX}/alerts",
            "dashboard": f"{settings.API_PREFIX}/dashboard",
            "export": f"{settings.API_PREFIX}/export",
            "rules": f"{settings.API_PREFIX}/rules"
        }
    }
