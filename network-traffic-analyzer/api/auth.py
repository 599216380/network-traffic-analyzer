"""
用户认证API
"""
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["authentication"])

# 简单的用户存储（实际生产环境应使用数据库）
USERS = {
    "admin": {
        "password_hash": hashlib.sha256("admin".encode()).hexdigest(),
        "role": "admin",
        "display_name": "管理员"
    }
}

# 简单的token存储（实际生产环境应使用Redis或数据库）
TOKENS = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str
    display_name: str
    expires_at: str


def hash_password(password: str) -> str:
    """密码哈希"""
    return hashlib.sha256(password.encode()).hexdigest()


def generate_token() -> str:
    """生成安全token"""
    return secrets.token_urlsafe(32)


def get_current_user(authorization: Optional[str] = Header(None)):
    """获取当前登录用户"""
    if not authorization:
        raise HTTPException(status_code=401, detail="未提供认证信息")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="认证格式错误")
    
    token = authorization[7:]
    
    if token not in TOKENS:
        raise HTTPException(status_code=401, detail="无效的token")
    
    token_data = TOKENS[token]
    
    if datetime.now() > token_data["expires_at"]:
        del TOKENS[token]
        raise HTTPException(status_code=401, detail="token已过期")
    
    return token_data["username"]


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """用户登录"""
    username = request.username.strip()
    password = request.password
    
    # 验证用户
    if username not in USERS:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    user = USERS[username]
    
    if user["password_hash"] != hash_password(password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    # 生成token
    token = generate_token()
    expires_at = datetime.now() + timedelta(hours=24)
    
    # 存储token
    TOKENS[token] = {
        "username": username,
        "expires_at": expires_at,
        "created_at": datetime.now()
    }
    
    return LoginResponse(
        token=token,
        username=username,
        display_name=user["display_name"],
        expires_at=expires_at.isoformat()
    )


@router.post("/logout")
async def logout(authorization: Optional[str] = Header(None)):
    """用户登出"""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        if token in TOKENS:
            del TOKENS[token]
    
    return {"message": "登出成功"}


@router.get("/verify")
async def verify_token(current_user: str = Depends(get_current_user)):
    """验证token是否有效"""
    user = USERS.get(current_user, {})
    return {
        "valid": True,
        "username": current_user,
        "display_name": user.get("display_name", current_user)
    }


@router.get("/me")
async def get_current_user_info(current_user: str = Depends(get_current_user)):
    """获取当前用户信息"""
    user = USERS.get(current_user, {})
    return {
        "username": current_user,
        "display_name": user.get("display_name", current_user),
        "role": user.get("role", "user")
    }
