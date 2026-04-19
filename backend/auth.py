import os
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from database.db import SessionLocal
from database import models
from sqlalchemy.orm import Session

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    """
    Dependency to protect routes. Decodes JWT and fetches the user.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token has expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user


def get_current_active_user(user: models.User = Depends(get_current_user)):
    """
    Dependency to ensure the user is both authenticated AND active.
    """
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User account is inactive")
    return user


class RoleChecker:
    """
    Dependency to enforce RBAC. Usage: `Depends(RoleChecker(["Admin", "Analyst"]))`
    """
    def __init__(self, allowed_roles: list):
        self.allowed_roles = allowed_roles

    def __call__(self, user: models.User = Depends(get_current_user)):
        user_role = user.roles[0].name if user.roles else "User"
        if user_role not in self.allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Operation not permitted. Required roles: {self.allowed_roles}"
            )
        return user
