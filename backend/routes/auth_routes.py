from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db import SessionLocal
from database import models
import auth
from pydantic import BaseModel, EmailStr

router = APIRouter(prefix="/api/auth", tags=["auth"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

@router.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = auth.get_password_hash(request.password)
    user = models.User(name=request.name, email=request.email, hashed_password=hashed)
    
    # First user becomes Admin, subsequent become User
    is_first_user = db.query(models.User).count() == 0
    role_name = "Admin" if is_first_user else "User"
    assigned_role = db.query(models.Role).filter_by(name=role_name).first()
    if assigned_role:
        user.roles.append(assigned_role)
        
    db.add(user)
    db.commit()
    db.refresh(user)

    user_role = user.roles[0].name if user.roles else "User"
    payload = {"sub": user.id, "email": user.email, "role": user_role}
    access_token  = auth.create_access_token(data=payload)
    refresh_token = auth.create_refresh_token(data=payload)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user_role},
    }

@router.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if not user or not auth.verify_password(request.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account suspended.")

    from datetime import datetime
    user.last_login = datetime.utcnow()
    db.commit()

    user_role = user.roles[0].name if user.roles else "User"
    payload = {"sub": user.id, "email": user.email, "role": user_role}
    access_token  = auth.create_access_token(data=payload)
    refresh_token = auth.create_refresh_token(data=payload)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {"id": user.id, "name": user.name, "email": user.email, "role": user_role},
    }

@router.post("/refresh")
def refresh_token(request: RefreshRequest, db: Session = Depends(get_db)):
    try:
        import jwt
        payload = jwt.decode(request.refresh_token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        user_id: str = payload.get("sub")
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User no longer exists")

    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_role = user.roles[0].name if user.roles else "User"
    new_payload = {"sub": user.id, "email": user.email, "role": user_role}
    new_access_token = auth.create_access_token(data=new_payload)
    return {"access_token": new_access_token, "token_type": "bearer"}
