import sys
import os

# Ensure the backend directory is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.db import SessionLocal, engine
from database import models
import auth
from pydantic import BaseModel
import traceback

class R(BaseModel):
    name: str = "Test"
    email: str = "test4@test.com"
    password: str = "password"

models.Base.metadata.create_all(bind=engine)

request = R()
db = SessionLocal()
try:
    print("Hashing password...")
    hashed = auth.get_password_hash(request.password)
    print("Creating user object...")
    user = models.User(name=request.name, email=request.email, hashed_password=hashed)
    print("Adding to session...")
    db.add(user)
    print("Committing...")
    db.commit()
    print("Refreshing...")
    db.refresh(user)
    
    print("Creating tokens...")
    access_token = auth.create_access_token(data={"sub": user.id})
    refresh_token = auth.create_refresh_token(data={"sub": user.id})
    print("Success:", user.id)
except Exception as e:
    print("Exception occurred:")
    traceback.print_exc()
finally:
    db.close()
