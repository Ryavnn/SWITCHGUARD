import sys
import os
from sqlalchemy.orm import Session

# Add the current directory to sys.path so we can import database modules
sys.path.append(os.getcwd())

from database.db import SessionLocal
from database import models
import auth

def reset_admin_password(email="admin@test.com", new_password="admin123"):
    """Resets the password for a specific user to a known value."""
    db: Session = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            print(f"Error: User with email {email} not found.")
            return

        print(f"Resetting password for {email}...")
        hashed = auth.get_password_hash(new_password)
        user.hashed_password = hashed
        
        # Ensure user is active
        user.is_active = True
        
        db.commit()
        print(f"Successfully reset password for {email} to: {new_password}")
        
    except Exception as e:
        print(f"Error resetting password: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    reset_admin_password()
