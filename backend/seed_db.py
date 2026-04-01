import sys
import os
import uuid
from sqlalchemy.orm import Session

# Add the current directory to sys.path so we can import database modules
sys.path.append(os.getcwd())

from database.db import SessionLocal, engine
from database import models

def seed():
    # Create tables
    print("Creating tables...")
    models.Base.metadata.create_all(bind=engine)
    
    db: Session = SessionLocal()
    
    try:
        # 1. Seed Permissions
        print("Seeding permissions...")
        permissions_data = [
            {"name": "scan:run", "description": "Can launch new scans"},
            {"name": "scan:view", "description": "Can view scan results"},
            {"name": "scan:delete", "description": "Can delete scans"},
            {"name": "user:manage", "description": "Can manage user accounts and roles"},
            {"name": "system:health", "description": "Can view system health/logs"},
        ]
        
        perms = {}
        for p in permissions_data:
            existing = db.query(models.Permission).filter_by(name=p["name"]).first()
            if not existing:
                new_p = models.Permission(name=p["name"], description=p["description"])
                db.add(new_p)
                perms[p["name"]] = new_p
                print(f"  Created permission: {p['name']}")
            else:
                perms[p["name"]] = existing
        
        db.commit()

        # 2. Seed Roles
        print("Seeding roles...")
        roles_data = [
            {
                "name": "Admin", 
                "description": "Full system access",
                "permissions": ["scan:run", "scan:view", "scan:delete", "user:manage", "system:health"]
            },
            {
                "name": "Analyst", 
                "description": "Scan management and analysis",
                "permissions": ["scan:run", "scan:view"]
            },
            {
                "name": "User", 
                "description": "Standard user - personal scans only",
                "permissions": ["scan:run", "scan:view"]
            },
        ]
        
        for r in roles_data:
            existing_role = db.query(models.Role).filter_by(name=r["name"]).first()
            if not existing_role:
                new_role = models.Role(name=r["name"], description=r["description"])
                # Link permissions
                for p_name in r["permissions"]:
                    if p_name in perms:
                        new_role.permissions.append(perms[p_name])
                
                db.add(new_role)
                print(f"  Created role: {r['name']}")
            else:
                print(f"  Role already exists: {r['name']}")
        
        db.commit()
        
        # 3. Handle Existing Users (Assign 'User' role to anyone without many)
        print("Updating existing users...")
        user_role = db.query(models.Role).filter_by(name="User").first()
        admin_role = db.query(models.Role).filter_by(name="Admin").first()
        
        users = db.query(models.User).filter(models.User.role_id == None).all()
        for u in users:
            # If it's the first user, maybe make them admin? 
            # For this project, let's just make everyone 'User' and the user can manually promote one.
            u.role = user_role
            print(f"  Assigned 'User' role to {u.email}")
            
        db.commit()
        print("Seeding complete.")

    except Exception as e:
        print(f"Error during seeding: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed()
