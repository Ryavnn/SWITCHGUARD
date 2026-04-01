import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

# Load environment variables from a .env file if present
load_dotenv()

# Get the database URL from the environment variables (defined in .env or system environment)
DATABASE_URL = os.getenv("DATABASE_URL")

# Create the engine that talks to the database
engine = create_engine(DATABASE_URL)

# Create a Session factory (this is what we use to add/save data)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our database models
Base = declarative_base()

# Dependency to get the database session in API requests
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()