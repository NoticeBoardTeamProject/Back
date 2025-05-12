from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import datetime

DATABASE_URL = "sqlite:///./bulletein_board.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    surname = Column(String)
    phone = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    isEmailConfirmed = Column(Boolean, default=False)
    isVerified = Column(Boolean, default=False)
    role = Column(String, default="user")
    socialLinks = Column(String)
    avatarBase64 = Column(String)
    createdAt = Column(DateTime, default=datetime.datetime.utcnow)

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    caption = Column(String)
    price = Column(Integer)
    images = Column(String)  
    tags = Column(String)
    views = Column(Integer, default=0)
    isPromoted = Column(Boolean, default=False)
    createdAt = Column(DateTime, default=datetime.datetime.utcnow)
    userId = Column(Integer, ForeignKey("users.id"))
    user = relationship("User")

class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)

class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True)
    user_from = Column(Integer, ForeignKey("users.id"))
    user_to = Column(Integer, ForeignKey("users.id"))
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    can_block_users = Column(Boolean, default=True)
    can_verify_posts = Column(Boolean, default=True)


class UserCreate(BaseModel):
    name: str
    surname: str
    phone: str
    email: str
    password: str

class PostCreate(BaseModel):
    title: str
    caption: str
    price: int

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

Base.metadata.create_all(bind=engine)
