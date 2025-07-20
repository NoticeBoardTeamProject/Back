from fastapi import FastAPI, Depends, HTTPException, status, Request, Body, Header,Form,UploadFile, File, Query
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, constr, conint, Field
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, or_, desc, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse
import os
from typing import List,Optional, Annotated
import json
from enum import Enum
import base64

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

DATABASE_URL = "sqlite:///./bulletin_board.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
SMTP_USER = "bodyaraz7@gmail.com"
SMTP_PASS = "hqmmpdzlupuyvijl"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],           
    allow_credentials=True,        
    allow_methods=["*"],           
    allow_headers=["*"],           
)

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
    isBlocked = Column(Boolean, default=False)
    blockReason = Column(String, nullable=True)
    blockedAt = Column(DateTime, nullable=True)
    role = Column(String, default="User")
    socialLinks = Column(String)
    avatarBase64 = Column(String)
    createdAt = Column(DateTime, default=datetime.utcnow)

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
    createdAt = Column(DateTime, default=datetime.utcnow)
    is_scam: bool = Column(Boolean, default=None, nullable=True)
    userId = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"))  
    user = relationship("User")
    category = relationship("Category")

class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)   

class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    can_block_users = Column(Boolean, default=True)
    can_verify_posts = Column(Boolean, default=True)

class Complaint(Base):
    __tablename__ = "complaints"
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    message = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    post = relationship("Post")

class UserCreate(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=50)]
    surname: Annotated[str, Field(min_length=1, max_length=50)]
    phone: Annotated[str, Field(min_length=9, max_length=15, pattern=r'^[\d\-\+\(\) ]+$', example="+380671234567")]
    email: EmailStr
    password: Annotated[str, Field(min_length=8)]

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginForm(BaseModel):
    email: EmailStr
    password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

class PostCreate(BaseModel):
    title: str
    caption: str
    price: int
    images: str = ""
    tags: List[str]
    category_id: int

class UserInfo(BaseModel):
    id: int
    name: str
    surname: str
    phone: Optional[str]
    email: str
    avatarBase64: Optional[str]
    createdAt: str

    class Config:
        orm_mode = True

class PostResponse(BaseModel):
    id: int
    title: str
    caption: str
    price: int
    images: List[str]
    tags: List[str]
    views: int
    isPromoted: bool
    createdAt: str
    is_scam: Optional[bool]
    userId: int
    user: Optional[UserInfo] = None
    category_id: int
    category_name: Optional[str]

    class Config:
        orm_mode = True

class FavoriteCategory(Base):
    __tablename__ = "favorite_categories"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"))

    user = relationship("User")
    category = relationship("Category")

class CategoryCreate(BaseModel):
    name: str

class UpdateProfile(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=50)]
    surname: Annotated[str, Field(min_length=1, max_length=50)]
    phone: Annotated[str, Field(min_length=9, max_length=15, pattern=r'^[\d\-\+\(\) ]+$', example="+380671234567")]

class ScamStatus(str, Enum):
    scam = "swindler"
    not_scam = "no swindler"

class ComplaintCreate(BaseModel):
    post_id: Optional[int] = None
    user_id: Optional[int] = None
    message: str

class BlockUserRequest(BaseModel):
    isBlocked: bool
    blockReason: Optional[str] = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str = None) -> bool:
    if hashed_password:
        return pwd_context.verify(password, hashed_password)
    else:
        return len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password)


def create_access_token(user: User, expires_delta: timedelta = None):
    expire = datetime.utcnow() + (expires_delta or timedelta(days=1))
    to_encode = {
        "sub": user.email,
        "isVerified": user.isVerified,
        "role": user.role,
        "exp": expire
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def send_verification_email(email: str, token: str):
    link = f"http://localhost:8000/verify-email?token={token}"

    html_body = f"""
    <!DOCTYPE html>
    <html lang="uk">
    <head>
        <meta charset="UTF-8">
        <title>Confirmation email</title>
        <style>
            body {{
                background-color: #f4f4f4;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                text-align: center;
            }}
            h2 {{
                color: #333333;
                margin-bottom: 20px;
            }}
            p {{
                color: #555555;
                line-height: 1.6;
            }}
            .button {{
                display: inline-block;
                padding: 12px 24px;
                background-color: #4CAF50;
                color: white;
                text-decoration: none;
                border-radius: 6px;
                font-weight: bold;
                margin-top: 20px;
            }}
            .footer {{
                font-size: 13px;
                color: #888888;
                margin-top: 30px;
            }}
            .link-fallback {{
                color: #4a90e2;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Confirmation email</h2>
            <p>Thank you for registering in the service <strong>Bulletin Board</strong>.</p>
            <p>Click the button below to activate your account:</p>
            <a href="{link}" class="button">Confirm Email</a>
            <p>Or <a href="{link}" class="link-fallback">click here</a>, if the button does not work.</p>
            <div class="footer">
                If you have not registered with us, simply ignore this email.
            </div>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🔔 Confirmation Email"
    msg["From"] = "Bulletin Board"
    msg["To"] = email
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, email, msg.as_string())


def send_password_reset_email(email: str, token: str):
    link = f"http://localhost:8000/reset-password-form?token={token}"
    
    html_body = f"""
    <!DOCTYPE html>
    <html lang="uk">
    <head>
      <meta charset="UTF-8" />
      <title>Password reset</title>
      <style>
        body {{
          background-color: #f4f4f4;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          margin: 0;
          padding: 0;
        }}
        .email-container {{
          max-width: 600px;
          margin: 40px auto;
          background-color: #ffffff;
          border-radius: 10px;
          padding: 30px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }}
        h2 {{
          color: #333333;
          margin-bottom: 20px;
        }}
        p {{
          color: #555555;
          line-height: 1.6;
        }}
        .button {{
          display: inline-block;
          padding: 12px 24px;
          background-color: #f44336;
          color: white;
          text-decoration: none;
          border-radius: 6px;
          font-weight: bold;
          margin-top: 20px;
        }}
        .footer {{
          font-size: 13px;
          color: #888888;
          margin-top: 30px;
        }}
        .link-fallback {{
          word-break: break-word;
          color: #4a90e2;
        }}
      </style>
    </head>
    <body>
      <div class="email-container">
        <h2>Password reset</h2>
        <p>You received this email because you are trying to reset your account password.</p>
        <p>To set a new password, click the button below:</p>
        <a href="{link}" class="button">Reset password</a>
        <p>Or <a href="{link}" class="link-fallback">click here</a>, if the button does not work.</p>
        <div class="footer">
          If you have not sent a password change request, simply ignore this email.
        </div>
      </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🔐 Password reset"
    msg["From"] = "Bulletin Board"
    msg["To"] = email
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, email, msg.as_string())


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(allowed_roles: list[str]):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Access denied")
        return current_user
    return role_checker

def safe_load_images(images_str: str):
    if not images_str:
        return []
    try:
        return json.loads(images_str)
    except json.JSONDecodeError:
        return []

def send_new_post_email(to: str, post: Post) -> None:
    link = f"http://localhost:8000/posts/{post.id}"
    first_image = json.loads(post.images)[0] if post.images else None

    html_body = f"""
    <html>
      <body style="background-color:#f9f9f9; padding:30px; font-family:Arial, sans-serif;">
        <div style="max-width:600px; margin:auto; background-color:#ffffff; padding:20px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,0.1);">
          <h2 style="text-align:center; color:#333333;">🔔 New post for you!</h2>
          
          {'<img src="data:image/jpeg;base64,' + first_image + '" style="max-width:100%; border-radius:8px; margin-bottom:15px;" />' if first_image else ''}

          <h3 style="color:#007BFF; margin-bottom:5px;">{post.title}</h3>
          <p style="color:#555555; font-size:15px; line-height:1.5;">{post.caption}</p>
          <p style="font-size:16px; font-weight:bold; color:#000000;">Ціна: {post.price} грн</p>

          <div style="text-align:center; margin-top:25px;">
            <a href="{link}" style="background-color:#28a745; color:white; padding:12px 20px; border-radius:5px; text-decoration:none; font-size:16px;">View the post</a>
          </div>

          <hr style="margin-top:30px; border:none; border-top:1px solid #e0e0e0;" />
          <p style="font-size:12px; color:#999999; text-align:center;">
            You received this message because you are subscribed to new ads in your favorite categories.
          </p>
        </div>
      </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "New ad in your favorite category 📢"
    msg["From"] = "Bulletin Board"
    msg["To"] = to
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to, msg.as_string())

def safe_load_tags(tags_str: str):
    if not tags_str:
        return []
    try:
        return json.loads(tags_str)
    except json.JSONDecodeError:
        return [t.strip() for t in tags_str.split(",") if t.strip()]

@app.post("/register", response_model=Token,tags=["User"])
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=user.email).first():
        raise HTTPException(status_code=400, detail="Email is already registered!")
    if not verify_password(user.password):
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not (1 <= len(user.name) <= 50):
        raise HTTPException(status_code=400, detail="Name must be between 1 and 50 characters.")
    if not (1 <= len(user.surname) <= 50):
        raise HTTPException(status_code=400, detail="Surname must be between 1 and 50 characters.")
    if not (9 <= len(user.phone) <= 15):
        raise HTTPException(status_code=400, detail="Phone number must be between 9 and 15 characters.")
    
    hashed_pw = hash_password(user.password)
    user_data = user.dict()
    user_data.pop("password")  
    db_user = User(**user_data, password=hashed_pw)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    token = create_access_token(db_user)
    send_verification_email(db_user.email, token)

    return {"access_token": token, "token_type": "bearer"}

@app.post("/complaints", tags=["User"])
def create_complaint(
    complaint: ComplaintCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not complaint.post_id and not complaint.user_id:
        raise HTTPException(status_code=400, detail="Either a post or a user must be specified.")

    new_complaint = Complaint(
        post_id=complaint.post_id,
        user_id=complaint.user_id,
        message=complaint.message
    )
    db.add(new_complaint)
    db.commit()
    db.refresh(new_complaint)
    return {"message": "Complaint sent"}

@app.post("/users/make-admin/{user_id}",tags=["User"])
def make_user_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["Owner"]))
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "Admin":
        return {"message": "User is already an administrator"}
    user.role = "Admin"
    db.commit()
    return {"message": f"User successfully promoted to administrator"}

@app.post("/forgot-password",tags=["User"])
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=request.email).first()
    if user:
        token = create_access_token(user, expires_delta=timedelta(hours=1))
        send_password_reset_email(user.email, token)
    
    return {"message": "If such an email exists, an email to change the password will be sent to it"}

@app.get("/posts/filter", tags=["Post"])
def search_posts(
    title: Optional[str] = None,
    min_price: Optional[int] = None,
    max_price: Optional[int] = None,
    category_name: Optional[str] = None,
    tags: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Post)

    if title:
        query = query.filter(Post.title.ilike(f"%{title}%"))
    if min_price is not None:
        query = query.filter(Post.price >= min_price)
    if max_price is not None:
        query = query.filter(Post.price <= max_price)
    if category_name:
        category = db.query(Category).filter(Category.name.ilike(category_name)).first()
        if category:
            query = query.filter(Post.category_id == category.id)
        else:
            raise HTTPException(status_code=404, detail="Category not found")
    if tags:
        tag_list = [tag.strip().lower() for tag in tags.split(",")]
        for tag in tag_list:
            query = query.filter(Post.tags.ilike(f"%{tag}%"))

    results = query.all()

    if not results:
        raise HTTPException(status_code=404, detail="No post found with the specified parameters")

    for post in results:
        post.images = safe_load_images(post.images)
        post.tags = safe_load_tags(post.tags)  

    return results

@app.get("/blocked-users", tags=["Admin"])
def get_blocked_users(db: Session = Depends(get_db), _: User = Depends(require_role(["Admin", "Owner"]))):
    blocked_users = db.query(User).filter(User.isBlocked == True).all()
    result = []
    for user in blocked_users:
        result.append({
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "surname": user.surname,
            "avatarBase64": user.avatarBase64,
            "phone": user.phone,
            "blockReason": user.blockReason,
            "blockedAt": user.blockedAt
        })
    return result

@app.get("/posts", tags=["Post"])
def get_posts(db: Session = Depends(get_db)):
    posts = db.query(Post).order_by(Post.createdAt.desc()).all()
    for post in posts:
        post.images = safe_load_images(post.images)
        post.tags = safe_load_tags(post.tags)
    return posts

@app.get("/posts/{post_id}", response_model=PostResponse, tags=["Post"])
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="No post found")

    post.views = (post.views or 0) + 1
    db.add(post)
    db.commit()
    db.refresh(post)

    user = db.query(User).filter(User.id == post.userId).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    category = db.query(Category).filter(Category.id == post.category_id).first()

    post.images = safe_load_images(post.images)

    post_tags = safe_load_tags(post.tags)

    user_info = UserInfo(
        id=user.id,
        name=user.name,
        surname=user.surname,
        phone=user.phone,
        email=user.email,
        avatarBase64=user.avatarBase64,
        createdAt=user.createdAt.isoformat()
    )

    return PostResponse(
        id=post.id,
        title=post.title,
        caption=post.caption,
        price=post.price,
        images=post.images,
        tags=post_tags,
        views=post.views,
        isPromoted=post.isPromoted,
        createdAt=post.createdAt.isoformat(),
        is_scam=post.is_scam,
        userId=post.userId,
        user=user_info,
        category_id=post.category_id,
        category_name=category.name if category else None,
    )

@app.get("/reset-password-form", response_class=HTMLResponse)
def reset_password_form(token: str):
    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Скидання пароля</title>
        <meta charset="utf-8" />
        <style>
            body {{
                background-color: #f2f2f2;
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }}
            .container {{
                background-color: #fff;
                padding: 30px;
                border-radius: 12px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                width: 100%;
                max-width: 400px;
            }}
            input {{
                width: 100%;
                padding: 10px;
                margin: 10px 0;
                border: 1px solid #ccc;
                border-radius: 8px;
            }}
            button {{
                width: 100%;
                padding: 10px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-size: 16px;
            }}
            button:hover {{
                background-color: #45a049;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Password reset</h2>
            <form method="post" action="/reset-password">
                <input type="hidden" name="token" value="{token}">
                <label for="new_password">New password:</label>
                <input type="password" name="new_password" required>
                <button type="submit">Confirm</button>
            </form>
        </div>
    </body>
    </html>
    """)

@app.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.isEmailConfirmed = True
        db.commit()
        return {"message": "Email confirmed!"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.get("/me",tags=["User"])
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "surname": current_user.surname,
        "email": current_user.email,
        "phone": current_user.phone,
        "isEmailConfirmed": current_user.isEmailConfirmed,
        "role": current_user.role,
        "createdAt": current_user.createdAt
    }

@app.get("/categories",tags=["Admin"])
def list_categories(db: Session = Depends(get_db)):
    return db.query(Category).all()

class Dialogue(Base):
    __tablename__ = "dialogues"

    id = Column(Integer, primary_key=True, index=True)
    user_from = Column(Integer, ForeignKey("users.id"), nullable=False)
    user_to = Column(Integer, ForeignKey("users.id"), nullable=False)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)

    user_from_rel = relationship("User", foreign_keys=[user_from])
    user_to_rel = relationship("User", foreign_keys=[user_to])
    post_rel = relationship("Post")

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    dialogue_id = Column(Integer, ForeignKey("dialogues.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    dialogue = relationship("Dialogue", backref="messages")
    user = relationship("User")

class UserShortResponse(BaseModel):
    id: int
    nickname: str

class PostShortResponse(BaseModel):
    id: int
    title: str

class MessageResponse(BaseModel):
    id: int
    dialogue_id: int
    user_id: int
    message: str
    timestamp: datetime

class DialogueSummaryResponse(BaseModel):
    id: int
    other_user: UserShortResponse
    post: PostShortResponse
    last_message: Optional[str]
    last_message_time: Optional[datetime]

class DialogueDetailResponse(BaseModel):
    other_user: UserShortResponse
    post: PostShortResponse
    messages: List[MessageResponse]

class SendMessageRequest(BaseModel):
    other_user_id: int
    post_id: int
    message: str

class SendMessageResponse(BaseModel):
    success: bool
    message_id: Optional[int]

@app.get("/chat/my", response_model=List[DialogueSummaryResponse], tags=["User"])
def get_my_chats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    dialogues = db.query(Dialogue).filter(
        (Dialogue.user_from == current_user.id) | (Dialogue.user_to == current_user.id)
    ).all()

    result = []

    for dialogue in dialogues:
        if dialogue.user_from == current_user.id:
            other_user = db.query(User).filter(User.id == dialogue.user_to).first()
        else:
            other_user = db.query(User).filter(User.id == dialogue.user_from).first()

        if not other_user:
            continue

        last_message = (
            db.query(Message)
            .filter(Message.dialogue_id == dialogue.id)
            .order_by(desc(Message.timestamp))
            .first()
        )

        post = db.query(Post).filter(Post.id == dialogue.post_id).first()

        post_response = PostShortResponse(
            id=post.id if post else -1,
            title=post.title if post else "Deleted post"
        )

        result.append(DialogueSummaryResponse(
            id=dialogue.id,
            other_user=UserShortResponse(
                id=other_user.id,
                nickname=f"{other_user.name} {other_user.surname}"
            ),
            post=post_response,
            last_message=last_message.message if last_message else None,
            last_message_time=last_message.timestamp if last_message else None
        ))

    return result

@app.get("/chat/with/{other_user_id}", response_model=DialogueDetailResponse, tags=["User"])
def get_conversation(
    other_user_id: int,
    post_id: int = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if other_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot create a chat with yourself")

    dialogue = db.query(Dialogue).filter(
        (
            ((Dialogue.user_from == current_user.id) & (Dialogue.user_to == other_user_id)) |
            ((Dialogue.user_from == other_user_id) & (Dialogue.user_to == current_user.id))
        ) & (Dialogue.post_id == post_id)
    ).first()

    if not dialogue:
        dialogue = Dialogue(
            user_from=current_user.id,
            user_to=other_user_id,
            post_id=post_id
        )
        db.add(dialogue)
        db.commit()
        db.refresh(dialogue)

    if dialogue.user_from == current_user.id:
        other_user = db.query(User).filter(User.id == dialogue.user_to).first()
    else:
        other_user = db.query(User).filter(User.id == dialogue.user_from).first()

    post = db.query(Post).filter(Post.id == dialogue.post_id).first()
    messages = db.query(Message).filter(Message.dialogue_id == dialogue.id).order_by(Message.timestamp.asc()).all()

    messages_response = [
        MessageResponse(
            id=msg.id,
            dialogue_id=msg.dialogue_id,
            user_id=msg.user_id,
            message=msg.message,
            timestamp=msg.timestamp
        )
        for msg in messages
    ]

    return DialogueDetailResponse(
        other_user=UserShortResponse(
            id=other_user.id,
            nickname=f"{other_user.name} {other_user.surname}"
        ),
        post=PostShortResponse(
            id=post.id if post else post_id,
            title=post.title if post else "The post has been removed"
        ),
        messages=messages_response
    )

@app.post("/chat/send", response_model=SendMessageResponse, tags=["User"])
def send_message(
    request: SendMessageRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    dialogue = db.query(Dialogue).filter(
        (
            ((Dialogue.user_from == current_user.id) & (Dialogue.user_to == request.other_user_id)) |
            ((Dialogue.user_from == request.other_user_id) & (Dialogue.user_to == current_user.id))
        ) & (Dialogue.post_id == request.post_id)
    ).first()

    if not dialogue:
        dialogue = Dialogue(
            user_from=current_user.id,
            user_to=request.other_user_id,
            post_id=request.post_id
        )
        db.add(dialogue)
        db.commit()
        db.refresh(dialogue)

    message = Message(
        dialogue_id=dialogue.id,
        user_id=current_user.id,
        message=request.message,
        timestamp=datetime.utcnow()
    )
    db.add(message)
    db.commit()
    db.refresh(message)

    return SendMessageResponse(success=True, message_id=message.id)

class ComplaintResponse(BaseModel):
    id: int
    post_id: Optional[int]
    user_id: Optional[int]
    message: str
    created_at: datetime

    complained_user_name: Optional[str]
    complained_user_surname: Optional[str]
    complained_post_title: Optional[str]

    class Config:
        orm_mode = True

@app.get("/complaints", response_model=List[ComplaintResponse], tags=["Admin"])
def list_complaints(
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["Admin", "Owner"]))
):
    complaints = db.query(Complaint).order_by(Complaint.created_at.desc()).all()
    result = []
    for c in complaints:
        result.append(
            ComplaintResponse(
                id=c.id,
                post_id=c.post_id,
                user_id=c.user_id,
                message=c.message,
                created_at=c.created_at,
                complained_user_name=c.user.name if c.user else None,
                complained_user_surname=c.user.surname if c.user else None,
                complained_post_title=c.post.title if c.post else None
            )
        )
    return result

@app.get("/admins", tags=["Owner"])
def get_all_admins(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["Owner"]))
):
    admins = db.query(User).filter(User.role == "Admin").all()
    
    if not admins:
        return {"detail": "There are no administrators yet"}

    return [
        {
            "id": admin.id,
            "email": admin.email,
            "isBlocked": admin.isBlocked,
            "blockReason": admin.blockReason,
            "blockedAt": admin.blockedAt
        }
        for admin in admins
    ]

@app.post("/reset-password")
def reset_password(
    token: str = Form(...),
    new_password: Annotated[str, Field(min_length=8)] = Form(...),
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.password = hash_password(new_password)
        db.commit()

        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Успішна зміна пароля</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f0f2f5;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                }
                .box {
                    background-color: white;
                    padding: 40px;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                    text-align: center;
                }
                h3 {
                    color: #333;
                    margin-bottom: 20px;
                }
                a.button {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #4CAF50;
                    color: white;
                    border-radius: 8px;
                    text-decoration: none;
                    font-weight: bold;
                    transition: background-color 0.3s ease;
                }
                a.button:hover {
                    background-color: #45a049;
                }
            </style>
        </head>
        <body>
            <div class="box">
                <h3>Пароль успішно змінено!</h3>
                <a href="/docs" class="button">Увійти</a>
            </div>
        </body>
        </html>
        """)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@app.post("/posts",tags=["Post"])
async def create_post(
    title: str = Form(...,max_length=100),
    caption: str = Form(...,max_length=1000),
    price: int = Form(...),
    tags: str = Form(""),
    category_id: int = Form(...),
    images: List[UploadFile] = File([]),  
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user.isVerified:
        raise HTTPException(status_code=403, detail="Only verified users can create posts")
    
    if price < 0:
        raise HTTPException(status_code=400, detail="Price cannot be less than 0")
    
    import base64
    import json

    allowed_types = {"image/jpeg", "image/png", "image/jpg", "image/webp"}
    image_list = []

    for image in images:
        if image.content_type not in allowed_types:
            raise HTTPException(
                status_code=400,
                detail="Only JPG, JPEG, PNG, and WEBP image formats are allowed"
            )

        contents = await image.read()
        encoded = base64.b64encode(contents).decode("utf-8")
        image_list.append(encoded)
        
    encoded_images = json.dumps(image_list)
    
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    encoded_tags = json.dumps(tag_list)

    new_post = Post(
        title=title,
        caption=caption,
        price=price,
        tags=encoded_tags,
        category_id=category_id,
        images=encoded_images,
        userId=current_user.id
    )
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    
    fav_users = (
    db.query(User)
    .join(FavoriteCategory, FavoriteCategory.user_id == User.id)
    .filter(FavoriteCategory.category_id == new_post.category_id)
    .filter(User.isEmailConfirmed == True)
    .all()
    )

    for user in fav_users:
        send_new_post_email(user.email, new_post)
    new_post.tags = safe_load_tags(new_post.tags)
    new_post.images = safe_load_images(new_post.images)
    return new_post


@app.post("/categories/favorite/{category_id}", tags=["User"])
def add_favorite_category(
    category_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    exists = db.query(FavoriteCategory).filter_by(user_id=current_user.id, category_id=category_id).first()
    if exists:
        raise HTTPException(status_code=400, detail="The category is already in favorites")

    fav = FavoriteCategory(user_id=current_user.id, category_id=category_id)
    db.add(fav)
    db.commit()
    return {"message": "The category has been added to favorites"}

@app.delete("/categories/favorite/{category_id}", tags=["User"])
def remove_favorite_category(
    category_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    favorite = db.query(FavoriteCategory).filter_by(
        user_id=current_user.id,
        category_id=category_id
    ).first()

    if not favorite:
        raise HTTPException(status_code=404, detail="Category not found in favorites")

    db.delete(favorite)
    db.commit()
    return {"message": "The category has been removed from favorites"}

@app.get("/categories/favorite", tags=["User"])
def get_favorite_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    favorites = (
        db.query(Category)
        .join(FavoriteCategory, FavoriteCategory.category_id == Category.id)
        .filter(FavoriteCategory.user_id == current_user.id)
        .all()
    )

    return [{"id": cat.id, "name": cat.name} for cat in favorites]

@app.get("/my/posts", response_model=List[PostResponse], tags=["Post"])
def get_my_posts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    posts = (
        db.query(Post)
        .filter(Post.userId == current_user.id)
        .order_by(Post.createdAt.desc())
        .all()
    )

    if not posts:
        raise HTTPException(status_code=404, detail="You don't have any posts")

    result = []
    for post in posts:
        category = db.query(Category).filter(Category.id == post.category_id).first()

        result.append(PostResponse(
            id=post.id,
            title=post.title,
            caption=post.caption,
            price=post.price,
            images=safe_load_images(post.images),
            tags=safe_load_tags(post.tags),
            views=post.views,
            isPromoted=post.isPromoted,
            createdAt=post.createdAt.isoformat(),
            is_scam=post.is_scam,
            userId=post.userId,
            category_id=post.category_id,
            category_name=category.name if category else None
        ))

    return result

@app.post("/login", response_model=Token, tags=["User"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.isEmailConfirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed!")
    if user.isBlocked:
        raise HTTPException(status_code=403, detail=f"User is blocked. Reason: {user.blockReason or 'not specified'}")
    
    token = create_access_token(user)
    
    return {"access_token": token, "token_type": "bearer"}

@app.post("/categories",tags=["Admin"])
def create_category(category: CategoryCreate, db: Session = Depends(get_db)):
    
    existing_category = db.query(Category).filter_by(name=category.name).first()
    if existing_category:
        raise HTTPException(status_code=400, detail="A category with this name already exists")

    new_cat = Category(name=category.name)
    db.add(new_cat)
    db.commit()
    return {"detail": "Category successfully added"}

@app.put("/posts/verify/{post_id}",tags=["Admin"])
def verify_post(
    post_id: int,
    status: ScamStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["Admin", "Owner"]))
):
    post = db.query(Post).filter_by(id=post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="No posts found.")
    
    if status == ScamStatus.scam:
        post.is_scam = True
    elif status == ScamStatus.not_scam:
        post.is_scam = False
    else:
        post.is_scam = None

    db.commit()
    return {"message": f"Ad verification status updated: {status}"}

@app.put("/users/block/{user_id}", tags=["Admin"])
def block_user(
    user_id: int,
    data: BlockUserRequest = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["Admin", "Owner"]))
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if current_user.role == "Admin" and user.role in ["Admin", "Owner"]:
        raise HTTPException(status_code=403, detail="Insufficient rights to block administrator")

    if user.role == "Admin" and current_user.role != "Owner":
        raise HTTPException(status_code=403, detail="Only the owner can block the administrator")

    user.isBlocked = data.isBlocked
    if data.isBlocked:
        user.blockReason = data.blockReason
        user.blockedAt = datetime.utcnow()
    else:
        user.blockReason = None
        user.blockedAt = None

    db.commit()
    return {"message": f"User {'blocked' if data.isBlocked else 'unlocked'}"}

@app.put("/update-profile",tags=["User"])
def update_profile(data: UpdateProfile, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.name = data.name
    current_user.surname = data.surname
    current_user.phone = data.phone
    db.commit()
    db.refresh(current_user)
    return {"message": "Profile updated successfully"}

@app.put("/categories/{cat_id}",tags=["Admin"])
def update_category(cat_id: int, category: CategoryCreate, db: Session = Depends(get_db)):
    cat = db.query(Category).filter_by(id=cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
    cat.name = category.name
    db.commit()
    return cat

class VerificationRequest(Base):
    __tablename__ = "verification_requests"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    images = Column(String)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")

class VerificationRequestCreate(BaseModel):
    images: List[str]

class VerificationResponse(BaseModel):
    id: int
    user_id: int
    email: str
    name: Optional[str]
    surname: Optional[str]
    avatarBase64: Optional[str]
    phone: Optional[str]
    images: List[str]
    status: str
    created_at: datetime

    class Config:
        orm_mode = True

class VerificationStatus(str, Enum):
    approved = "approved"
    rejected = "rejected"

class VerificationUpdate(BaseModel):
    status: VerificationStatus

@app.post("/verification/request", tags=["Verification"])
async def request_verification(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    allowed_types = {"image/jpeg", "image/png", "image/jpg", "image/webp"}

    existing_request = db.query(VerificationRequest).filter_by(user_id=current_user.id).first()
    if existing_request:
        raise HTTPException(status_code=400, detail="Verification request already submitted")

    base64_images = []
    for file in files:
        if file.content_type not in allowed_types:
            raise HTTPException(
                status_code=400,
                detail="Only JPG, JPEG, PNG, and WEBP image formats are allowed"
            )
        content = await file.read()
        encoded = base64.b64encode(content).decode("utf-8")
        base64_images.append(encoded)

    new_request = VerificationRequest(
        user_id=current_user.id,
        images=json.dumps(base64_images),
        status="pending"
    )
    db.add(new_request)
    db.commit()

    return {"detail": "Verification request submitted successfully"}


@app.get("/verification/requests", response_model=List[VerificationResponse], tags=["Admin"])
def get_verification_requests(
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["Admin", "Owner"]))
):
    requests = db.query(VerificationRequest).filter_by(status="pending").all()

    return [
        VerificationResponse(
            id=r.id,
            user_id=r.user_id,
            email=r.user.email,
            name=r.user.name,
            surname=r.user.surname,
            avatarBase64=r.user.avatarBase64,
            phone=r.user.phone,
            images=json.loads(r.images),
            status=r.status,
            created_at=r.created_at
        ) for r in requests
    ]


@app.put("/verification/requests/{request_id}", tags=["Admin"])
def verify_user_request(
    request_id: int,
    update: VerificationUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["Admin", "Owner"]))
):
    req = db.query(VerificationRequest).filter_by(id=request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Verification request not found")

    req.status = update.status.value

    if update.status == VerificationStatus.approved:
        req.user.isVerified = True
        message = "Verification request approved"
    else:
        message = "Verification request rejected"

    db.commit()
    return {"detail": message}

@app.delete("/posts/{post_id}", tags=["User"])
def delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_post = db.query(Post).filter_by(id=post_id).first()
    if not db_post:
        raise HTTPException(status_code=404, detail="No posts found")

    if db_post.userId != current_user.id and current_user.role not in ["Admin", "Owner"]:
        raise HTTPException(status_code=403, detail="No rights to delete this post")

    db.delete(db_post)
    db.commit()
    return {"message": "Post deleted"}

@app.delete("/categories/{cat_id}",tags=["Admin"])
def delete_category(cat_id: int, db: Session = Depends(get_db), _: User = Depends(require_role(["Admin", "Owner"]))):
    cat = db.query(Category).filter_by(id=cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
    db.delete(cat)
    db.commit()
    return {"message": "Category deleted"}

@app.put("/admins/{user_id}/demote", tags=["Owner"])
def demote_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["Owner"]))
):
    admin = db.query(User).filter_by(id=user_id, role="Admin").first()
    if not admin:
        raise HTTPException(status_code=404, detail="Administrator not found or no longer an administrator")
    if current_user.role != "Owner":
        raise HTTPException(status_code=403, detail="Only the owner can demote administrators")
    admin.role = "User"
    db.commit()
    return {"message": "Administrator demoted to user"}


Base.metadata.create_all(bind=engine)

def create_default_owner():
    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        if user_count == 0:
            owner = User(
                name="Bodya",
                surname="Raz",
                phone="+380562323765",
                email="Razum_ld54@student.itstep.org",
                password=hash_password("123456789"),
                role="Owner",
                isVerified=True,
                isEmailConfirmed=True
            )
            db.add(owner)
            
            admin = User(
                name="Test",
                surname="Admin",
                phone="+3802546848",
                email="test_admin124@gmail.com",
                password=hash_password("123456789"),
                role="Admin",
                isVerified=True,
                isEmailConfirmed=True
            )
            db.add(admin)

            user1 = User(
                name="Daniil",
                surname="Shtyvola",
                phone="+3802347234794",
                email="danyashtyvola@gmail.com",
                password=hash_password("123456789"),
                role="User",
                isVerified=True,
                isEmailConfirmed=True
            )
            db.add(user1)

            user2 = User(
                name="Sponge",
                surname="Bob",
                phone="+380732571617",
                email="sponge_bober263@gmail.com",
                password=hash_password("123456789"),
                role="User",
                isVerified=True,
                isEmailConfirmed=True
            )
            db.add(user2)

            user3 = User(
                name="Tralalero",
                surname="Tralala",
                phone="+38047234717",
                email="akula_tralala2135@gmail.com",
                password=hash_password("123456789"),
                role="User",
                isEmailConfirmed=True
            )
            db.add(user3)

            user4 = User(
                name="Ayanami",
                surname="Rei",
                phone="+380439867134",
                email="ayanami_rei23858@gmail.com",
                password=hash_password("123456789"),
                role="User",
                isEmailConfirmed=True
            )
            db.add(user4)

            db.commit()
    finally:
        db.close()

create_default_owner()