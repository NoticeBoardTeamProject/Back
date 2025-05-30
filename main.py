from fastapi import FastAPI, Depends, HTTPException, status, Request, Body, Header,Form,UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
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
from typing import List,Optional
import json
from enum import Enum

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
    allow_origins=["*"],           
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
    role = Column(String, default="user")
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
    timestamp = Column(DateTime, default=datetime.utcnow)

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
    email: EmailStr
    password: str

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
    tags: str = ""
    category_id: int

class CategoryCreate(BaseModel):
    name: str

class UpdateProfile(BaseModel):
    name: str
    surname: str
    phone: str

class ChatCreate(BaseModel):
    user_to: int
    message: str

class ChatResponse(BaseModel):
    id: int
    user_from: int
    user_to: int
    message: str
    timestamp: datetime

    class Config:
        orm_mode = True

class ScamStatus(str, Enum):
    scam = "шахрай"
    not_scam = "не шахрай"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def send_verification_email(email: str, token: str):
    link = f"http://localhost:8000/verify-email?token={token}"
    html_body = f"""
    <html>
      <body>
        <p>Щоб підтвердити свій email, натисніть кнопку нижче:</p>
        <a href="{link}" style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">Підтвердити Email</a>
        <p>Якщо кнопка не працює, відкрийте це посилання:<br>{link}</p>
      </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Підтвердження email"
    msg["From"] = "Bulletin Board"
    msg["To"] = email
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, email, msg.as_string())

def send_password_reset_email(email: str, token: str):
    link = f"http://localhost:8000/reset-password-form?token={token}"
    html_body = f"""
    <html>
      <body>
        <p>Щоб скинути пароль, натисніть кнопку нижче:</p>
        <a href="{link}" style="display: inline-block; padding: 10px 20px; background-color: #f44336; color: white; text-decoration: none; border-radius: 5px;">Скинути пароль</a>
        <p>Якщо кнопка не працює, відкрийте це посилання:<br>{link}</p>
      </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Зміна пароля"
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

@app.post("/register", response_model=Token,tags=["User"])
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(user.password)
    user_data = user.dict()
    user_data.pop("password")  
    db_user = User(**user_data, password=hashed_pw)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    token = create_access_token({"sub": db_user.email})
    send_verification_email(db_user.email, token)

    return {"access_token": token, "token_type": "bearer"}

@app.post("/users/{user_id}/make-admin",tags=["User"])
def make_user_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["owner"]))
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin":
        return {"message": "User is already an admin"}
    user.role = "admin"
    db.commit()
    return {"message": f"User was successfully promoted to admin"}

@app.post("/forgot-password",tags=["User"])
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=request.email).first()
    if user:
        token = create_access_token({"sub": user.email}, expires_delta=timedelta(hours=1))
        send_password_reset_email(user.email, token)
    
    return {"message": "Якщо такий email існує, на нього надіслано листа для зміни пароля"}

@app.get("/posts/filter",tags=["Post"])
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
            raise HTTPException(status_code=404, detail="Категорія не знайдена")
    if tags:
        tag_list = [tag.strip().lower() for tag in tags.split(",")]
        for tag in tag_list:
            query = query.filter(Post.tags.ilike(f"%{tag}%"))

    results = query.all()

    if not results:
        raise HTTPException(status_code=404, detail="Оголошення за заданими параметрами не знайдено")

    for post in results:
        post.images = safe_load_images(post.images)

    return results

@app.get("/posts",tags=["Post"])
def get_posts(db: Session = Depends(get_db)):
    return db.query(Post).all()

@app.get("/posts/{post_id}",tags=["Post"])
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter_by(id=post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Оголошення не знайдено")
    
    post.views += 1
    db.commit()

    post.images = safe_load_images(post.images)
    return post


@app.get("/reset-password-form", response_class=HTMLResponse)
def reset_password_form(token: str):
    html_content = f"""
    <html>
      <body>
        <h2>Скинути пароль</h2>
        <form action="/reset-password" method="post">
          <input type="hidden" name="token" value="{token}" />
          <label>Новий пароль:</label><br>
          <input type="password" name="new_password" required/><br><br>
          <button type="submit">Скинути пароль</button>
        </form>
      </body>
    </html>
    """
    return html_content

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

@app.get("/chat/with/{other_user_id}", response_model=List[ChatResponse],tags=["User"])
def get_conversation(
    other_user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    messages = db.query(Chat).filter(
        ((Chat.user_from == current_user.id) & (Chat.user_to == other_user_id)) |
        ((Chat.user_from == other_user_id) & (Chat.user_to == current_user.id))
    ).order_by(Chat.timestamp.asc()).all()
    
    return messages

@app.get("/chat/my", response_model=List[ChatResponse],tags=["User"])
def get_my_chats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    messages = db.query(Chat).filter(
        (Chat.user_from == current_user.id) | (Chat.user_to == current_user.id)
    ).order_by(Chat.timestamp.desc()).all()

    return messages
    
@app.post("/reset-password",tags=["User"])
def reset_password(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")

        user.password = hash_password(new_password)
        db.commit()
        return HTMLResponse("""
            <html><body>
            <h3>Пароль успішно змінено!</h3>
            <a href="/login-form">Увійти</a>
            </body></html>
        """)
    except JWTError:
        raise HTTPException(status_code=400, detail="Невалідний або прострочений токен")

@app.post("/posts",tags=["Post"])
async def create_post(
    title: str = Form(...),
    caption: str = Form(...),
    price: int = Form(...),
    tags: str = Form(""),
    category_id: int = Form(...),
    images: List[UploadFile] = File([]),  
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    import base64
    image_list = []

    for image in images:
        contents = await image.read()
        encoded = base64.b64encode(contents).decode("utf-8")
        image_list.append(encoded)

    import json
    encoded_images = json.dumps(image_list)

    new_post = Post(
        title=title,
        caption=caption,
        price=price,
        tags=tags,
        category_id=category_id,
        images=encoded_images,
        userId=current_user.id
    )
    db.add(new_post)
    db.commit()
    db.refresh(new_post)
    return new_post

@app.post("/login", response_model=Token,tags=["User"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=form_data.username).first() 
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.isEmailConfirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/categories",tags=["Admin"])
def create_category(category: CategoryCreate, db: Session = Depends(get_db), _: User = Depends(require_role(["admin", "owner"]))):
    new_cat = Category(name=category.name)
    db.add(new_cat)
    db.commit()
    return new_cat

@app.post("/chat/send", response_model=ChatResponse,tags=["User"])
def send_message(
    chat: ChatCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    recipient = db.query(User).filter_by(id=chat.user_to).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")

    message = Chat(
        user_from=current_user.id,
        user_to=chat.user_to,
        message=chat.message
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message

@app.put("/posts/{post_id}/verify",tags=["Admin"])
def verify_post(
    post_id: int,
    status: ScamStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "owner"]))
):
    post = db.query(Post).filter_by(id=post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Оголошення не знайдено")
    
    if status == ScamStatus.scam:
        post.is_scam = True
    elif status == ScamStatus.not_scam:
        post.is_scam = False
    else:
        post.is_scam = None

    db.commit()
    return {"message": f"Статус верифікації оголошення оновлено: {status}"}

@app.put("/update-profile",tags=["User"])
def update_profile(data: UpdateProfile, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    current_user.name = data.name
    current_user.surname = data.surname
    current_user.phone = data.phone
    db.commit()
    db.refresh(current_user)
    return {"message": "Профіль оновлено успішно"}

@app.put("/categories/{cat_id}",tags=["Admin"])
def update_category(cat_id: int, category: CategoryCreate, db: Session = Depends(get_db)):
    cat = db.query(Category).filter_by(id=cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Категорію не знайдено")
    cat.name = category.name
    db.commit()
    return cat

@app.delete("/posts/{post_id}",tags=["User"])
def delete_post(post_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_post = db.query(Post).filter_by(id=post_id).first()
    if not db_post:
        raise HTTPException(status_code=404, detail="Оголошення не знайдено")
    if db_post.userId != current_user.id:
        raise HTTPException(status_code=403, detail="Немає прав на видалення цього оголошення")
    db.delete(db_post)
    db.commit()
    return {"message": "Оголошення видалено"}

@app.delete("/categories/{cat_id}",tags=["Admin"])
def delete_category(cat_id: int, db: Session = Depends(get_db), _: User = Depends(require_role(["admin", "owner"]))):
    cat = db.query(Category).filter_by(id=cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Категорію не знайдено")
    db.delete(cat)
    db.commit()
    return {"message": "Категорію видалено"}

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
                role="owner",
                isEmailConfirmed=True
            )
            db.add(owner)
            db.commit()
            print("[INFO] Default owner was created")
    finally:
        db.close()

create_default_owner()