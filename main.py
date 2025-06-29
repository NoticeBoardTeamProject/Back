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
    isBlocked = Column(Boolean, default=False)
    blockReason = Column(String, nullable=True)
    blockedAt = Column(DateTime, nullable=True)
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

class ComplaintCreate(BaseModel):
    post_id: Optional[int] = None
    user_id: Optional[int] = None
    message: str

class BlockUserRequest(BaseModel):
    isBlocked: bool
    blockReason: Optional[str] = None

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
    images: List[str]
    status: str
    created_at: datetime

    class Config:
        orm_mode = True

class VerificationStatus(str, Enum):
    approved = "схвалити"
    rejected = "відхилити"

class VerificationUpdate(BaseModel):
    status: VerificationStatus

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
        raise HTTPException(status_code=400, detail="Email вже зареєстровано")

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

@app.post("/complaints", tags=["User"])
def create_complaint(
    complaint: ComplaintCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not complaint.post_id and not complaint.user_id:
        raise HTTPException(status_code=400, detail="Повинно бути вказано або пост, або користувач")

    new_complaint = Complaint(
        post_id=complaint.post_id,
        user_id=complaint.user_id,
        message=complaint.message
    )
    db.add(new_complaint)
    db.commit()
    db.refresh(new_complaint)
    return {"message": "Скаргу надіслано"}

@app.post("/users/make-admin/{user_id}",tags=["User"])
def make_user_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["owner"]))
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")
    if user.role == "admin":
        return {"message": "Користувач уже є адміністратором"}
    user.role = "admin"
    db.commit()
    return {"message": f"Користувача успішно підвищено до адміністратора"}

@app.post("/forgot-password",tags=["User"])
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=request.email).first()
    if user:
        token = create_access_token({"sub": user.email}, expires_delta=timedelta(hours=1))
        send_password_reset_email(user.email, token)
    
    return {"message": "Якщо такий email існує, на нього буде надіслано листа для зміни пароля"}

@app.post("/verification/request", tags=["Verification"])
async def request_verification(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    allowed_types = {"image/jpeg", "image/png", "image/jpg", "image/webp"}

    existing = db.query(VerificationRequest).filter_by(user_id=current_user.id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Заявка вже подана")

    base64_images = []
    for file in files:
        if file.content_type not in allowed_types:
            raise HTTPException(
                status_code=400,
                detail="Можна завантажувати лише фото: JPG, JPEG, PNG, WEBP"
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

    return {"detail": "Заявка на верифікацію подана"}

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

@app.get("/blocked-users", tags=["Admin"])
def get_blocked_users(db: Session = Depends(get_db), _: User = Depends(require_role(["admin", "owner"]))):
    blocked_users = db.query(User).filter(User.isBlocked == True).all()
    result = []
    for user in blocked_users:
        result.append({
            "id": user.id,
            "email": user.email,
            "blockReason": user.blockReason,
            "blockedAt": user.blockedAt
        })
    return result

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
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        user.isEmailConfirmed = True
        db.commit()
        return {"message": "Email підтверджено!"}
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

@app.get("/complaints", tags=["Admin"])
def list_complaints(
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["admin", "owner"]))
):
    return db.query(Complaint).order_by(Complaint.created_at.desc()).all()

@app.get("/admins", tags=["Owner"])
def get_all_admins(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["owner"]))
):
    admins = db.query(User).filter(User.role == "admin").all()
    
    if not admins:
        return {"detail": "Адміністраторів поки що немає"}

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

@app.get("/verification/requests", response_model=List[VerificationResponse], tags=["Admin"])
def get_verification_requests(
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["admin", "owner"]))
):
    requests = db.query(VerificationRequest).filter_by(status="pending").all()

    if not requests:
        raise HTTPException(status_code=404, detail="Заявок на верифікацію поки що немає")
    
    return [
        VerificationResponse(
            id=r.id,
            user_id=r.user_id,
            email=r.user.email,
            images=json.loads(r.images),
            status=r.status,
            created_at=r.created_at
        ) for r in requests
    ]

@app.post("/reset-password")
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
    if not current_user.isVerified:
        raise HTTPException(status_code=403, detail="Тільки верифіковані користувачі можуть створювати оголошення")
    
    import base64
    import json

    allowed_types = {"image/jpeg", "image/png", "image/jpg", "image/webp"}
    image_list = []

    for image in images:
        if image.content_type not in allowed_types:
            raise HTTPException(
                status_code=400,
                detail="Можна завантажувати лише фото: JPG, JPEG, PNG, WEBP"
            )

        contents = await image.read()
        encoded = base64.b64encode(contents).decode("utf-8")
        image_list.append(encoded)
        
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
        raise HTTPException(status_code=403, detail="Email не підтверджено")
    if user.isBlocked:
        raise HTTPException(status_code=403, detail=f"Користувач заблокований. Причина: {user.blockReason or 'не вказана'}")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/categories",tags=["Admin"])
def create_category(category: CategoryCreate, db: Session = Depends(get_db), _: User = Depends(require_role(["admin", "owner"]))):
    
    existing_category = db.query(Category).filter_by(name=category.name).first()
    if existing_category:
        raise HTTPException(status_code=400, detail="Категорія з такою назвою вже існує")

    new_cat = Category(name=category.name)
    db.add(new_cat)
    db.commit()
    return {"detail": "Категорія успішно додана"}

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

@app.put("/posts/verify/{post_id}",tags=["Admin"])
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

@app.put("/users/block/{user_id}", tags=["Admin"])
def block_user(
    user_id: int,
    data: BlockUserRequest = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "owner"]))
):
    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")

    if current_user.role == "admin" and user.role in ["admin", "owner"]:
        raise HTTPException(status_code=403, detail="Недостатньо прав для блокування адміністратора")

    if user.role == "admin" and current_user.role != "owner":
        raise HTTPException(status_code=403, detail="Тільки власник може блокувати адміністратора")

    user.isBlocked = data.isBlocked
    if data.isBlocked:
        user.blockReason = data.blockReason
        user.blockedAt = datetime.utcnow()
    else:
        user.blockReason = None
        user.blockedAt = None

    db.commit()
    return {"message": f"Користувач {'заблокований' if data.isBlocked else 'розблокований'}"}

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

@app.put("/verification/requests/{request_id}", tags=["Admin"])
def verify_user_request(
    request_id: int,
    status: VerificationStatus,  
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["admin", "owner"]))
):
    req = db.query(VerificationRequest).filter_by(id=request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Заявку не знайдено")

    req.status = status.name  

    if status == VerificationStatus.approved:
        req.user.isVerified = True
        message = "Заявку схвалено"
    else:
        message = "Заявку відхилено"

    db.commit()
    return {"detail": message}

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

@app.put("/admins/{user_id}/demote", tags=["Owner"])
def demote_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["owner"]))
):
    admin = db.query(User).filter_by(id=user_id, role="admin").first()
    if not admin:
        raise HTTPException(status_code=404, detail="Адміністратора не знайдено або він вже не є адміністратором")
    if current_user.role != "owner":
        raise HTTPException(status_code=403, detail="Тільки власник може понижувати адміністраторів")
    admin.role = "user"
    db.commit()
    return {"message": "Адміністратор понижений до користувача"}


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
    finally:
        db.close()

create_default_owner()