from fastapi import FastAPI, Depends, HTTPException, status, Request, Body, Header,Form
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
        <p>Щоб змінити пароль, натисніть кнопку нижче:</p>
        <a href="{link}" style="display: inline-block; padding: 10px 20px; background-color: #f44336; color: white; text-decoration: none; border-radius: 5px;">Змінити пароль</a>
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


@app.post("/register", response_model=Token)
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

@app.post("/init-owner", response_model=Token)
def create_initial_owner(user: UserCreate, db: Session = Depends(get_db)):
    existing_owner = db.query(User).filter_by(role="owner").first()
    if existing_owner:
        raise HTTPException(status_code=400, detail="Owner already exists")

    hashed_pw = hash_password(user.password)
    user_data = user.dict()
    user_data.pop("password")

    db_user = User(
        **user_data,
        password=hashed_pw,
        role="owner",
        isEmailConfirmed=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    token = create_access_token({"sub": db_user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/users/{user_id}/make-admin")
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

@app.post("/forgot-password")
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Користувача з таким email не знайдено")
    
    token = create_access_token({"sub": user.email}, expires_delta=timedelta(hours=1))
    send_password_reset_email(user.email, token)
    return {"message": "Лист для скидання пароля було відправлено на email"}

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
          <button type="submit">Змінити пароль</button>
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

@app.get("/me")
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

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=form_data.username).first() 
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.isEmailConfirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

Base.metadata.create_all(bind=engine)
