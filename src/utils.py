import json
import jwt
import smtplib
from datetime import datetime, timedelta
from typing import List

from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from models import User, Category, Post
from main import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, get_db
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, SMTP_USER, SMTP_PASS, BASE_URL,FRONT_URL
from database import get_db, SessionLocal, Base, engine

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def send_verification_email(email: str, token: str):
    link = f"{BASE_URL}/verify-email?token={token}"

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
    link = f"{BASE_URL}/reset-password-form?token={token}"
    
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
    link = f"{FRONT_URL}/posts/{post.id}"
    first_image = json.loads(post.images)[0] if post.images else None

    currency_map = {
        "UAH": "UAH",
        "USD": "$",
        "EUR": "€"
    }

    currency = currency_map.get(post.currency, post.currency or "UAH")

    condition = "Used" if post.isUsed else "New"

    location = "No location"
    if getattr(post, "location", None):
        try:
            location = post.location.value  
        except AttributeError:
            location = post.location        

    html_body = f"""
    <html>
      <body style="background-color:#f9f9f9; padding:30px; font-family:Arial, sans-serif;">
        <div style="max-width:600px; margin:auto; background-color:#ffffff; padding:20px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,0.1);">
          <h2 style="text-align:center; color:#333333;">🔔 New post for you!</h2>
          
          {'<img src="data:image/jpeg;base64,' + first_image + '" style="max-width:100%; border-radius:8px; margin-bottom:15px;" />' if first_image else ''}

          <h3 style="color:#007BFF; margin-bottom:5px;">{post.title}</h3>
          <p style="color:#555555; font-size:15px; line-height:1.5;">{post.caption}</p>
          
          <p style="font-size:16px; font-weight:bold; color:#000000;">Ціна: {post.price} {currency}</p>
          <p style="font-size:15px; color:#333333;">Стан: {condition}</p>
          <p style="font-size:15px; color:#333333;">Локація: {location}</p>

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

def create_default_owner_and_categories():
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
                name="Daniil",
                surname="Shtyvola",
                phone="+3802546848",
                email="danyashtyvola@gmail.com",
                password=hash_password("123456789"),
                role="Admin",
                isVerified=True,
                isEmailConfirmed=True
            )
            db.add(admin)

            user1 = User(
                name="Patrick",
                surname="Star",
                phone="+3802347234794",
                email="patrick_star2352@gmail.com",
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
                name="Asuka",
                surname="Langley",
                phone="+38047234717",
                email="asuka_langley2135@gmail.com",
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

        categories = ["Toys", "Electronics", "Clothes", "Furniture"]
        for cat_name in categories:
            exists = db.query(Category).filter_by(name=cat_name).first()
            if not exists:
                new_cat = Category(name=cat_name)
                db.add(new_cat)

        db.commit()
    finally:
        db.close()