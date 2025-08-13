from fastapi import FastAPI, Depends, HTTPException, status, Request, Body, Header,Form,UploadFile, File, Query
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, constr, conint, Field
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, or_, desc, Text, Enum as SQLEnum, Float
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
from enum import Enum, IntEnum
import base64
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, SMTP_USER, SMTP_PASS
from database import get_db, Base, engine
from database import Base, engine, get_db
from utils import create_default_owner_and_categories
from models import (
    User, Post, Category, Review, Dialogue, Message, Complaint,
    FavoriteCategory, VerificationRequest
)
from schemas import (
    Token, UserCreate, ComplaintCreate, CategoryCreate, PostResponse, PostShortResponse,
    ReviewResponse, DialogueSummaryResponse, DialogueDetailResponse, UserShortResponse,
    MessageResponse, SendMessageRequest, SendMessageResponse, ComplaintResponse, UserInfo,
    BlockUserRequest, UpdateProfile,PasswordResetRequest, VerificationResponse, VerificationUpdate,
    CloseReason, RatingEnum, CurrencyEnum, CityEnum, ScamStatus, VerificationStatus
)
from utils import (
    hash_password, verify_password, create_access_token, get_current_user,
    require_role, safe_load_images, safe_load_tags,
    send_verification_email, send_password_reset_email, send_new_post_email
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", 
        "https://noticeboardteamproject.github.io"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/me",tags=["User"])
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "surname": current_user.surname,
        "email": current_user.email,
        "phone": current_user.phone,
        "isVerified": current_user.isVerified,
        "isEmailConfirmed": current_user.isEmailConfirmed,
        "avatarBase64": current_user.avatarBase64,
        "role": current_user.role,
        "createdAt": current_user.createdAt
    }

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
                nickname=f"{other_user.name} {other_user.surname}",
                avatarBase64=other_user.avatarBase64
            ),
            post=post_response,
            last_message=last_message.message if last_message else None,
            last_message_time=last_message.timestamp if last_message else None
        ))

    return result

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

@app.post("/register", response_model=Token, tags=["User"])
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=user.email).first():
        raise HTTPException(status_code=400, detail="Email is already registered!")
    if len(user.password) < 8:
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

@app.post("/forgot-password", tags=["User"])
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=request.email).first()
    if user:
        token = create_access_token({"sub": user.email}, expires_delta=timedelta(hours=1))
        send_password_reset_email(user.email, token)
    
    return {"message": "If such an email exists, an email to change the password will be sent to it"}

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

@app.post("/login", response_model=Token, tags=["User"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.isEmailConfirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed!")
    if user.isBlocked:
        raise HTTPException(status_code=403, detail=f"User is blocked. Reason: {user.blockReason or 'not specified'}")

    token = create_access_token(data={"sub": user.email})

    return {"access_token": token, "token_type": "bearer"}

@app.put("/update-profile", tags=["User"])
def update_profile(
    data: UpdateProfile,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    current_user.name = data.name
    current_user.surname = data.surname
    current_user.phone = data.phone

    if data.avatarBase64 is not None:
        current_user.avatarBase64 = data.avatarBase64

    db.commit()
    db.refresh(current_user)
    return {"message": "Profile updated successfully"}

@app.get("/posts/filter", tags=["Post"])
def search_posts(
    title: Optional[str] = None,
    min_price: Optional[int] = None,
    max_price: Optional[int] = None,
    category_name: Optional[str] = None,
    tags: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Post).filter(Post.isClosed == False)

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

@app.get("/posts/{post_id}", response_model=PostResponse, tags=["Post"])
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id, Post.isClosed == False).first()
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
        currency=post.currency,
        location=post.location,
        isUsed=post.isUsed
    )

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
            category_name=category.name if category else None,
            isUsed=post.isUsed,            
            currency=post.currency,       
            location=post.location 
        ))

    return result

@app.get("/posts", tags=["Post"])
def get_posts(db: Session = Depends(get_db)):
    posts = db.query(Post)\
              .filter(Post.isClosed == False)\
              .order_by(Post.createdAt.desc())\
              .all()
    if not posts:
        raise HTTPException(status_code=404, detail="There are no posts yet") 
    for post in posts:
        post.images = safe_load_images(post.images)
        post.tags = safe_load_tags(post.tags)
    return posts

@app.post("/posts/{id}/close", tags=["Post"])
def close_ad(
    id: int,
    reason: CloseReason = Form(...),  
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    post = db.query(Post).filter(Post.id == id, Post.userId == current_user.id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found or not yours")

    if post.isClosed:
        raise HTTPException(status_code=400, detail="Post already closed")

    post.isClosed = True
    post.closeReason = reason.value
    db.commit()

    return {"message": f"Post {id} closed successfully", "reason": reason.value}

@app.get("/reviews/{seller_id}", response_model=List[ReviewResponse], tags=["Reviews"])
def get_reviews(seller_id: int, db: Session = Depends(get_db)):
    reviews = db.query(Review).filter(Review.sellerId == seller_id).all()
    if not reviews:
        raise HTTPException(status_code=404, detail="No reviews found for this seller")
    return reviews

@app.get("/my/reviews", response_model=List[ReviewResponse], tags=["Reviews"])
def get_my_received_reviews(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    reviews = db.query(Review).filter(Review.sellerId == current_user.id).all()
    if not reviews:
        raise HTTPException(status_code=404, detail="You have not received any reviews yet")
    return reviews

@app.post("/reviews", response_model=ReviewResponse, tags=["Reviews"])
def create_review(
    sellerId: int = Form(...),
    text: str = Form(...),
    rating: RatingEnum = Form(...),  
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if sellerId == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot review yourself")

    review = Review(
        sellerId=sellerId,
        authorId=current_user.id,
        text=text,
        rating=rating.value  
    )
    db.add(review)
    db.commit()
    db.refresh(review)

    all_reviews = db.query(Review).filter(Review.sellerId == sellerId).all()
    avg_rating = sum(r.rating for r in all_reviews) / len(all_reviews)

    seller = db.query(User).filter(User.id == sellerId).first()
    seller.rating = avg_rating
    seller.reviewsCount = len(all_reviews)

    db.commit()

    return review

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

@app.get("/categories",tags=["Admin"])
def list_categories(db: Session = Depends(get_db)):
    return db.query(Category).all()


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

@app.post("/posts", tags=["Post"])
async def create_post(
    title: str = Form(..., max_length=100),
    caption: str = Form(..., max_length=1000),
    price: int = Form(...),
    tags: str = Form(""),
    category_id: int = Form(...),
    isUsed: bool = Form(...),
    currency: CurrencyEnum = Form(...),
    location: CityEnum = Form(...),
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
        userId=current_user.id,
        isUsed=isUsed,
        currency=currency,
        location=location
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
    data: BlockUserRequest = Form(...),
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

@app.put("/categories/{cat_id}",tags=["Admin"])
def update_category(cat_id: int, category: CategoryCreate, db: Session = Depends(get_db)):
    cat = db.query(Category).filter_by(id=cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
    cat.name = category.name
    db.commit()
    return cat

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

@app.put("/verification/requests/{request_id}", tags=["Admin"])
def verify_user_request(
    request_id: int,
    status: VerificationStatus = Form(...),
    db: Session = Depends(get_db),
    _: User = Depends(require_role(["Admin", "Owner"]))
):
    req = db.query(VerificationRequest).filter_by(id=request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Verification request not found")

    req.status = status.value

    if status == VerificationStatus.approved:
        req.user.isVerified = True
        message = "Verification request approved"
    else:
        message = "Verification request rejected"

    db.commit()
    return {"detail": message}

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

@app.delete("/categories/{cat_id}",tags=["Admin"])
def delete_category(cat_id: int, db: Session = Depends(get_db), _: User = Depends(require_role(["Admin", "Owner"]))):
    cat = db.query(Category).filter_by(id=cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
    db.delete(cat)
    db.commit()
    return {"message": "Category deleted"}

Base.metadata.create_all(bind=engine)
create_default_owner_and_categories()


