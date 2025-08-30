from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Annotated
from datetime import datetime
from enum import Enum, IntEnum
from models import CurrencyEnum, CityEnum, ScamStatus, CloseReason, RatingEnum, VerificationStatus

class UserCreate(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=50)]
    surname: Annotated[str, Field(min_length=1, max_length=50)]
    phone: Annotated[str, Field(min_length=9, max_length=15, pattern=r'^[\d\-\+\(\) ]+$', example="+380671234567")]
    email: EmailStr
    password: Annotated[str, Field(min_length=8)]

class UpdateProfile(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=50)]
    surname: Annotated[str, Field(min_length=1, max_length=50)]
    phone: Annotated[str, Field(min_length=9, max_length=15, pattern=r'^[\d\-\+\(\) ]+$', example="+380671234567")]
    avatarBase64: Optional[str] = None

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
    isUsed: bool
    currency: CurrencyEnum

class UserInfo(BaseModel):
    id: int
    name: str
    surname: str
    phone: Optional[str]
    email: str
    avatarBase64: Optional[str]
    createdAt: str
    rating: float = 0.0
    reviewsCount: int = 0
    
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
    isUsed: bool
    currency: CurrencyEnum
    location: CityEnum
    
    class Config:
        orm_mode = True

class PostShortResponse(BaseModel):
    id: int
    title: str

class CategoryCreate(BaseModel):
    name: str

class ComplaintCreate(BaseModel):
    post_id: Optional[int] = None
    user_id: Optional[int] = None
    message: str

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

class BlockUserRequest(BaseModel):
    isBlocked: bool
    blockReason: Optional[str] = None

class ReviewCreate(BaseModel):
    sellerId: int
    text: str
    rating: Annotated[int, Field(ge=1, le=5)]

class ReviewResponse(BaseModel):
    id: int
    sellerId: int
    authorId: int
    text: str
    rating: int
    createdAt: datetime
    
    class Config:
        orm_mode = True

class UserShortResponse(BaseModel):
    id: int
    nickname: str
    avatarBase64: Optional[str] = None

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

class VerificationUpdate(BaseModel):
    status: VerificationStatus

class PostOut(BaseModel):
    id: int
    title: str
    caption: Optional[str] = None
    createdAt: Optional[datetime] = None
    views: Optional[int] = 0

    class Config:
        orm_mode = True

class UserWithPosts(BaseModel):
    id: int
    name: str
    surname: str
    phone: Optional[str] = None
    email: str
    isVerified: bool
    isBlocked: bool
    blockReason: Optional[str] = None
    blockedAt: Optional[datetime] = None
    role: str
    createdAt: Optional[datetime] = None
    location: Optional[str] = None
    rating: Optional[float] = None
    reviewsCount: Optional[int] = 0
    posts: List[PostOut] = []

    class Config:
        orm_mode = True
