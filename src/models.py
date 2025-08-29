from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Enum as SQLEnum, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum, IntEnum
from database import Base

class CurrencyEnum(str, Enum):
    UAH = "UAH"
    EUR = "EUR"
    USD = "USD"

class CityEnum(str, Enum):
    Kyiv = "Kyiv, Kyiv Oblast"
    Kharkiv = "Kharkiv, Kharkiv Oblast"
    Odesa = "Odesa, Odesa Oblast"
    Dnipro = "Dnipro, Dnipropetrovsk Oblast"
    Donetsk = "Donetsk, Donetsk Oblast"
    Zaporizhzhia = "Zaporizhzhia, Zaporizhzhia Oblast"
    Lviv = "Lviv, Lviv Oblast"
    Kryvyi_Rih = "Kryvyi Rih, Dnipropetrovsk Oblast"
    Mykolaiv = "Mykolaiv, Mykolaiv Oblast"
    Mariupol = "Mariupol, Donetsk Oblast"
    Luhansk = "Luhansk, Luhansk Oblast"
    Vinnytsia = "Vinnytsia, Vinnytsia Oblast"
    Makiivka = "Makiivka, Donetsk Oblast"
    Sevastopol = "Sevastopol, Crimea"
    Simferopol = "Simferopol, Crimea"
    Kherson = "Kherson, Kherson Oblast"
    Poltava = "Poltava, Poltava Oblast"
    Chernihiv = "Chernihiv, Chernihiv Oblast"
    Cherkasy = "Cherkasy, Cherkasy Oblast"
    Sumy = "Sumy, Sumy Oblast"
    Zhytomyr = "Zhytomyr, Zhytomyr Oblast"
    Horlivka = "Horlivka, Donetsk Oblast"
    Rivne = "Rivne, Rivne Oblast"
    Kropyvnytskyi = "Kropyvnytskyi, Kirovohrad Oblast"
    Kamianske = "Kamianske, Dnipropetrovsk Oblast"
    Chernivtsi = "Chernivtsi, Chernivtsi Oblast"
    Ternopil = "Ternopil, Ternopil Oblast"
    Ivano_Frankivsk = "Ivano-Frankivsk, Ivano-Frankivsk Oblast"
    Bila_Tserkva = "Bila Tserkva, Kyiv Oblast"
    Melitopol = "Melitopol, Zaporizhzhia Oblast"
    Kerch = "Kerch, Crimea"
    Sloviansk = "Sloviansk, Donetsk Oblast"
    Berdyansk = "Berdyansk, Zaporizhzhia Oblast"
    Uzhhorod = "Uzhhorod, Zakarpattia Oblast"
    Kramatorsk = "Kramatorsk, Donetsk Oblast"
    Nizhyn = "Nizhyn, Chernihiv Oblast"
    Fastiv = "Fastiv, Kyiv Oblast"

class CloseReason(str, Enum):
    sold = "sold"
    not_relevant = "not_relevant"
    mistake = "mistake"

class RatingEnum(IntEnum):
    one = 1
    two = 2
    three = 3
    four = 4
    five = 5

class ScamStatus(str, Enum):
    scam = "swindler"
    not_scam = "no swindler"

class VerificationStatus(str, Enum):
    approved = "approved"
    rejected = "rejected"

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
    location = Column(String, nullable=True)
    rating = Column(Float, nullable=True, default=0.0)
    reviewsCount = Column(Integer, nullable=True, default=0)
    
    posts = relationship("Post", back_populates="user")

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
    is_scam = Column(Boolean, default=None, nullable=True)
    isUsed = Column(Boolean, nullable=False, default=False)  
    currency = Column(SQLEnum(CurrencyEnum), nullable=False, default=CurrencyEnum.UAH)
    location = Column(SQLEnum(CityEnum), nullable=False)
    isClosed = Column(Boolean, default=False)
    closeReason = Column(String, nullable=True)
    userId = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"))  
    user = relationship("User", back_populates="posts")
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

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    sellerId = Column(Integer, ForeignKey("users.id"), nullable=False)
    authorId = Column(Integer, ForeignKey("users.id"), nullable=False)
    text = Column(Text, nullable=False)
    rating = Column(Integer, nullable=False)
    createdAt = Column(DateTime, default=datetime.utcnow)
    seller = relationship("User", foreign_keys=[sellerId])
    author = relationship("User", foreign_keys=[authorId])

class FavoriteCategory(Base):
    __tablename__ = "favorite_categories"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"))
    user = relationship("User")
    category = relationship("Category")

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

class VerificationRequest(Base):
    __tablename__ = "verification_requests"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    images = Column(String)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User")
