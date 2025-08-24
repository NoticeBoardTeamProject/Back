import os

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
SMTP_USER = "bodyaraz7@gmail.com"
SMTP_PASS = "hqmmpdzlupuyvijl"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, '../bulletin_board.db')}"
BASE_URL = "https://api.beez.pp.ua"