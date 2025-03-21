from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Base, User, Product
from auth import hash_password, verify_password, create_jwt, verify_jwt
from pydantic import BaseModel

app = FastAPI()

# Create database tables
Base.metadata.create_all(bind=engine)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User Signup Schema
class SignUpSchema(BaseModel):
    name: str
    username: str
    password: str

# User Login Schema
class LoginSchema(BaseModel):
    username: str
    password: str

# User Signup
@app.post("/signup")
def signup(user: SignUpSchema, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    hashed_password = hash_password(user.password)
    new_user = User(name=user.name, username=user.username, password=hashed_password)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

# User Login
@app.post("/login")
def login(credentials: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt(user.id)
    return {"token": token}

# Middleware for JWT authentication
def get_current_user(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Token missing")
    
    token = authorization.split(" ")[1]
    payload = verify_jwt(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return payload["user_id"]

# Protected Route (Example)
@app.get("/protected")
def protected_route(user_id: int = Depends(get_current_user)):
    return {"message": "You have accessed a protected route", "user_id": user_id}

