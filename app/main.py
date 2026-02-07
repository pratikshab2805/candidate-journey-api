# app/main.py

from enum import Enum
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import (
    Column, Integer, String, Enum as SqlEnum,
    ForeignKey, DateTime, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
DATABASE_URL = "sqlite:///./database.db"
SECRET_KEY = "secret-key-change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -------------------------------------------------------------------
# Database setup
# -------------------------------------------------------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# -------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------
class Role(str, Enum):
    recruiter = "RECRUITER"
    candidate = "CANDIDATE"

class Stage(str, Enum):
    applied = "APPLIED"
    screening = "SCREENING"
    interview = "INTERVIEW"
    hired = "HIRED"
    rejected = "REJECTED"

PIPELINE = [
    Stage.applied,
    Stage.screening,
    Stage.interview,
    Stage.hired,
]

# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(SqlEnum(Role))
    created_at = Column(DateTime, default=datetime.utcnow)

    candidate = relationship("Candidate", back_populates="user", uselist=False)

class Candidate(Base):
    __tablename__ = "candidates"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)
    role_applied = Column(String)
    resume_text = Column(String)
    stage = Column(SqlEnum(Stage), default=Stage.applied)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="candidate")

Base.metadata.create_all(bind=engine)

# -------------------------------------------------------------------
# Auth utilities
# -------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401)
    return user

def recruiter_only(user: User = Depends(get_current_user)):
    if user.role != Role.recruiter:
        raise HTTPException(status_code=403, detail="Recruiter access only")
    return user

# -------------------------------------------------------------------
# Schemas
# -------------------------------------------------------------------
class CandidateCreate(BaseModel):
    name: str
    email: EmailStr
    role_applied: str
    resume_text: str

class CandidateOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    role_applied: str
    resume_text: str
    stage: Stage

    class Config:
        orm_mode = True

# -------------------------------------------------------------------
# App
# -------------------------------------------------------------------
app = FastAPI(title="Candidate Journey Management API")

# -------------------------------------------------------------------
# Auth endpoint
# -------------------------------------------------------------------
@app.post("/auth/login")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user.id})
    return {"access_token": token, "token_type": "bearer"}

# -------------------------------------------------------------------
# Candidate CRUD (Recruiter)
# -------------------------------------------------------------------
@app.post("/candidates", response_model=CandidateOut)
def create_candidate(
    data: CandidateCreate,
    db: Session = Depends(get_db),
    _: User = Depends(recruiter_only),
):
    user = User(
        name=data.name,
        email=data.email,
        password=hash_password("changeme"),
        role=Role.candidate,
    )
    candidate = Candidate(**data.dict(), user=user)
    db.add_all([user, candidate])
    db.commit()
    db.refresh(candidate)
    return candidate

@app.get("/candidates", response_model=list[CandidateOut])
def list_candidates(
    db: Session = Depends(get_db),
    _: User = Depends(recruiter_only),
):
    return db.query(Candidate).all()

@app.get("/candidates/{candidate_id}", response_model=CandidateOut)
def get_candidate(
    candidate_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(recruiter_only),
):
    candidate = db.get(Candidate, candidate_id)
    if not candidate:
        raise HTTPException(status_code=404)
    return candidate

# -------------------------------------------------------------------
# Candidate self view
# -------------------------------------------------------------------
@app.get("/me/candidate", response_model=CandidateOut)
def my_profile(user: User = Depends(get_current_user)):
    if user.role != Role.candidate or not user.candidate:
        raise HTTPException(status_code=403)
    return user.candidate

# -------------------------------------------------------------------
# Pipeline actions
# -------------------------------------------------------------------
@app.post("/candidates/{candidate_id}/advance", response_model=CandidateOut)
def advance_stage(
    candidate_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(recruiter_only),
):
    candidate = db.get(Candidate, candidate_id)
    if not candidate or candidate.stage in [Stage.hired, Stage.rejected]:
        raise HTTPException(status_code=400)

    index = PIPELINE.index(candidate.stage)
    candidate.stage = PIPELINE[index + 1]
    db.commit()
    db.refresh(candidate)
    return candidate

@app.post("/candidates/{candidate_id}/reject", response_model=CandidateOut)
def reject_candidate(
    candidate_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(recruiter_only),
):
    candidate = db.get(Candidate, candidate_id)
    if not candidate:
        raise HTTPException(status_code=404)

    candidate.stage = Stage.rejected
    db.commit()
    db.refresh(candidate)
    return candidate

