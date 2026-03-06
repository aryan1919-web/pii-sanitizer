import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.database import engine, Base
from app.config import settings
from app.routes_auth import router as auth_router
from app.routes_files import router as files_router
from app.models import User, Role
from app.auth import hash_password
from app.database import SessionLocal


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(settings.SANITIZED_DIR, exist_ok=True)
    db = SessionLocal()
    if not db.query(User).filter(User.role == Role.ADMIN).first():
        db.add(User(username="admin", email="admin@local.dev", hashed_password=hash_password("admin123"), role=Role.ADMIN))
        db.commit()
    db.close()
    yield


app = FastAPI(title="PII Sanitizer", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(auth_router)
app.include_router(files_router)
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
