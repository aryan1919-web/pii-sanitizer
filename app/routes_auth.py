from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Role, ActionType
from app.schemas import UserCreate, UserOut, Token, LoginRequest, AuditLogOut
from app.auth import hash_password, verify_password, create_access_token, get_current_user, require_admin, log_action

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register", response_model=UserOut, status_code=201)
def register(body: UserCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if db.query(User).filter((User.username == body.username) | (User.email == body.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    user = User(username=body.username, email=body.email, hashed_password=hash_password(body.password), role=body.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, admin.id, ActionType.USER_CREATED, details=f"Created user {user.username}")
    return user


@router.post("/login", response_model=Token)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    log_action(db, user.id, ActionType.LOGIN)
    return Token(access_token=create_access_token({"sub": user.id, "role": user.role.value}))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(User).all()


@router.get("/logs", response_model=list[AuditLogOut])
def get_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    from app.models import AuditLog
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
