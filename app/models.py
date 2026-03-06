import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base
import enum


class Role(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class ActionType(str, enum.Enum):
    UPLOAD = "upload"
    LOGIN = "login"
    DOWNLOAD = "download"
    PII_DETECTION = "pii_detection"
    USER_CREATED = "user_created"
    VIEW = "view"
    FILE_REJECTED = "file_rejected"
    FILE_TAMPERED = "file_tampered"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(SAEnum(Role), default=Role.USER)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    files: Mapped[list["File"]] = relationship(back_populates="owner")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")


class File(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename: Mapped[str] = mapped_column(String(255))
    encrypted_path: Mapped[str] = mapped_column(Text)
    sanitized_path: Mapped[str] = mapped_column(Text, nullable=True)
    upload_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    mode: Mapped[str] = mapped_column(String(20), default="redact")
    pii_count: Mapped[int] = mapped_column(default=0)
    original_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    sanitized_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner: Mapped["User"] = relationship(back_populates="files")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(SAEnum(ActionType))
    target_file: Mapped[str] = mapped_column(String(255), nullable=True)
    details: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship(back_populates="audit_logs")
