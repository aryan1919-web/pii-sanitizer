import os
import uuid
import hashlib
import asyncio
from functools import partial
from fastapi import APIRouter, Depends, UploadFile, File as FastAPIFile, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, File, ActionType, Role
from app.schemas import FileOut
from app.auth import get_current_user, require_admin, log_action
from app.encryption import encrypt_bytes, decrypt_bytes
from app.parsers import process_file, get_extension
from app.security import scan_file
from app.config import settings

router = APIRouter(prefix="/files", tags=["Files"])

MIME_MAP = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".ppt": "application/vnd.ms-powerpoint",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xls": "application/vnd.ms-excel",
    ".sql": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".txt": "text/plain",
    ".xml": "text/xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".tiff": "image/tiff",
    ".tif": "image/tiff",
    ".bmp": "image/bmp",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".heic": "image/heic",
}


@router.post("/upload", response_model=FileOut, status_code=201)
async def upload(
    file: UploadFile = FastAPIFile(...),
    mode: str = Query("redact", regex="^(redact|mask|tokenize)$"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    raw = await file.read()
    orig_hash = hashlib.sha256(raw).hexdigest()

    # Security scan — reject malicious files before processing
    is_safe, reject_reason = scan_file(file.filename, raw)
    if not is_safe:
        log_action(db, user.id, ActionType.FILE_REJECTED, target_file=file.filename, details=reject_reason)
        raise HTTPException(status_code=400, detail=f"File rejected: {reject_reason}")

    encrypted = encrypt_bytes(raw)
    file_id = str(uuid.uuid4())
    ext = get_extension(file.filename)
    enc_path = os.path.join(settings.UPLOAD_DIR, f"{file_id}{ext}.enc")
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    with open(enc_path, "wb") as f:
        f.write(encrypted)

    log_action(db, user.id, ActionType.UPLOAD, target_file=file.filename)

    # Run heavy processing in thread pool to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    sanitized_data, pii_count = await loop.run_in_executor(
        None, partial(process_file, raw, file.filename, mode)
    )
    san_hash = hashlib.sha256(sanitized_data).hexdigest()
    san_path = os.path.join(settings.SANITIZED_DIR, f"{file_id}{ext}")
    os.makedirs(settings.SANITIZED_DIR, exist_ok=True)
    with open(san_path, "wb") as f:
        f.write(sanitized_data)

    log_action(db, user.id, ActionType.PII_DETECTION, target_file=file.filename, details=f"Detected {pii_count} PII entities, mode={mode}")

    db_file = File(
        id=file_id,
        original_filename=file.filename,
        encrypted_path=enc_path,
        sanitized_path=san_path,
        upload_by=user.id,
        mode=mode,
        pii_count=pii_count,
        original_hash=orig_hash,
        sanitized_hash=san_hash,
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    return db_file


@router.get("/", response_model=list[FileOut])
def list_files(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == Role.ADMIN:
        # Admin sees every file
        return db.query(File).order_by(File.created_at.desc()).all()
    # Regular user sees own uploads + all admin uploads
    admin_ids = [u.id for u in db.query(User).filter(User.role == Role.ADMIN).all()]
    return (
        db.query(File)
        .filter((File.upload_by == user.id) | (File.upload_by.in_(admin_ids)))
        .order_by(File.created_at.desc())
        .all()
    )


@router.get("/{file_id}/download")
def download_sanitized(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rec = db.query(File).filter(File.id == file_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="File not found")
    # Access control: user can download own files + admin-uploaded files
    if user.role != Role.ADMIN:
        uploader = db.query(User).filter(User.id == rec.upload_by).first()
        if rec.upload_by != user.id and (not uploader or uploader.role != Role.ADMIN):
            raise HTTPException(status_code=403, detail="Access denied")
    if not rec.sanitized_path or not os.path.exists(rec.sanitized_path):
        raise HTTPException(status_code=404, detail="Sanitized file not available")
    with open(rec.sanitized_path, "rb") as f:
        data = f.read()
    # Integrity check
    if rec.sanitized_hash:
        actual = hashlib.sha256(data).hexdigest()
        if actual != rec.sanitized_hash:
            log_action(db, user.id, ActionType.FILE_TAMPERED, target_file=rec.original_filename,
                       details=f"Sanitized file tampered. Expected: {rec.sanitized_hash}, Actual: {actual}")
            raise HTTPException(status_code=409, detail="File integrity check failed — sanitized file has been tampered with")
    ext = get_extension(rec.original_filename)
    log_action(db, user.id, ActionType.DOWNLOAD, target_file=rec.original_filename)
    return Response(content=data, media_type=MIME_MAP.get(ext, "application/octet-stream"),
                    headers={"Content-Disposition": f'attachment; filename="sanitized_{rec.original_filename}"'})


@router.get("/{file_id}/raw")
def download_raw(file_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rec = db.query(File).filter(File.id == file_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="File not found")
    if not os.path.exists(rec.encrypted_path):
        raise HTTPException(status_code=404, detail="Raw file not available")
    with open(rec.encrypted_path, "rb") as f:
        encrypted = f.read()
    data = decrypt_bytes(encrypted)
    # Integrity check
    if rec.original_hash:
        actual = hashlib.sha256(data).hexdigest()
        if actual != rec.original_hash:
            log_action(db, admin.id, ActionType.FILE_TAMPERED, target_file=rec.original_filename,
                       details=f"Original file tampered. Expected: {rec.original_hash}, Actual: {actual}")
            raise HTTPException(status_code=409, detail="File integrity check failed — original file has been tampered with")
    ext = get_extension(rec.original_filename)
    log_action(db, admin.id, ActionType.VIEW, target_file=rec.original_filename)
    return Response(content=data, media_type=MIME_MAP.get(ext, "application/octet-stream"),
                    headers={"Content-Disposition": f'attachment; filename="{rec.original_filename}"'})


@router.get("/{file_id}/verify")
def verify_file(file_id: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rec = db.query(File).filter(File.id == file_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="File not found")
    result = {"file_id": file_id, "filename": rec.original_filename, "original": None, "sanitized": None}
    # Check sanitized file
    if rec.sanitized_path and os.path.exists(rec.sanitized_path):
        with open(rec.sanitized_path, "rb") as f:
            data = f.read()
        actual = hashlib.sha256(data).hexdigest()
        result["sanitized"] = "intact" if actual == rec.sanitized_hash else "tampered"
    else:
        result["sanitized"] = "missing"
    # Check original (encrypted) file
    if rec.encrypted_path and os.path.exists(rec.encrypted_path):
        with open(rec.encrypted_path, "rb") as f:
            encrypted = f.read()
        data = decrypt_bytes(encrypted)
        actual = hashlib.sha256(data).hexdigest()
        result["original"] = "intact" if actual == rec.original_hash else "tampered"
    else:
        result["original"] = "missing"
    if result["original"] == "tampered" or result["sanitized"] == "tampered":
        log_action(db, admin.id, ActionType.FILE_TAMPERED, target_file=rec.original_filename,
                   details=f"Integrity check: original={result['original']}, sanitized={result['sanitized']}")
    return result


@router.delete("/{file_id}", status_code=204)
def delete_file(file_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rec = db.query(File).filter(File.id == file_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="File not found")
    if user.role != Role.ADMIN and rec.upload_by != user.id:
        raise HTTPException(status_code=403, detail="Not allowed to delete this file")
    for path in [rec.encrypted_path, rec.sanitized_path]:
        if path and os.path.exists(path):
            os.remove(path)
    db.delete(rec)
    db.commit()
