from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./pii_sanitizer.db"
    SECRET_KEY: str = "change-this-to-a-long-random-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    UPLOAD_DIR: str = "./uploads/raw"
    SANITIZED_DIR: str = "./uploads/sanitized"
    FERNET_KEY: str = ""
    # OCR settings (can override ocr_config.yaml via environment variables)
    OCR_USE_GPU: bool = False
    OCR_LANG: str = "en"
    OCR_CONFIDENCE_THRESHOLD: float = 0.5
    OCR_DPI: int = 300

    class Config:
        env_file = ".env"


settings = Settings()
