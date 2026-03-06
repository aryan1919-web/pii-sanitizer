from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./pii_sanitizer.db"
    SECRET_KEY: str = "change-this-to-a-long-random-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    UPLOAD_DIR: str = "./uploads/raw"
    SANITIZED_DIR: str = "./uploads/sanitized"
    FERNET_KEY: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
