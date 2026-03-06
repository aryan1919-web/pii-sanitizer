import io
import os
import pytesseract
from PIL import Image
from app.pii_engine import sanitize

for _p in [r"C:\Program Files\Tesseract-OCR\tesseract.exe", r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"]:
    if os.path.exists(_p):
        pytesseract.pytesseract.tesseract_cmd = _p
        break


def parse_image(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    img = Image.open(io.BytesIO(data))
    text = pytesseract.image_to_string(img)
    if not text.strip():
        return data, 0
    cleaned, count = sanitize(text, mode)
    return cleaned.encode("utf-8"), count
