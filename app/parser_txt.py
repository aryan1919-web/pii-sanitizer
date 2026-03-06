from app.pii_engine import sanitize


def parse_txt(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    text = data.decode("utf-8", errors="replace")
    cleaned, count = sanitize(text, mode)
    return cleaned.encode("utf-8"), count
