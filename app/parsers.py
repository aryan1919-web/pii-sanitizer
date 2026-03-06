from fastapi import HTTPException
from app.parser_docx import parse_docx
from app.parser_pdf import parse_pdf
from app.parser_sql import parse_sql
from app.parser_data import parse_csv, parse_json
from app.parser_txt import parse_txt
from app.parser_image import parse_image
from app.parser_xlsx import parse_xlsx

PARSERS = {
    ".docx": parse_docx,
    ".pdf": parse_pdf,
    ".sql": parse_sql,
    ".csv": parse_csv,
    ".json": parse_json,
    ".txt": parse_txt,
    ".xlsx": parse_xlsx,
    ".xls": parse_xlsx,
    ".png": parse_image,
    ".jpg": parse_image,
    ".jpeg": parse_image,
}

ALLOWED_EXTENSIONS = set(PARSERS.keys())


def get_extension(filename: str) -> str:
    return "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def process_file(data: bytes, filename: str, mode: str = "redact") -> tuple[bytes, int]:
    ext = get_extension(filename)
    if ext not in PARSERS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {ext}")
    return PARSERS[ext](data, mode)
