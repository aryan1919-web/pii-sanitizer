from fastapi import HTTPException
from app.parser_docx import parse_docx
from app.parser_pdf import parse_pdf
from app.parser_sql import parse_sql
from app.parser_data import parse_csv, parse_json
from app.parser_txt import parse_txt
from app.parser_image import parse_image
from app.parser_xlsx import parse_xlsx
from app.parser_pptx import parse_pptx


def _parse_office_via_pdf(data: bytes, mode: str, ext: str) -> tuple[bytes, int]:
    """Convert .doc/.ppt to PDF via LibreOffice, then process as PDF."""
    from app.converter import convert_office_to_pdf
    pdf_data = convert_office_to_pdf(data, ext)
    return parse_pdf(pdf_data, mode)


def parse_doc(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    return _parse_office_via_pdf(data, mode, ".doc")


def parse_ppt(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    return _parse_office_via_pdf(data, mode, ".ppt")


PARSERS = {
    # Text / data files (read directly — no OCR)
    ".txt":  parse_txt,
    ".csv":  parse_csv,
    ".json": parse_json,
    ".xml":  parse_txt,
    ".sql":  parse_sql,
    # Office documents (direct text extraction)
    ".docx": parse_docx,
    ".xlsx": parse_xlsx,
    ".xls":  parse_xlsx,
    ".pptx": parse_pptx,
    # Office legacy (LibreOffice conversion → PDF → OCR)
    ".doc":  parse_doc,
    ".ppt":  parse_ppt,
    # PDF (text extraction or OCR fallback)
    ".pdf":  parse_pdf,
    # Images (PaddleOCR)
    ".png":  parse_image,
    ".jpg":  parse_image,
    ".jpeg": parse_image,
    ".tiff": parse_image,
    ".tif":  parse_image,
    ".bmp":  parse_image,
    ".webp": parse_image,
    ".gif":  parse_image,
    ".heic": parse_image,
}

ALLOWED_EXTENSIONS = set(PARSERS.keys())


def get_extension(filename: str) -> str:
    return "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def process_file(data: bytes, filename: str, mode: str = "redact") -> tuple[bytes, int]:
    ext = get_extension(filename)
    if ext not in PARSERS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {ext}")
    return PARSERS[ext](data, mode)
