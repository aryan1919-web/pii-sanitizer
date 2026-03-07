import io
import fitz
from PIL import Image
from app.pii_engine import sanitize
from app.ocr_engine import run_ocr_text, _load_config


def _has_selectable_text(doc) -> bool:
    for i in range(len(doc)):
        if doc[i].get_text("text").strip():
            return True
    return False


def _ocr_page_to_text(page) -> str:
    """Render a PDF page to an image and run PaddleOCR on it."""
    config = _load_config()
    dpi = config.get("dpi", 300)
    pix = page.get_pixmap(dpi=dpi)
    img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
    return run_ocr_text(img)


def _process_text_pdf(src, mode: str) -> tuple[bytes, int]:
    total = 0
    for i in range(len(src)):
        page = src[i]
        blocks = page.get_text("dict")["blocks"]
        for block in blocks:
            if block["type"] != 0:
                continue
            for line in block["lines"]:
                for span in line["spans"]:
                    text = span["text"]
                    if not text.strip():
                        continue
                    cleaned, c = sanitize(text, mode)
                    total += c
                    if c > 0:
                        rect = fitz.Rect(span["bbox"])
                        page.add_redact_annot(rect)
                        page.apply_redactions()
                        page.insert_textbox(
                            rect, cleaned,
                            fontsize=span["size"] * 0.9,
                            fontname="helv", color=(0, 0, 0),
                        )
    out = src.tobytes(deflate=True, garbage=4)
    src.close()
    return out, total


def _process_scanned_pdf(src, mode: str) -> tuple[bytes, int]:
    all_text = []
    for i in range(len(src)):
        all_text.append(_ocr_page_to_text(src[i]))
    src.close()
    full_text = "\n".join(all_text)
    if not full_text.strip():
        return b"", 0
    cleaned, count = sanitize(full_text, mode)
    new_doc = fitz.open()
    for page_text in cleaned.split("\n\n---PAGE_BREAK---\n\n") if "---PAGE_BREAK---" in cleaned else [cleaned]:
        page = new_doc.new_page(width=595, height=842)
        page.insert_textbox(
            fitz.Rect(50, 50, 545, 792),
            page_text, fontsize=11, fontname="helv", color=(0, 0, 0),
        )
    out = new_doc.tobytes(deflate=True, garbage=4)
    new_doc.close()
    return out, count


def parse_pdf(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    src = fitz.open(stream=data, filetype="pdf")
    if _has_selectable_text(src):
        return _process_text_pdf(src, mode)
    return _process_scanned_pdf(src, mode)
