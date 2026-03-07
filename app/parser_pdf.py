import io
import fitz
from PIL import Image
from app.pii_engine import sanitize
from app.ocr_engine import run_ocr_text, _load_config
from concurrent.futures import ThreadPoolExecutor


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
    # Collect all spans with their metadata first
    spans_info = []
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
                    spans_info.append({
                        "page_idx": i,
                        "text": text,
                        "bbox": span["bbox"],
                        "size": span["size"],
                    })

    if not spans_info:
        out = src.tobytes(deflate=True, garbage=4)
        src.close()
        return out, 0

    # Batch: join all texts with a unique separator, run ONE detect_pii call
    separator = "\n\x00\n"
    all_text = separator.join(s["text"] for s in spans_info)
    cleaned_text, total = sanitize(all_text, mode)

    if total > 0:
        # Split back into per-span cleaned texts
        cleaned_parts = cleaned_text.split(separator)
        for idx, span_info in enumerate(spans_info):
            if idx < len(cleaned_parts):
                cleaned = cleaned_parts[idx]
            else:
                cleaned = span_info["text"]
            if cleaned != span_info["text"]:
                page = src[span_info["page_idx"]]
                rect = fitz.Rect(span_info["bbox"])
                page.add_redact_annot(rect)
                page.apply_redactions()
                page.insert_textbox(
                    rect, cleaned,
                    fontsize=span_info["size"] * 0.9,
                    fontname="helv", color=(0, 0, 0),
                )

    out = src.tobytes(deflate=True, garbage=4)
    src.close()
    return out, total


def _process_scanned_pdf(src, mode: str) -> tuple[bytes, int]:
    pages = [src[i] for i in range(len(src))]
    # OCR pages in parallel
    with ThreadPoolExecutor(max_workers=min(4, len(pages))) as executor:
        all_text = list(executor.map(_ocr_page_to_text, pages))
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
