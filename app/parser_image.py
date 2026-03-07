import io
import uuid
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from app.pii_engine import detect_pii, _mask_value
from app.ocr_engine import run_ocr, preprocess_image, box_to_rect, postprocess_text

# Register HEIF opener if pillow-heif is installed (for .heic support)
try:
    from pillow_heif import register_heif_opener
    register_heif_opener()
except ImportError:
    pass

# ── font helpers ────────────────────────────────────────────
_FONT_NAMES = ["arial.ttf", "Arial.ttf", "consola.ttf", "cour.ttf",
               "DejaVuSans.ttf", "DejaVuSansMono.ttf"]


def _load_font(size: int):
    for name in _FONT_NAMES:
        try:
            return ImageFont.truetype(name, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


def _fit_font(text: str, max_w: int, max_h: int, draw: ImageDraw.ImageDraw):
    """Return a font sized so *text* fits inside max_w × max_h."""
    size = max(8, max_h - 2)
    for _ in range(40):
        font = _load_font(size)
        bbox = draw.textbbox((0, 0), text, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        if tw <= max_w and th <= max_h:
            return font
        size -= 1
        if size < 6:
            break
    return _load_font(max(6, size))


def _text_fits(text: str, max_w: int, max_h: int, draw: ImageDraw.ImageDraw) -> bool:
    """Check whether *text* can render at minimum font size inside the box."""
    font = _load_font(6)
    bbox = draw.textbbox((0, 0), text, font=font)
    return (bbox[2] - bbox[0]) <= max_w and (bbox[3] - bbox[1]) <= max_h


# ── background colour sampling ─────────────────────────────
def _sample_bg(img: Image.Image, x: int, y: int, w: int, h: int) -> tuple:
    """Sample the dominant background colour around a bounding box."""
    img_w, img_h = img.size
    pad = 4
    regions = []
    if y - pad >= 0:
        regions.append((max(0, x), max(0, y - pad), min(img_w, x + w), y))
    if y + h + pad <= img_h:
        regions.append((max(0, x), y + h, min(img_w, x + w), min(img_h, y + h + pad)))
    if x - pad >= 0:
        regions.append((max(0, x - pad), max(0, y), x, min(img_h, y + h)))
    if x + w + pad <= img_w:
        regions.append((x + w, max(0, y), min(img_w, x + w + pad), min(img_h, y + h)))

    pixels = []
    for r in regions:
        if r[2] > r[0] and r[3] > r[1]:
            crop = img.crop(r)
            arr = np.array(crop).reshape(-1, 3)
            pixels.append(arr)
    if pixels:
        all_px = np.concatenate(pixels, axis=0)
        median = np.median(all_px, axis=0).astype(int)
        return tuple(median)
    return (255, 255, 255)


# ── render helpers ─────────────────────────────────────────
def _draw_text_box(draw, x, y, w, h, text, bg, fill=(0, 0, 0), center=True):
    """Fill box with *bg*, render *text* fitted inside it."""
    if _text_fits(text, w, h, draw):
        draw.rectangle([x, y, x + w, y + h], fill=bg)
        font = _fit_font(text, w, h, draw)
        tb = draw.textbbox((0, 0), text, font=font)
        tw, th_ = tb[2] - tb[0], tb[3] - tb[1]
        tx = x + (w - tw) // 2 if center else x + 2
        ty = y + (h - th_) // 2
        draw.text((tx, ty), text, fill=fill, font=font)
    else:
        draw.rectangle([x, y, x + w, y + h], fill=(0, 0, 0))


# ── main entry point ───────────────────────────────────────
def parse_image(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    img = Image.open(io.BytesIO(data)).convert("RGB")

    # Preprocess for better OCR accuracy
    processed = preprocess_image(img)

    # PaddleOCR → line-level bounding boxes with text + confidence
    ocr_results = run_ocr(processed)
    if not ocr_results:
        return data, 0

    # Build reconstructed text with char→line mapping
    line_entries = []          # (char_start, char_end, line_index)
    full_parts: list[str] = []
    offset = 0
    for idx, entry in enumerate(ocr_results):
        text = entry["text"].strip()
        if not text:
            continue
        if full_parts:
            full_parts.append(" ")
            offset += 1
        line_entries.append((offset, offset + len(text), idx))
        full_parts.append(text)
        offset += len(text)

    full_text = postprocess_text("".join(full_parts))
    if not full_text.strip():
        return data, 0

    # Detect PII spans in the reconstructed text
    entities = detect_pii(full_text)
    if not entities:
        return data, 0

    # ── Entity-level rendering with PaddleOCR bounding boxes ──
    result = img.copy()
    draw = ImageDraw.Draw(result)

    for ent in entities:
        # Find OCR lines that overlap with this entity span
        for char_start, char_end, line_idx in line_entries:
            if char_start >= ent.end or char_end <= ent.start:
                continue

            entry = ocr_results[line_idx]
            line_text = entry["text"].strip()
            bx, by, bw, bh = box_to_rect(entry["box"])

            if bw < 2 or bh < 2:
                continue

            # Compute proportional sub-box within the line
            overlap_start = max(ent.start, char_start) - char_start
            overlap_end = min(ent.end, char_end) - char_start
            line_len = len(line_text)

            if line_len > 0:
                frac_start = overlap_start / line_len
                frac_end = overlap_end / line_len
            else:
                frac_start, frac_end = 0.0, 1.0

            sub_x = int(bx + frac_start * bw)
            sub_w = max(int((frac_end - frac_start) * bw), 2)
            sub_text = line_text[overlap_start:overlap_end]

            bg = _sample_bg(img, sub_x, by, sub_w, bh)

            if mode == "redact":
                _draw_text_box(draw, sub_x, by, sub_w, bh,
                               "[REDACTED]", bg, center=True)

            elif mode == "mask":
                masked = _mask_value(sub_text, ent.entity_type)
                _draw_text_box(draw, sub_x, by, sub_w, bh,
                               masked, bg, center=False)

            elif mode == "tokenize":
                token = "<" + str(uuid.uuid4())[:8] + ">"
                _draw_text_box(draw, sub_x, by, sub_w, bh,
                               token, bg, fill=(200, 0, 0),
                               center=True)
                _draw_text_box(draw, x1, y1, bw, bh,
                               token, bg, fill=(200, 0, 0),
                               center=True)

    # ── save in original format ─────────────────────────────
    orig_img = Image.open(io.BytesIO(data))
    fmt = (orig_img.format or "PNG").upper()
    buf = io.BytesIO()
    if fmt in ("JPEG", "JPG"):
        result.save(buf, format="JPEG", quality=95)
    else:
        result.save(buf, format="PNG")

    return buf.getvalue(), len(entities)
