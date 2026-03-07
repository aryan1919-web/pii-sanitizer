"""
File-format conversion utilities for the OCR / PII pipeline.

Handles conversion of non-native formats to images or text
so they can be processed by PaddleOCR or the text parsers.
"""

import io
import os
import logging
import subprocess
import tempfile
from PIL import Image

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# Image format conversion
# ═══════════════════════════════════════════════════════════

def convert_image_to_rgb(data: bytes) -> Image.Image:
    """Open any Pillow-supported image and return as RGB PIL Image."""
    img = Image.open(io.BytesIO(data))
    if img.mode in ("RGBA", "LA", "PA", "P"):
        background = Image.new("RGB", img.size, (255, 255, 255))
        if img.mode == "P":
            img = img.convert("RGBA")
        if "A" in img.mode:
            background.paste(img, mask=img.split()[-1])
        else:
            background.paste(img)
        return background
    return img.convert("RGB")


def convert_heic_to_image(data: bytes) -> Image.Image:
    """Convert HEIC/HEIF data to an RGB PIL Image."""
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
    except ImportError:
        raise ImportError(
            "pillow-heif is required for HEIC support. "
            "Install with: pip install pillow-heif"
        )
    return Image.open(io.BytesIO(data)).convert("RGB")


def convert_gif_first_frame(data: bytes) -> Image.Image:
    """Extract the first frame of a GIF and return as RGB."""
    img = Image.open(io.BytesIO(data))
    img.seek(0)
    return img.convert("RGB")


# ═══════════════════════════════════════════════════════════
# Office document conversion (LibreOffice headless)
# ═══════════════════════════════════════════════════════════

def convert_office_to_pdf(data: bytes, ext: str) -> bytes:
    """
    Convert an office document (.doc, .ppt, .pptx) to PDF bytes
    using LibreOffice in headless mode.

    Raises RuntimeError if LibreOffice is not installed or conversion fails.
    """
    suffix = ext if ext.startswith(".") else f".{ext}"

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, f"input{suffix}")
        with open(input_path, "wb") as f:
            f.write(data)

        for cmd in ("soffice", "libreoffice"):
            try:
                result = subprocess.run(
                    [
                        cmd, "--headless", "--convert-to", "pdf",
                        "--outdir", tmpdir, input_path,
                    ],
                    capture_output=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    pdf_path = os.path.join(tmpdir, "input.pdf")
                    if os.path.exists(pdf_path):
                        with open(pdf_path, "rb") as f:
                            return f.read()
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                logger.warning("LibreOffice conversion timed out for %s", ext)
                continue

        raise RuntimeError(
            "LibreOffice is required for .doc / .ppt / .pptx conversion. "
            "Install LibreOffice and ensure 'soffice' is in your PATH."
        )


# ═══════════════════════════════════════════════════════════
# PDF to images  (via PyMuPDF — already a project dependency)
# ═══════════════════════════════════════════════════════════

def pdf_pages_to_images(data: bytes, dpi: int = 300) -> list[Image.Image]:
    """
    Render every page of a PDF to a PIL Image at the given DPI.

    Uses PyMuPDF (fitz) which is already installed as a project dependency.
    """
    import fitz

    doc = fitz.open(stream=data, filetype="pdf")
    images: list[Image.Image] = []
    for page in doc:
        pix = page.get_pixmap(dpi=dpi)
        img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
        images.append(img)
    doc.close()
    return images
