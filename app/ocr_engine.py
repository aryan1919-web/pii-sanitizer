"""
PaddleOCR Engine — self-hosted, GPU/CPU-configurable OCR pipeline.

Replaces pytesseract with PaddleOCR (PaddlePaddle) for higher-accuracy
multilingual OCR.  Supports image preprocessing, confidence filtering,
NFKC text normalisation, and per-language singleton instances.

Configuration is loaded from ``ocr_config.yaml`` in the project root.
"""

import logging
import unicodedata
import numpy as np
from PIL import Image, ImageFilter, ImageEnhance
from pathlib import Path
from threading import Lock

logger = logging.getLogger(__name__)

# ── Singleton state ─────────────────────────────────────────
_ocr_instances: dict = {}
_lock = Lock()
_config: dict | None = None


# ═══════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════

def _load_config() -> dict:
    """Load OCR configuration from ocr_config.yaml (cached)."""
    global _config
    if _config is not None:
        return _config

    config_path = Path(__file__).parent.parent / "ocr_config.yaml"
    if config_path.exists():
        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                _config = yaml.safe_load(f) or {}
        except ImportError:
            logger.warning("PyYAML not installed; using default OCR config")
            _config = {}
        except Exception as exc:
            logger.warning("Failed to load ocr_config.yaml: %s", exc)
            _config = {}
    else:
        _config = {}

    # ── merge defaults ──────────────────────────────────────
    defaults = {
        "use_gpu": False,
        "lang": "en",
        "det_db_threshold": 0.3,
        "rec_confidence_threshold": 0.5,
        "max_image_long_side": 960,
        "dpi": 300,
        "batch_size": 1,
        "use_structure": False,
        "concurrency": 4,
        "model": {
            "use_angle_cls": True,
        },
        "preprocessing": {
            "deskew": False,
            "denoise": False,
            "sharpen": False,
            "contrast_enhance": False,
            "binarization": None,
            "auto_crop_text_regions": False,
            "dpi_convert": 300,
        },
        "postprocessing": {
            "spellcheck": False,
            "language_model_correction": False,
            "confidence_threshold": 0.5,
        },
        "output_formats": ["txt", "json"],
        "save_path": "./ocr_outputs",
    }

    for key, val in defaults.items():
        if key not in _config:
            _config[key] = val
        elif isinstance(val, dict) and isinstance(_config.get(key), dict):
            for dk, dv in val.items():
                if dk not in _config[key]:
                    _config[key][dk] = dv

    return _config


# ═══════════════════════════════════════════════════════════
# OCR instance management
# ═══════════════════════════════════════════════════════════

def get_ocr(lang: str | None = None):
    """
    Return a **PaddleOCR** singleton for the requested language.

    Instances are cached per language string and created thread-safely.
    Models are auto-downloaded on first use.
    """
    config = _load_config()
    lang = lang or config.get("lang", "en")

    with _lock:
        if lang in _ocr_instances:
            return _ocr_instances[lang]

        try:
            from paddleocr import PaddleOCR
        except ImportError:
            raise ImportError(
                "PaddleOCR is not installed. Install with:\n"
                "  CPU:  pip install paddlepaddle paddleocr\n"
                "  GPU:  pip install paddlepaddle-gpu paddleocr"
            )

        model_cfg = config.get("model", {})
        ocr = PaddleOCR(
            use_angle_cls=model_cfg.get("use_angle_cls", True),
            lang=lang,
            use_gpu=config.get("use_gpu", False),
            det_db_thresh=config.get("det_db_threshold", 0.3),
            enable_mkldnn=False,
            show_log=False,
        )
        _ocr_instances[lang] = ocr
        logger.info(
            "PaddleOCR initialised (GPU=%s, lang=%s)",
            config.get("use_gpu"),
            lang,
        )
        return ocr


# ═══════════════════════════════════════════════════════════
# Image preprocessing
# ═══════════════════════════════════════════════════════════

def preprocess_image(img: Image.Image) -> Image.Image:
    """
    Apply configured preprocessing steps to *img* before OCR.

    Order: contrast → sharpen → denoise → binarise → deskew.
    """
    config = _load_config()
    pp = config.get("preprocessing", {})

    if pp.get("contrast_enhance"):
        img = ImageEnhance.Contrast(img).enhance(1.5)

    if pp.get("sharpen"):
        img = img.filter(ImageFilter.SHARPEN)

    if pp.get("denoise"):
        img = img.filter(ImageFilter.MedianFilter(size=3))

    binarization = pp.get("binarization")
    if binarization in ("otsu", "adaptive"):
        try:
            import cv2

            gray = np.array(img.convert("L"))
            if binarization == "otsu":
                _, binary = cv2.threshold(
                    gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
                )
            else:
                binary = cv2.adaptiveThreshold(
                    gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                    cv2.THRESH_BINARY, 11, 2,
                )
            img = Image.fromarray(binary).convert("RGB")
        except ImportError:
            logger.warning("opencv-python not installed; skipping binarisation")

    if pp.get("deskew"):
        try:
            import cv2

            gray = np.array(img.convert("L"))
            coords = np.column_stack(np.where(gray < 128))
            if len(coords) > 100:
                angle = cv2.minAreaRect(coords)[-1]
                if angle < -45:
                    angle = -(90 + angle)
                else:
                    angle = -angle
                if abs(angle) > 0.5:
                    h, w = gray.shape
                    center = (w // 2, h // 2)
                    M = cv2.getRotationMatrix2D(center, angle, 1.0)
                    rotated = cv2.warpAffine(
                        np.array(img), M, (w, h),
                        flags=cv2.INTER_CUBIC,
                        borderMode=cv2.BORDER_REPLICATE,
                    )
                    img = Image.fromarray(rotated)
        except ImportError:
            logger.warning("opencv-python not installed; skipping deskew")

    return img


# ═══════════════════════════════════════════════════════════
# Core OCR functions
# ═══════════════════════════════════════════════════════════

def run_ocr(
    img: Image.Image,
    lang: str | None = None,
    conf_threshold: float | None = None,
) -> list[dict]:
    """
    Run PaddleOCR on a PIL Image.

    Returns a list of dicts, each containing:
        ``box``  – quadrilateral [[x1,y1], [x2,y2], [x3,y3], [x4,y4]]
        ``text`` – recognised string
        ``confidence`` – float 0-1

    Results below *conf_threshold* are filtered out.
    """
    config = _load_config()
    if conf_threshold is None:
        conf_threshold = config.get("rec_confidence_threshold", 0.5)

    ocr = get_ocr(lang)
    img_array = np.array(img.convert("RGB"))

    result = ocr.ocr(img_array, cls=True)

    if not result or not result[0]:
        return []

    entries: list[dict] = []
    for line in result[0]:
        if line is None:
            continue
        box = line[0]
        text = line[1][0]
        conf = float(line[1][1])
        if conf >= conf_threshold:
            entries.append({"box": box, "text": text, "confidence": conf})

    return entries


def run_ocr_text(
    img: Image.Image,
    lang: str | None = None,
    conf_threshold: float | None = None,
) -> str:
    """Run OCR and return concatenated text (newline-separated lines)."""
    entries = run_ocr(img, lang, conf_threshold)
    text = "\n".join(e["text"] for e in entries)
    return postprocess_text(text)


# ═══════════════════════════════════════════════════════════
# PP-Structure (optional table/form parsing)
# ═══════════════════════════════════════════════════════════

def run_structure(img: Image.Image, lang: str | None = None) -> list[dict]:
    """
    Run PP-Structure on a PIL Image for table/form layout analysis.

    Returns list of detected regions with type, bbox, and extracted content.
    Only called when ``use_structure: true`` in config.
    """
    config = _load_config()
    lang = lang or config.get("lang", "en")

    try:
        from paddleocr import PPStructure
    except ImportError:
        logger.warning("PPStructure not available in this paddleocr version")
        return []

    engine = PPStructure(
        show_log=False,
        lang=lang,
        use_gpu=config.get("use_gpu", False),
    )
    img_array = np.array(img.convert("RGB"))
    result = engine(img_array)

    if not result:
        return []

    entries = []
    for region in result:
        entries.append({
            "type": region.get("type", "unknown"),
            "bbox": region.get("bbox", []),
            "res": region.get("res", ""),
        })
    return entries


# ═══════════════════════════════════════════════════════════
# Post-processing helpers
# ═══════════════════════════════════════════════════════════

def postprocess_text(text: str) -> str:
    """Normalise OCR output (NFKC, whitespace cleanup)."""
    text = unicodedata.normalize("NFKC", text)
    lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(lines)


def box_to_rect(box) -> tuple[int, int, int, int]:
    """
    Convert PaddleOCR quadrilateral to axis-aligned ``(x, y, w, h)``.

    *box*: [[x1,y1], [x2,y2], [x3,y3], [x4,y4]]
    """
    xs = [p[0] for p in box]
    ys = [p[1] for p in box]
    x1, y1 = int(min(xs)), int(min(ys))
    x2, y2 = int(max(xs)), int(max(ys))
    return x1, y1, max(1, x2 - x1), max(1, y2 - y1)
