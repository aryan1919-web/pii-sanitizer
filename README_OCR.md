# PaddleOCR Integration — Installation & Configuration

## Overview

This project uses **PaddleOCR** (PaddlePaddle) as the self-hosted OCR engine,
replacing the previous pytesseract/Tesseract integration. PaddleOCR provides
higher accuracy, multilingual support, and GPU acceleration.

### Key Features

- **PP-OCRv4** detection + recognition (DB detector, SVTR recogniser)
- **80+ languages** including English, Hindi, Chinese, French, German, etc.
- **GPU / CPU configurable** — runs on CPU by default, optional CUDA GPU acceleration
- **Preprocessing pipeline** — deskew, denoise, sharpen, contrast enhance, binarisation
- **Confidence filtering** — configurable threshold to drop low-quality results
- **PP-Structure** (optional) — table and form layout analysis
- **Multi-format support** — PNG, JPG, TIFF, BMP, WebP, GIF, HEIC, PDF, DOCX, PPTX, XLSX, and more

---

## Installation

### 1. CPU Installation (Default)

```bash
pip install paddlepaddle paddleocr>=2.7 PyYAML opencv-python python-pptx pdf2image
```

### 2. GPU Installation (CUDA)

First, check your CUDA version:
```bash
nvcc --version
```

Then install the matching paddlepaddle-gpu wheel:

```bash
# Example for CUDA 11.8
pip install paddlepaddle-gpu==2.6.3.post118 -f https://www.paddlepaddle.org.cn/whl/mkl/avx/stable.html
pip install paddleocr>=2.7 PyYAML opencv-python python-pptx pdf2image
```

After installing GPU version, set `use_gpu: true` in `ocr_config.yaml`.

### 3. Optional Dependencies

```bash
# HEIC/HEIF image support
pip install pillow-heif

# .doc / .ppt conversion (requires LibreOffice installed on system)
# Install LibreOffice from https://www.libreoffice.org/
# Ensure 'soffice' is in your system PATH
```

### 4. Docker (Reproducible Environment)

```dockerfile
FROM paddlepaddle/paddle:2.6.3-gpu-cuda11.8-cudnn8
RUN pip install paddleocr>=2.7 PyYAML opencv-python python-pptx pdf2image pillow-heif
COPY . /app
WORKDIR /app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Configuration

All OCR settings are in **`ocr_config.yaml`** in the project root.

### Key Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `use_gpu` | `false` | Enable GPU acceleration |
| `lang` | `"en"` | OCR language code (en, hi, ch, fr, etc.) |
| `det_db_threshold` | `0.3` | Text detection confidence |
| `rec_confidence_threshold` | `0.5` | Recognition confidence filter |
| `dpi` | `300` | PDF/document → image conversion DPI |
| `use_structure` | `false` | Enable PP-Structure for tables/forms |
| `preprocessing.deskew` | `false` | Auto-rotate skewed text |
| `preprocessing.denoise` | `false` | Median filter denoising |
| `preprocessing.binarization` | `null` | `null`, `"otsu"`, or `"adaptive"` |

### Environment Variable Overrides

You can also override OCR settings via environment variables in `.env`:

```env
OCR_USE_GPU=false
OCR_LANG=en
OCR_CONFIDENCE_THRESHOLD=0.5
OCR_DPI=300
```

---

## Supported File Formats

### Direct OCR (Images)
| Format | Extension | Notes |
|--------|-----------|-------|
| PNG | `.png` | Native support |
| JPEG | `.jpg`, `.jpeg` | Native support |
| TIFF | `.tiff`, `.tif` | Native support |
| BMP | `.bmp` | Native support |
| WebP | `.webp` | Converted to RGB via Pillow |
| GIF | `.gif` | First frame extracted |
| HEIC | `.heic` | Requires `pillow-heif` |

### Documents (Direct Text Extraction)
| Format | Extension | Parser |
|--------|-----------|--------|
| Word | `.docx` | python-docx |
| Excel | `.xlsx`, `.xls` | openpyxl |
| PowerPoint | `.pptx` | python-pptx |
| PDF | `.pdf` | PyMuPDF (text) or PaddleOCR (scanned) |

### Documents (Conversion Required)
| Format | Extension | Requires |
|--------|-----------|----------|
| Word (legacy) | `.doc` | LibreOffice |
| PowerPoint (legacy) | `.ppt` | LibreOffice |

### Text/Data Files (No OCR)
| Format | Extension | Parser |
|--------|-----------|--------|
| Plain text | `.txt` | Direct read |
| CSV | `.csv` | csv module |
| JSON | `.json` | json module |
| XML | `.xml` | Direct read |
| SQL | `.sql` | sqlparse |

---

## Processing Pipeline

1. **Detect file type** by extension
2. **Image files** → Optional preprocessing (deskew/denoise/binarise) → PaddleOCR
3. **PDF files** → Check for selectable text → If scanned, render pages to images at configured DPI → PaddleOCR
4. **Office files** → Direct text extraction (DOCX/XLSX/PPTX) or convert to PDF via LibreOffice (DOC/PPT)
5. **Text files** → Read content directly
6. **PII Detection** → Three-pass engine (Presidio + Keyword + DeBERTa NER)
7. **Sanitisation** → Redact / Mask / Tokenise
8. **Output** → Sanitised file in original format

---

## Model Selection

| Use Case | Model | Config |
|----------|-------|--------|
| General documents | PP-OCRv4 (default) | `lang: en` |
| Hindi/Devanagari | PP-OCRv4 Hindi | `lang: hi` |
| Chinese | PP-OCRv4 Chinese | `lang: ch` |
| Tables/Forms | PP-Structure | `use_structure: true` |
| Handwriting | Fine-tune recogniser | See fine-tuning section |

### Fine-Tuning

To fine-tune on custom data:

1. Prepare labeled images (COCO/ICDAR/LST format)
2. Set in `ocr_config.yaml`:
   ```yaml
   fine_tune: true
   fine_tuning:
     labeled_data_path: "./training_data"
     epochs: 20
     learning_rate: 0.0001
     save_model_dir: "./models"
   ```
3. Use PaddleOCR training scripts: `tools/train.py`

---

## Troubleshooting

### PaddleOCR not found
```
ModuleNotFoundError: No module named 'paddleocr'
```
→ Install: `pip install paddlepaddle paddleocr`

### torch DLL loading error on Windows
```
OSError: [WinError 127] The specified procedure could not be found
```
→ Reinstall torch: `pip install --force-reinstall torch --index-url https://download.pytorch.org/whl/cpu`

### GPU not detected
→ Verify CUDA: `python -c "import paddle; print(paddle.device.is_compiled_with_cuda())"`
→ Ensure correct paddlepaddle-gpu wheel for your CUDA version

### LibreOffice not found (.doc/.ppt conversion)
```
RuntimeError: LibreOffice is required for .doc / .ppt / .pptx conversion
```
→ Install LibreOffice and add `soffice` to system PATH

### HEIC files not supported
```
ImportError: pillow-heif is required for HEIC support
```
→ Install: `pip install pillow-heif`

### First run is slow
PaddleOCR auto-downloads models on first use (~100 MB). Subsequent runs are fast.

---

## Architecture

```
app/
├── ocr_engine.py      # PaddleOCR wrapper (singleton, preprocessing, postprocessing)
├── converter.py        # File format conversion utilities
├── parser_image.py     # Image OCR + PII redaction on bounding boxes
├── parser_pdf.py       # PDF text extraction + OCR fallback for scanned pages
├── parser_pptx.py      # PowerPoint text extraction
├── parser_docx.py      # Word document text extraction
├── parser_xlsx.py      # Excel text extraction
├── parser_txt.py       # Plain text
├── parser_data.py      # CSV / JSON
├── parser_sql.py       # SQL files
├── parsers.py          # Format router + extension mapping
├── security.py         # File validation (magic bytes, macros, injection)
├── pii_engine.py       # Three-pass PII detection engine
└── config.py           # App settings

ocr_config.yaml         # OCR configuration (GPU, lang, preprocessing, etc.)
```
