"""Parser for PowerPoint (.pptx) files — direct text-level PII sanitisation."""

import io
from pptx import Presentation
from app.pii_engine import sanitize


def parse_pptx(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    prs = Presentation(io.BytesIO(data))
    total = 0

    for slide in prs.slides:
        for shape in slide.shapes:
            # ── text frames ──────────────────────────────
            if shape.has_text_frame:
                for para in shape.text_frame.paragraphs:
                    full_text = para.text
                    if not full_text.strip():
                        continue
                    cleaned, c = sanitize(full_text, mode)
                    total += c
                    if c > 0 and para.runs:
                        para.runs[0].text = cleaned
                        for run in para.runs[1:]:
                            run.text = ""

            # ── tables inside shapes ─────────────────────
            if shape.has_table:
                for row in shape.table.rows:
                    for cell in row.cells:
                        for para in cell.text_frame.paragraphs:
                            full_text = para.text
                            if not full_text.strip():
                                continue
                            cleaned, c = sanitize(full_text, mode)
                            total += c
                            if c > 0 and para.runs:
                                para.runs[0].text = cleaned
                                for run in para.runs[1:]:
                                    run.text = ""

    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue(), total
