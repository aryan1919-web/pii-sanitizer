import io
from openpyxl import load_workbook
from app.pii_engine import sanitize


def parse_xlsx(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    wb = load_workbook(io.BytesIO(data))
    total = 0

    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str):
                    cleaned, c = sanitize(cell.value, mode)
                    total += c
                    cell.value = cleaned

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue(), total
