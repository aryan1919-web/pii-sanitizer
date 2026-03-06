import csv
import io
import json
from app.pii_engine import sanitize


def parse_csv(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    text = data.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    buf = io.StringIO()
    writer = csv.writer(buf)
    total = 0

    for row in reader:
        new_row = []
        for cell in row:
            cleaned, c = sanitize(cell, mode)
            total += c
            new_row.append(cleaned)
        writer.writerow(new_row)

    return buf.getvalue().encode("utf-8"), total


def parse_json(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    obj = json.loads(data.decode("utf-8", errors="replace"))
    total = [0]

    def walk(node):
        if isinstance(node, str):
            cleaned, c = sanitize(node, mode)
            total[0] += c
            return cleaned
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(i) for i in node]
        return node

    result = walk(obj)
    return json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8"), total[0]
