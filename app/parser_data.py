import csv
import io
import json
from app.pii_engine import sanitize, sanitize_batch


def parse_csv(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    text = data.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)

    # Collect all cells into a flat list for batch processing
    all_cells = []
    cell_map = []  # (row_idx, col_idx)
    for ri, row in enumerate(rows):
        for ci, cell in enumerate(row):
            all_cells.append(cell)
            cell_map.append((ri, ci))

    # Single batch sanitize call for ALL cells
    cleaned_cells, total = sanitize_batch(all_cells, mode)

    # Write back
    for idx, (ri, ci) in enumerate(cell_map):
        rows[ri][ci] = cleaned_cells[idx]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8"), total


def parse_json(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    obj = json.loads(data.decode("utf-8", errors="replace"))

    # Collect all string values with their paths for batch processing
    strings = []
    paths = []

    def collect(node, path):
        if isinstance(node, str):
            strings.append(node)
            paths.append(path)
        elif isinstance(node, dict):
            for k, v in node.items():
                collect(v, path + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                collect(v, path + (i,))

    collect(obj, ())

    if not strings:
        return json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8"), 0

    # Single batch sanitize
    cleaned, total = sanitize_batch(strings, mode)

    # Write cleaned values back
    def set_at_path(root, path, value):
        node = root
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    for i, p in enumerate(paths):
        if cleaned[i] != strings[i]:
            set_at_path(obj, p, cleaned[i])

    return json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8"), total
