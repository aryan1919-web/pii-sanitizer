import re
import sqlparse
from app.pii_engine import sanitize


def parse_sql(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    text = data.decode("utf-8", errors="replace")
    statements = sqlparse.split(text)
    out_parts = []
    total = 0

    for stmt in statements:
        cleaned_stmt, c = _sanitize_statement(stmt, mode)
        total += c
        out_parts.append(cleaned_stmt)

    return "\n".join(out_parts).encode("utf-8"), total


def _sanitize_statement(stmt: str, mode: str) -> tuple[str, int]:
    total = 0
    result = []
    tokens = sqlparse.parse(stmt)[0].flatten() if stmt.strip() else []

    for token in tokens:
        if token.ttype in (sqlparse.tokens.Literal.String.Single, sqlparse.tokens.Literal.String.Symbol):
            inner = token.value[1:-1]
            cleaned, c = sanitize(inner, mode)
            total += c
            quote = token.value[0]
            result.append(f"{quote}{cleaned}{quote}")
        else:
            result.append(token.value)

    return "".join(result), total
