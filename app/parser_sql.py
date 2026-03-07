import re
import sqlparse
from app.pii_engine import sanitize, sanitize_batch


def parse_sql(data: bytes, mode: str = "redact") -> tuple[bytes, int]:
    text = data.decode("utf-8", errors="replace")
    statements = sqlparse.split(text)

    # Collect all string literal values across all statements
    all_strings = []
    # Track: (stmt_idx, token_position_in_flat_list, quote_char)
    token_map = []
    flat_tokens_per_stmt = []

    for si, stmt in enumerate(statements):
        if not stmt.strip():
            flat_tokens_per_stmt.append([])
            continue
        tokens = list(sqlparse.parse(stmt)[0].flatten())
        flat_tokens_per_stmt.append(tokens)
        for ti, token in enumerate(tokens):
            if token.ttype in (sqlparse.tokens.Literal.String.Single, sqlparse.tokens.Literal.String.Symbol):
                inner = token.value[1:-1]
                all_strings.append(inner)
                token_map.append((si, ti, token.value[0]))

    if not all_strings:
        return text.encode("utf-8"), 0

    # Single batch sanitize for all SQL string literals
    cleaned_strings, total = sanitize_batch(all_strings, mode)

    # Write cleaned values back into tokens
    for idx, (si, ti, quote) in enumerate(token_map):
        flat_tokens_per_stmt[si][ti] = type(flat_tokens_per_stmt[si][ti])(
            flat_tokens_per_stmt[si][ti].ttype,
            f"{quote}{cleaned_strings[idx]}{quote}"
        )

    # Reconstruct statements
    out_parts = []
    for si, stmt in enumerate(statements):
        if not stmt.strip():
            out_parts.append(stmt)
        else:
            out_parts.append("".join(t.value for t in flat_tokens_per_stmt[si]))

    return "\n".join(out_parts).encode("utf-8"), total
