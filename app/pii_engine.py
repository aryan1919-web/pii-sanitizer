import uuid
import re
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.recognizers import CUSTOM_RECOGNIZERS, ENTITY_LIST
from app.deberta_ner import deberta_detect

# Threshold for switching to fast regex-only path (skips spaCy NER + DeBERTa)
_FAST_PATH_CHARS = 2000

_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None

CONTEXT_KEYWORDS = {
    "PERSON": [
        r"(?:full\s*)?name\s*[:=]\s*",
        r"applicant\s*[:=]?\s*",
        r"customer\s*[:=]?\s*",
        r"employee\s*[:=]?\s*",
        r"patient\s*[:=]?\s*",
        r"father'?s?\s*name\s*[:=]\s*",
        r"mother'?s?\s*name\s*[:=]\s*",
        r"spouse\s*[:=]?\s*",
        r"(?:mr|mrs|ms|dr|prof)\.?\s+",
        r"user\s*[:=]?\s*",
        r"account\s*holder\s*[:=]?\s*",
    ],
    "DATE_OF_BIRTH": [
        r"(?:date\s*of\s*birth|dob|d\.o\.b|birth\s*date)\s*[:=]\s*",
    ],
    "IN_PASSPORT": [
        r"passport\s*(?:no|number|#)?\s*[:=]\s*",
    ],
    "BANK_NAME": [
        r"bank\s*(?:name)?\s*[:=]\s*",
    ],
    "BANK_ACCOUNT": [
        r"(?:account|acct|a/c)\s*(?:no|number|#)?\s*[:=]\s*",
    ],
    "IFSC_CODE": [
        r"ifsc\s*(?:code)?\s*[:=]\s*",
    ],
    "UPI_ID": [
        r"upi\s*(?:id)?\s*[:=]\s*",
    ],
    "DEVICE_ID": [
        r"device\s*(?:id)?\s*[:=]\s*",
        r"imei\s*[:=]\s*",
    ],
    "HASH_VALUE": [
        r"fingerprint\s*(?:hash)?\s*[:=]\s*",
        r"face\s*template\s*[:=]\s*",
        r"biometric\s*(?:id|hash|template)?\s*[:=]\s*",
        r"hash\s*[:=]\s*",
    ],
    "CREDIT_CARD": [
        r"(?:credit|debit)\s*card\s*(?:no|number|#)?\s*[:=]\s*",
    ],
    "LOCATION": [
        r"address\s*[:=]\s*",
        r"city\s*[:=]\s*",
        r"state\s*[:=]\s*",
        r"pin\s*code\s*[:=]\s*",
    ],
    "IN_PHONE": [
        r"(?:mobile|phone|cell|contact)\s*(?:no|number|#)?\s*[:=]\s*",
    ],
    "EMAIL_ADDRESS": [
        r"e-?mail\s*(?:id|address)?\s*[:=]\s*",
    ],
    "IN_AADHAAR": [
        r"aadhaar\s*(?:no|number|#|card)?\s*[:=]\s*",
    ],
    "IN_PAN": [
        r"pan\s*(?:no|number|#|card)?\s*[:=]\s*",
    ],
}


def get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        _analyzer = AnalyzerEngine()
        for r in CUSTOM_RECOGNIZERS:
            _analyzer.registry.add_recognizer(r)
    return _analyzer


def get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


# Regex for any known label that might follow a value on the same line
_NEXT_LABEL_RE = re.compile(
    r"\s+(?:(?:full\s*)?name|dob|d\.o\.b|date\s*of\s*birth|birth\s*date"
    r"|mobile|phone|cell|contact|e-?mail|address|city|state|pin\s*code"
    r"|pan|aadhaar|passport|bank|account|acct|a/c|ifsc|upi|ip\b"
    r"|device|imei|fingerprint|face\s*template|biometric|hash"
    r"|credit|debit)\s*(?:no|number|#|name|id|code|card|address)?\s*[:=]",
    re.IGNORECASE,
)


def _keyword_context_scan(text: str) -> list[RecognizerResult]:
    results = []
    for entity_type, patterns in CONTEXT_KEYWORDS.items():
        for pat in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                val_start = m.end()
                rest = text[val_start:]
                # Stop at newline OR at the next label on the same line
                nl_pos = rest.find('\n')
                if nl_pos == -1:
                    nl_pos = len(rest)
                segment = rest[:nl_pos]
                # Check if another label exists on the same line
                next_label = _NEXT_LABEL_RE.search(segment)
                if next_label:
                    segment = segment[:next_label.start()]

                # For PERSON, limit to name-like text (2-4 capitalized words)
                if entity_type == "PERSON":
                    name_match = re.match(r'\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})', segment)
                    if name_match:
                        val = name_match.group(1).strip()
                        name_start = val_start + name_match.start(1)
                        results.append(RecognizerResult(
                            entity_type=entity_type,
                            start=name_start,
                            end=name_start + len(val),
                            score=0.85,
                        ))
                    continue

                val = segment.strip()
                if val and len(val) > 1:
                    results.append(RecognizerResult(
                        entity_type=entity_type,
                        start=val_start,
                        end=val_start + len(segment.rstrip()),
                        score=0.85,
                    ))
    return results


def _clip_at_newline(results: list[RecognizerResult], text: str) -> list[RecognizerResult]:
    """Trim entity spans that cross newline boundaries."""
    clipped = []
    for r in results:
        span = text[r.start:r.end]
        nl_pos = span.find('\n')
        if nl_pos != -1:
            new_end = r.start + nl_pos
            trimmed = text[r.start:new_end].strip()
            if trimmed:
                clipped.append(RecognizerResult(
                    entity_type=r.entity_type,
                    start=r.start,
                    end=new_end,
                    score=r.score,
                ))
        else:
            clipped.append(r)
    return clipped


_TRAILING_LABEL_RE = re.compile(
    r"\s+(?:DOB|D\.O\.B|Mobile|Phone|Cell|Contact|Email|Address"
    r"|PAN|Aadhaar|Passport|Bank|Account|IFSC|UPI|IP)\s*[:=]?$",
    re.IGNORECASE,
)


def _trim_trailing_labels(results: list[RecognizerResult], text: str) -> list[RecognizerResult]:
    """Strip trailing field labels from PERSON / NAME spans."""
    trimmed = []
    for r in results:
        if r.entity_type in ("PERSON", "NAME"):
            span = text[r.start:r.end]
            m = _TRAILING_LABEL_RE.search(span)
            if m:
                new_end = r.start + m.start()
                if new_end > r.start:
                    trimmed.append(RecognizerResult(
                        entity_type=r.entity_type,
                        start=r.start,
                        end=new_end,
                        score=r.score,
                    ))
                continue
        trimmed.append(r)
    return trimmed


# Finer specificity tiers for dedup:
# Tier 3: India-specific IDs (most specific patterns)
# Tier 2: General typed entities
# Tier 1: Catch-all generic types from DeBERTa
_TIER3_TYPES = {
    "IN_AADHAAR", "IN_PAN", "IN_PASSPORT", "IFSC_CODE",
    "BANK_ACCOUNT", "CREDIT_CARD", "DEVICE_ID", "HASH_VALUE",
    "UPI_ID", "DATE_OF_BIRTH", "IP_ADDRESS",
}
_TIER2_TYPES = {
    "IN_PHONE", "PHONE_NUMBER", "EMAIL_ADDRESS", "PERSON",
    "LOCATION", "BANK_NAME",
}
_GENERIC_TYPES = {"ID_NUM", "URL", "USERNAME", "NAME"}


def _type_specificity(entity_type: str) -> int:
    """Higher = more specific = preferred."""
    if entity_type in _TIER3_TYPES:
        return 3
    if entity_type in _TIER2_TYPES:
        return 2
    if entity_type in _GENERIC_TYPES:
        return 0
    return 1


def _dedup_results(results: list[RecognizerResult]) -> list[RecognizerResult]:
    results.sort(key=lambda r: (r.start, -(r.end - r.start), -r.score))
    merged = []
    for r in results:
        if merged and r.start < merged[-1].end:
            prev = merged[-1]
            prev_len = prev.end - prev.start
            r_len = r.end - r.start
            prev_spec = _type_specificity(prev.entity_type)
            r_spec = _type_specificity(r.entity_type)
            # If spans are same length, prefer higher specificity then score
            if r_len == prev_len:
                if r_spec > prev_spec or (r_spec == prev_spec and r.score > prev.score):
                    merged[-1] = r
            # If new span is longer (shouldn't normally happen after sort), take it
            elif r_len > prev_len:
                merged[-1] = r
            # If prev fully contains r (r is shorter), only replace if
            # BOTH have same length AND r is more specific — otherwise keep prev
            # (i.e., do nothing; the longer prev span wins)
        else:
            merged.append(r)
    return merged


def detect_pii(text: str, language: str = "en") -> list:
    if not text or not text.strip():
        return []

    # Short texts: full pipeline (Presidio NER + keyword + DeBERTa)
    if len(text) <= _FAST_PATH_CHARS:
        return _detect_full(text, language)

    # Large texts: fast regex-only path (no spaCy NER, no DeBERTa)
    return _detect_fast(text)


def _detect_full(text: str, language: str = "en") -> list:
    """Full PII detection: Presidio (regex + spaCy NER) + keyword + DeBERTa."""
    # Pass 1: Presidio (regex + spaCy NER)
    presidio_results = get_analyzer().analyze(text=text, entities=ENTITY_LIST, language=language)
    presidio_results = _clip_at_newline(list(presidio_results), text)
    presidio_results = _trim_trailing_labels(presidio_results, text)
    # Pass 2: Keyword-context scanning
    context_results = _keyword_context_scan(text)
    # Pass 3: DeBERTa-v3 deep learning NER
    deberta_results = []
    try:
        deberta_results = deberta_detect(text)
        deberta_results = _clip_at_newline(deberta_results, text)
    except Exception:
        pass

    all_results = presidio_results + context_results + deberta_results
    return _dedup_results(all_results)


def _detect_fast(text: str) -> list:
    """Fast regex-only PII detection for large texts.

    Runs custom regex recognizers + keyword context directly,
    skipping Presidio's expensive spaCy NER pipeline and DeBERTa.
    Also adds a built-in email regex since Presidio's EMAIL_ADDRESS
    recognizer is internal.
    """
    all_results = []

    # Run all custom regex recognizers directly
    for recognizer in CUSTOM_RECOGNIZERS:
        for pattern_obj in recognizer.patterns:
            compiled = re.compile(pattern_obj.regex)
            for m in compiled.finditer(text):
                all_results.append(RecognizerResult(
                    entity_type=recognizer.supported_entities[0],
                    start=m.start(),
                    end=m.end(),
                    score=pattern_obj.score,
                ))

    # Email regex (Presidio has this built-in, we need it here)
    for m in re.finditer(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', text):
        all_results.append(RecognizerResult(
            entity_type="EMAIL_ADDRESS", start=m.start(), end=m.end(), score=0.85,
        ))

    # Keyword-context scanning (catches names after "customer", "name:", etc.)
    context_results = _keyword_context_scan(text)
    all_results.extend(context_results)

    # Clip at newlines and dedup
    all_results = _clip_at_newline(all_results, text)
    return _dedup_results(all_results)


def _mask_value(original: str, entity_type: str) -> str:
    if entity_type == "EMAIL_ADDRESS":
        parts = original.split("@")
        if len(parts) == 2:
            local = parts[0]
            return local[0] + "*" * (len(local) - 1) + "@" + parts[1]
    if entity_type in ("IN_PHONE", "PHONE_NUMBER"):
        digits = re.sub(r"\D", "", original)
        if len(digits) >= 4:
            return digits[:2] + "*" * (len(digits) - 4) + digits[-2:]
    if entity_type == "IN_AADHAAR":
        digits = re.sub(r"\D", "", original)
        if len(digits) >= 4:
            return "XXXX XXXX " + digits[-4:]
        return "XXXX XXXX XXXX"
    if entity_type == "IN_PAN":
        if len(original) >= 6:
            return original[0] + "****" + original[5:]
    if entity_type in ("PERSON", "NAME"):
        return original[0] + "*" * (len(original) - 1)
    if entity_type == "IP_ADDRESS":
        parts = original.split(".")
        return parts[0] + ".***.***.***"
    if entity_type == "DATE_OF_BIRTH":
        return "** **** 19**"
    if entity_type == "BANK_ACCOUNT":
        if len(original) >= 4:
            return "*" * (len(original) - 4) + original[-4:]
    if entity_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", original)
        if len(digits) >= 4:
            return "*" * (len(digits) - 4) + digits[-4:]
    if entity_type == "UPI_ID":
        at_pos = original.find("@")
        if at_pos > 0:
            return original[0] + "*" * (at_pos - 1) + original[at_pos:]
    if entity_type == "IN_PASSPORT":
        if len(original) > 1:
            return original[0] + "*" * (len(original) - 1)
        return "[REDACTED]"
    if entity_type in ("DEVICE_ID", "HASH_VALUE", "IFSC_CODE", "BANK_NAME", "LOCATION"):
        return "[REDACTED]"
    if len(original) > 1:
        return original[0] + "*" * (len(original) - 1)
    return "[REDACTED]"


def sanitize(text: str, mode: str = "redact", language: str = "en") -> tuple[str, int]:
    results = detect_pii(text, language)
    if not results:
        return text, 0

    count = len(results)
    all_entities = set(ENTITY_LIST) | {r.entity_type for r in results}

    if mode == "redact":
        operators = {e: OperatorConfig("replace", {"new_value": "[REDACTED]"}) for e in all_entities}
        out = get_anonymizer().anonymize(text=text, analyzer_results=results, operators=operators)
        return out.text, count

    if mode == "tokenize":
        operators = {e: OperatorConfig("replace", {"new_value": f"<{uuid.uuid4()}>"}) for e in all_entities}
        out = get_anonymizer().anonymize(text=text, analyzer_results=results, operators=operators)
        return out.text, count

    if mode == "mask":
        sorted_results = sorted(results, key=lambda r: r.start, reverse=True)
        masked = text
        for r in sorted_results:
            original = text[r.start:r.end]
            masked = masked[:r.start] + _mask_value(original, r.entity_type) + masked[r.end:]
        return masked, count

    return text, 0


# Separator for batch processing — null byte won't appear in normal text
_BATCH_SEP = "\n\x00\n"
_BATCH_MAX_CHARS = 50000  # Max combined text size per batch


def sanitize_batch(texts: list[str], mode: str = "redact", language: str = "en") -> tuple[list[str], int]:
    """Sanitize multiple texts in one or few PII detection passes.

    Groups texts into batches of ~20K chars, runs one sanitize call per batch.
    Much faster than calling sanitize() per text.
    """
    if not texts:
        return [], 0

    # Filter out empty texts but track their positions
    non_empty = [(i, t) for i, t in enumerate(texts) if t and t.strip()]
    if not non_empty:
        return list(texts), 0

    # Split into batches by character limit
    batches = []
    current_batch = []
    current_size = 0
    for item in non_empty:
        item_len = len(item[1]) + len(_BATCH_SEP)
        if current_batch and current_size + item_len > _BATCH_MAX_CHARS:
            batches.append(current_batch)
            current_batch = [item]
            current_size = item_len
        else:
            current_batch.append(item)
            current_size += item_len
    if current_batch:
        batches.append(current_batch)

    result = list(texts)
    total_count = 0

    for batch in batches:
        combined = _BATCH_SEP.join(t for _, t in batch)
        cleaned, count = sanitize(combined, mode, language)
        total_count += count
        cleaned_parts = cleaned.split(_BATCH_SEP)
        for idx, (orig_idx, _) in enumerate(batch):
            if idx < len(cleaned_parts):
                result[orig_idx] = cleaned_parts[idx]

    return result, total_count
