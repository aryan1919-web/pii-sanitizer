import uuid
import re
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.recognizers import CUSTOM_RECOGNIZERS, ENTITY_LIST
from app.deberta_ner import deberta_detect

_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None

CONTEXT_KEYWORDS = {
    "PERSON": [
        r"(?:full\s*)?name\s*[:=]\s*",
        r"applicant\s*[:=]\s*",
        r"customer\s*[:=]\s*",
        r"employee\s*[:=]\s*",
        r"patient\s*[:=]\s*",
        r"father'?s?\s*name\s*[:=]\s*",
        r"mother'?s?\s*name\s*[:=]\s*",
        r"spouse\s*[:=]\s*",
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
    # Pass 1: Presidio (regex + spaCy NER)
    presidio_results = get_analyzer().analyze(text=text, entities=ENTITY_LIST, language=language)
    presidio_results = _clip_at_newline(list(presidio_results), text)
    presidio_results = _trim_trailing_labels(presidio_results, text)
    # Pass 2: Keyword-context scanning
    context_results = _keyword_context_scan(text)
    # Pass 3: DeBERTa-v3 deep learning NER
    try:
        deberta_results = deberta_detect(text)
        deberta_results = _clip_at_newline(deberta_results, text)
    except Exception:
        deberta_results = []
    all_results = presidio_results + context_results + deberta_results
    all_entity_types = set(ENTITY_LIST) | {"BANK_NAME"}
    for r in all_results:
        if r.entity_type not in all_entity_types:
            all_entity_types.add(r.entity_type)
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
