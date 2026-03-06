"""
DeBERTa-v3 PII NER module (HydroXai/pii-masker).
Provides a third detection pass using a fine-tuned token-classification model.
"""

import os
import re
import torch
from transformers import DebertaV2TokenizerFast, AutoModelForTokenClassification
from presidio_analyzer import RecognizerResult

_MODEL_DIR = os.path.join(os.path.dirname(__file__), "deberta_pii_model")

# Map DeBERTa BIO labels -> our entity types
_LABEL_MAP = {
    "NAME_STUDENT": "PERSON",
    "EMAIL": "EMAIL_ADDRESS",
    "PHONE_NUM": "IN_PHONE",
    "STREET_ADDRESS": "LOCATION",
    "ID_NUM": "ID_NUM",
    "URL_PERSONAL": "URL",
    "USERNAME": "USERNAME",
}

_tokenizer = None
_model = None
_device = None


def _load_model():
    global _tokenizer, _model, _device
    if _model is not None:
        return
    _tokenizer = DebertaV2TokenizerFast.from_pretrained(_MODEL_DIR)
    _model = AutoModelForTokenClassification.from_pretrained(_MODEL_DIR)
    _device = "cuda" if torch.cuda.is_available() else "cpu"
    _model.to(_device)
    _model.eval()


def deberta_detect(text: str) -> list[RecognizerResult]:
    """Run DeBERTa NER on text and return RecognizerResult list."""
    _load_model()

    inputs = _tokenizer(
        text, return_tensors="pt", truncation=True, max_length=1024,
        return_offsets_mapping=True,
    )
    offset_mapping = inputs.pop("offset_mapping")[0].tolist()

    with torch.no_grad():
        outputs = _model(**{k: v.to(_device) for k, v in inputs.items()})

    predictions = torch.argmax(outputs.logits, dim=2)[0].tolist()

    raw_results = []
    current_entity = None
    current_start = None
    current_end = None

    for idx, (pred_id, (tok_start, tok_end)) in enumerate(
        zip(predictions, offset_mapping)
    ):
        if tok_start == 0 and tok_end == 0:
            if current_entity:
                raw_results.append(_make_result(current_entity, current_start, current_end))
                current_entity = None
            continue

        label = _model.config.id2label[pred_id]

        if label == "O":
            if current_entity:
                raw_results.append(_make_result(current_entity, current_start, current_end))
                current_entity = None
        elif label.startswith("B-") or label.startswith("I-"):
            raw_type = label[2:].replace("_STUDENT", "")
            mapped = _LABEL_MAP.get(raw_type, raw_type)
            if current_entity == mapped:
                # Extend current span (handles both B- continuation and I-)
                current_end = tok_end
            else:
                if current_entity:
                    raw_results.append(_make_result(current_entity, current_start, current_end))
                current_entity = mapped
                current_start = tok_start
                current_end = tok_end

    if current_entity:
        raw_results.append(_make_result(current_entity, current_start, current_end))

    # Merge adjacent results of the same entity type (gap <= 1 char, e.g. space)
    if not raw_results:
        return raw_results
    merged = [raw_results[0]]
    for r in raw_results[1:]:
        prev = merged[-1]
        if r.entity_type == prev.entity_type and r.start - prev.end <= 1:
            merged[-1] = _make_result(prev.entity_type, prev.start, r.end)
        else:
            merged.append(r)

    # Trim leading whitespace from spans
    trimmed = []
    for r in merged:
        span = text[r.start:r.end]
        lstripped = span.lstrip()
        offset = len(span) - len(lstripped)
        trimmed.append(_make_result(r.entity_type, r.start + offset, r.end))
    return trimmed


def _make_result(entity_type: str, start: int, end: int) -> RecognizerResult:
    return RecognizerResult(
        entity_type=entity_type,
        start=start,
        end=end,
        score=0.90,
    )
