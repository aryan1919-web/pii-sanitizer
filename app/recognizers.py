from presidio_analyzer import PatternRecognizer, Pattern

indian_phone_recognizer = PatternRecognizer(
    supported_entity="IN_PHONE",
    name="IndianPhoneRecognizer",
    patterns=[Pattern("indian_phone", r"\b(?:\+91|91|0)?[6-9]\d{9}\b", 0.85)],
    supported_language="en",
)

aadhaar_recognizer = PatternRecognizer(
    supported_entity="IN_AADHAAR",
    name="AadhaarRecognizer",
    patterns=[Pattern("aadhaar", r"\b\d{4}\s?\d{4}\s?\d{4}\b", 0.85)],
    supported_language="en",
)

pan_recognizer = PatternRecognizer(
    supported_entity="IN_PAN",
    name="PANRecognizer",
    patterns=[Pattern("pan", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.9)],
    supported_language="en",
)

ip_recognizer = PatternRecognizer(
    supported_entity="IP_ADDRESS",
    name="IPRecognizer",
    patterns=[Pattern("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.6)],
    supported_language="en",
)

passport_recognizer = PatternRecognizer(
    supported_entity="IN_PASSPORT",
    name="PassportRecognizer",
    patterns=[Pattern("in_passport", r"\b[A-Z][0-9]{7}\b", 0.7)],
    supported_language="en",
)

ifsc_recognizer = PatternRecognizer(
    supported_entity="IFSC_CODE",
    name="IFSCRecognizer",
    patterns=[Pattern("ifsc", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.9)],
    supported_language="en",
)

bank_account_recognizer = PatternRecognizer(
    supported_entity="BANK_ACCOUNT",
    name="BankAccountRecognizer",
    patterns=[Pattern("bank_acct", r"\b\d{9,18}\b", 0.4)],
    supported_language="en",
)

upi_recognizer = PatternRecognizer(
    supported_entity="UPI_ID",
    name="UPIRecognizer",
    patterns=[Pattern("upi", r"\b[\w.\-]+@[a-z]{2,}(?:bank|pay|upi|paytm|gpay|ybl|okhdfcbank|okaxis|oksbi|apl|ibl)\b", 0.9)],
    supported_language="en",
)

credit_card_recognizer = PatternRecognizer(
    supported_entity="CREDIT_CARD",
    name="CreditCardRecognizer",
    patterns=[Pattern("cc", r"\b(?:\d[ -]*?){13,19}\b", 0.5)],
    supported_language="en",
)

device_id_recognizer = PatternRecognizer(
    supported_entity="DEVICE_ID",
    name="DeviceIDRecognizer",
    patterns=[
        Pattern("android_id", r"\bandroid-[a-f0-9]{10,16}\b", 0.9),
        Pattern("ios_id", r"\b[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\b", 0.7),
        Pattern("imei", r"\b\d{15}\b", 0.3),
    ],
    supported_language="en",
)

hash_recognizer = PatternRecognizer(
    supported_entity="HASH_VALUE",
    name="HashRecognizer",
    patterns=[
        Pattern("fp_hash", r"\bfp_hash_[a-f0-9]{10,}\b", 0.95),
        Pattern("face_tmp", r"\bface_tmp_[a-f0-9]{8,}\b", 0.95),
        Pattern("sha256", r"\b[a-f0-9]{64}\b", 0.6),
        Pattern("md5", r"\b[a-f0-9]{32}\b", 0.5),
    ],
    supported_language="en",
)

dob_recognizer = PatternRecognizer(
    supported_entity="DATE_OF_BIRTH",
    name="DOBRecognizer",
    patterns=[
        Pattern("dob_dmy", r"\b\d{1,2}[\s/\-.](?:January|February|March|April|May|June|July|August|September|October|November|December|\d{1,2})[\s/\-.]\d{2,4}\b", 0.6),
        Pattern("dob_iso", r"\b\d{4}[-/]\d{2}[-/]\d{2}\b", 0.5),
    ],
    supported_language="en",
)

CUSTOM_RECOGNIZERS = [
    indian_phone_recognizer, aadhaar_recognizer, pan_recognizer, ip_recognizer,
    passport_recognizer, ifsc_recognizer, bank_account_recognizer, upi_recognizer,
    credit_card_recognizer, device_id_recognizer, hash_recognizer, dob_recognizer,
]

ENTITY_LIST = [
    "PERSON", "EMAIL_ADDRESS", "IP_ADDRESS", "LOCATION",
    "IN_PHONE", "IN_AADHAAR", "IN_PAN", "PHONE_NUMBER",
    "IN_PASSPORT", "IFSC_CODE", "BANK_ACCOUNT", "UPI_ID",
    "CREDIT_CARD", "DEVICE_ID", "HASH_VALUE", "DATE_OF_BIRTH",
]
