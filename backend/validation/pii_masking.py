"""
PII Masking — Stage D of Trust Gate.

Runs after field extraction and validation, but before OCSF normalization.
Masks only identified sensitive fields in the parsed output, rather than scanning the entire raw log.
The raw log in Evidence Vault remains untouched.
"""

import re
from typing import Any

# Common PII regex patterns
SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

SENSITIVE_FIELDS = {
    "user.email",
    "user.name",
    "actor.user.name",
    "actor.user.email",
    "source.user.name",
    "source.user.email",
}

class PIIMasker:
    """Masks PII in parsed fields."""

    def mask(self, parsed_fields: dict[str, Any]) -> dict[str, Any]:
        """
        Apply PII masking to the parsed fields.
        Returns a new dictionary with masked values.
        """
        masked_fields = {}
        for key, value in parsed_fields.items():
            if not isinstance(value, str):
                masked_fields[key] = value
                continue

            # Check if this field is known to be sensitive
            if key in SENSITIVE_FIELDS:
                masked_fields[key] = "***MASKED***"
                continue

            # Otherwise apply generic regex masking on strings
            masked_val = value
            # Mask emails
            masked_val = EMAIL_REGEX.sub("[EMAIL_MASKED]", masked_val)
            # Mask SSNs
            masked_val = SSN_REGEX.sub("[SSN_MASKED]", masked_val)
            # Mask Credit Cards (simple heuristic)
            masked_val = CREDIT_CARD_REGEX.sub("[CC_MASKED]", masked_val)

            masked_fields[key] = masked_val

        return masked_fields

pii_masker = PIIMasker()
