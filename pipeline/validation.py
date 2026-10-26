import ipaddress
import json
import math
import os
import re
from collections import Counter
from pydantic import BaseModel, Field, field_validator
from typing import Callable, List, Optional, Pattern, Tuple

class TicketIngestionSchema(BaseModel):
    ticket_id: str = Field(..., description="Unique alphanumeric tracking string.")
    reporter_email: str = Field(..., description="Corporate sender communication handle.")
    raw_text: str = Field(..., description="Unstructured description text payload.")

    @field_validator('reporter_email')
    @classmethod
    def validate_corporate_domain(cls, value: str) -> str:
        if not value.endswith("@enterprise.com"):
            raise ValueError("Ingestion restricted to internal corporate system users.")
        return value

# Placeholder chars used to mask SSNs / card numbers (e.g. ***-**-6789, XXXX XXXX XXXX 1234)
_MASK_CHAR = r"[*Xx#•]"

# Separator groupings printed on real cards (Visa/MC 4-4-4-4, Amex 4-6-5, Diners 4-6-4, 19-digit 4-4-4-4-3)
_PRINTED_CARD_GROUPINGS = {(4, 4, 4, 4), (4, 6, 5), (4, 6, 4), (4, 4, 4, 4, 3), (4, 4, 4, 1), (4, 4, 5)}


def _passes_luhn_checksum(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def _is_plausible_credit_card(match: re.Match) -> bool:
    raw = match.group(0)
    digits = re.sub(r"\D", "", raw)
    if not 13 <= len(digits) <= 19:
        return False
    separators = set(re.findall(r"[ .-]", raw))
    if len(separators) > 1:  # mixed separators look like dates/versions, not cards
        return False
    if _passes_luhn_checksum(digits):
        return True
    # Not Luhn-valid (e.g. test data), but laid out exactly like a printed card number
    groups = tuple(len(g) for g in re.split(r"[ .-]", raw))
    return bool(separators) and groups in _PRINTED_CARD_GROUPINGS


def _is_issuable_ssn(match: re.Match) -> bool:
    # Unseparated 9-digit runs are only treated as SSNs if they could be issued,
    # so arbitrary 9-digit IDs are left alone.
    area, group, serial = match.group("area"), match.group("group"), match.group("serial")
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def _has_valid_phone_length(match: re.Match) -> bool:
    main = match.group("main")
    digits = re.sub(r"\D", "", main)
    if main.startswith("+"):
        return 7 <= len(digits) <= 15  # E.164 limit
    # Without a country code, require a full national number (e.g. 10-digit US, 11-digit UK)
    return 10 <= len(digits) <= 11


def _has_valid_ipv4_octets(match: re.Match) -> bool:
    return all(int(octet) <= 255 for octet in match.group("addr").split("."))


def _is_valid_ipv6_address(match: re.Match) -> bool:
    try:
        ipaddress.IPv6Address(match.group("addr"))
        return True
    except ValueError:
        return False


def _is_high_entropy_secret(match: re.Match) -> bool:
    token = match.group(0)
    if re.fullmatch(r"[0-9a-fA-F-]+", token):  # hashes, UUIDs, commit SHAs
        return False
    has_classes = (re.search(r"[a-z]", token) and re.search(r"[A-Z]", token)
                   and re.search(r"\d", token))
    return bool(has_classes) and _shannon_entropy(token) >= 4.0


class DataSanitizationPipeline:
    def __init__(self, dlq_path: str = "dead_letter_queue.log"):
        self.dlq_path = dlq_path
        # Ordered PII rules: (label, pattern, optional validator). Earlier rules run first,
        # so their placeholders can't be re-matched by later, looser rules. If a pattern
        # has a "secret" group, only that group is redacted (e.g. keeps "api_key=").
        self.pii_rules: List[Tuple[str, Pattern, Optional[Callable[[re.Match], bool]]]] = [
            # Well-known credential formats
            ("api_key", re.compile(
                r'(?<![\w-])(?:'
                r'sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}'          # OpenAI / Anthropic
                r'|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}'  # Stripe
                r'|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{30,}'  # GitHub
                r'|glpat-[A-Za-z0-9_-]{20,}'                     # GitLab
                r'|(?:AKIA|ASIA)[0-9A-Z]{16}'                    # AWS access key id
                r'|AIza[0-9A-Za-z_-]{35}'                        # Google
                r'|xox[abposr]-[A-Za-z0-9-]{10,}'                # Slack
                r'|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}'       # JWT
                r')'), None),
            # "Authorization: Bearer <token>"
            ("api_key", re.compile(r'(?i)\b(?:bearer|basic)\s+(?P<secret>[\w.~+/-]{16,}=*)'), None),
            # key=value / key: value assignments for secrets
            ("api_key", re.compile(
                r'(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?(?:key|token)'
                r'|auth[_-]?token|token|password|passwd|pwd|private[_-]?key)["\']?\s*[:=]\s*["\']?'
                r'(?P<secret>[^\s"\',;]{8,})'), None),
            # Emails, including internationalized local parts / domains, quoted local parts,
            # and IP-literal domains
            ("email", re.compile(
                r'(?<![\w.!#$%&\'*+/=?^`{|}~-])'
                r'(?:"[^"\r\n]+"|[\w!#$%&\'*+/=?^`{|}~-]+(?:\.[\w!#$%&\'*+/=?^`{|}~-]+)*)'
                r'@(?:(?:[^\W_](?:[\w-]*[^\W_])?\.)+(?:[^\W\d_]{2,}|xn--[a-z0-9-]+)'
                r'|\[(?:IPv6:)?[0-9A-Fa-f:.]+\])(?![\w-])',
                re.IGNORECASE), None),
            # IPv6 (validated by ipaddress), optional zone id / prefix length
            ("ip_address", re.compile(
                r'(?<![\w:.])(?P<addr>[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*[0-9A-Fa-f:])'
                r'(?:%[\w.]+)?(?:/\d{1,3})?(?![\w:])'), _is_valid_ipv6_address),
            # IPv4 with each octet checked to be 0-255, optional CIDR suffix
            ("ip_address", re.compile(
                r'(?<![\w.])(?P<addr>\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?!\w|\.\d)'), _has_valid_ipv4_octets),
            # Card numbers: 13-19 digits, no / space / dash / dot separators, Luhn or card layout
            ("credit_card", re.compile(r'(?<![\w.-])(?<!\d[ .-])\d(?:[ .-]?\d){12,18}(?![ .-]?\d)(?!\w)'),
             _is_plausible_credit_card),
            # Masked cards, e.g. **** **** **** 1234, XXXX-XXXX-XXXX-1234
            ("credit_card", re.compile(rf'(?<!\w){_MASK_CHAR}{{4}}([ .-]?){_MASK_CHAR}{{4,6}}\1(?:{_MASK_CHAR}{{4,5}}\1)?\d{{4,5}}(?!\w)'),
             None),
            # SSNs with a consistent separator (dash, space, dot): 123-45-6789, 123 45 6789
            ("ssn", re.compile(r'(?<![\w.-])\d{3}([- .])\d{2}\1\d{4}(?![\w-]|\.\d)'), None),
            # Masked SSNs: ***-**-6789, XXX-XX-6789, ***-**-****
            ("ssn", re.compile(rf'(?<![\w*#])(?<!\u2022){_MASK_CHAR}{{3}}([- .]?){_MASK_CHAR}{{2}}\1(?:\d{{4}}|{_MASK_CHAR}{{4}})(?![\w*#])'),
             None),
            # Unseparated SSNs: 123456789 (only if structurally valid)
            ("ssn", re.compile(r'(?<![\w.-])(?P<area>\d{3})(?P<group>\d{2})(?P<serial>\d{4})(?![\w-]|\.\d)'),
             _is_issuable_ssn),
            # Phone numbers: optional +country code, (area code), space/dash/dot groups, extensions
            ("phone", re.compile(
                r'(?<![\w+.-])(?P<main>(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{1,4}){1,5})'
                r'(?:\s*(?i:ext\.?|extension|x|\#)\s*\d{1,6})?(?!\w)'), _has_valid_phone_length),
            # Generic high-entropy tokens (mixed case + digits); skips hex IDs / UUIDs / plain words
            ("api_key", re.compile(r'(?<![\w.+/=~-])[\w.+/=~-]{31,}[\w+/=](?![\w+/=~-]|\.\w)'),
             _is_high_entropy_secret),
        ]
        # Patterns that should NOT be scrubbed (whitelist for corporate domains)
        self.safe_patterns = [
            re.compile(r'@enterprise\.com$', re.IGNORECASE),  # Allow corporate emails
        ]

    def _is_whitelisted_match(self, text: str, match: re.Match) -> bool:
        """Check if a match should be whitelisted (not scrubbed)"""
        matched_text = match.group(0)
        for pattern in self.safe_patterns:
            if pattern.search(matched_text):
                return True
        return False

    def scrub_pii(self, text: str) -> str:
        """Enhanced PII scrubbing with whitelist protection"""
        sanitized = text

        # Process each PII rule in priority order
        for label, pattern, validator in self.pii_rules:
            def replace_func(match, label=label, validator=validator):
                # Check if match should be whitelisted or fails format validation
                if self._is_whitelisted_match(text, match):
                    return match.group(0)
                if validator is not None and not validator(match):
                    return match.group(0)
                placeholder = f"[{label.upper()}_REDACTED]"
                if "secret" in match.groupdict():
                    whole_start = match.start(0)
                    prefix = match.group(0)[:match.start("secret") - whole_start]
                    suffix = match.group(0)[match.end("secret") - whole_start:]
                    return prefix + placeholder + suffix
                return placeholder

            sanitized = pattern.sub(replace_func, sanitized)

        return sanitized

    def route_to_dlq(self, error_message: str, unvalidated_payload: dict):
        with open(self.dlq_path, "a") as dlq_file:
            entry = {
                "error": error_message,
                "payload": unvalidated_payload
            }
            dlq_file.write(json.dumps(entry) + "\n")