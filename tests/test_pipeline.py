import pytest
from pipeline.validation import TicketIngestionSchema, DataSanitizationPipeline
import os
def test_pydantic_corporate_domain_enforcement():
    valid_data = {
        "ticket_id": "TCK-101",
        "reporter_email": "engineer@enterprise.com",
        "raw_text": "System logs show standard disk allocations exceeding 85% thresholds."
    }
    schema = TicketIngestionSchema(**valid_data)
    assert schema.reporter_email == "engineer@enterprise.com"

    invalid_data = {
        "ticket_id": "TCK-102",
        "reporter_email": "adversary@gmail.com",
        "raw_text": "Attempted arbitrary cross-domain payload pipeline inject."
    }
    with pytest.raises(ValueError, match="Ingestion restricted to internal corporate system users."):
        TicketIngestionSchema(**invalid_data)

def test_regex_pii_scrubbing_pipeline():
    pipeline = DataSanitizationPipeline(dlq_path="tests/mock_dlq.log")
    dirty_text = "Urgent: Customer identity verification details matched SSN: 000-12-3456 profile."

    clean_text = pipeline.scrub_pii(dirty_text)
    assert "000-12-3456" not in clean_text
    assert "[SSN_REDACTED]" in clean_text

    if os.path.exists("tests/mock_dlq.log"):
        os.remove("tests/mock_dlq.log")

def test_enhanced_pii_scrubbing():
    """Test enhanced PII scrubbing for additional patterns"""
    pipeline = DataSanitizationPipeline(dlq_path="tests/mock_dlq.log")

    # Test phone number scrubbing
    dirty_text = "Contact us at 555-123-4567 for immediate assistance."
    clean_text = pipeline.scrub_pii(dirty_text)
    assert "555-123-4567" not in clean_text
    assert "[PHONE_REDACTED]" in clean_text

    # Test IP address scrubbing
    dirty_text = "Malicious traffic detected from 192.168.1.100"
    clean_text = pipeline.scrub_pii(dirty_text)
    assert "192.168.1.100" not in clean_text
    assert "[IP_ADDRESS_REDACTED]" in clean_text

    # Test that corporate emails are NOT scrubbed (whitelist protection)
    dirty_text = "Please contact admin@enterprise.com for approval"
    clean_text = pipeline.scrub_pii(dirty_text)
    assert "admin@enterprise.com" in clean_text  # Should remain unchanged

    # Test that non-corporate emails ARE scrubbed
    dirty_text = "Please contact attacker@gmail.com for approval"
    clean_text = pipeline.scrub_pii(dirty_text)
    assert "attacker@gmail.com" not in clean_text
    assert "[EMAIL_REDACTED]" in clean_text

    if os.path.exists("tests/mock_dlq.log"):
        os.remove("tests/mock_dlq.log")

@pytest.mark.parametrize("dirty, secret, placeholder", [
    # SSN: space/dot separators, unseparated, masked
    ("SSN 123 45 6789 on file", "123 45 6789", "[SSN_REDACTED]"),
    ("SSN 123456789 on file", "123456789", "[SSN_REDACTED]"),
    ("SSN ***-**-6789 on file", "6789", "[SSN_REDACTED]"),
    ("SSN XXX-XX-6789 on file", "6789", "[SSN_REDACTED]"),
    # Credit cards: spaces, no separators, dots, Amex / Diners lengths, masked
    ("card 4111 1111 1111 1111 charged", "4111 1111 1111 1111", "[CREDIT_CARD_REDACTED]"),
    ("card 4111111111111111 charged", "4111111111111111", "[CREDIT_CARD_REDACTED]"),
    ("card 4111.1111.1111.1111 charged", "4111.1111.1111.1111", "[CREDIT_CARD_REDACTED]"),
    ("amex 3782 822463 10005 charged", "822463", "[CREDIT_CARD_REDACTED]"),
    ("diners 30569309025904 charged", "30569309025904", "[CREDIT_CARD_REDACTED]"),
    ("card **** **** **** 1234 charged", "1234", "[CREDIT_CARD_REDACTED]"),
    # Email: internationalized and unusual valid formats
    ("from josé.müller@bücher.de today", "bücher.de", "[EMAIL_REDACTED]"),
    ('from "john doe"@example.com today', "example.com", "[EMAIL_REDACTED]"),
    ("from o'brien+tag@sub.example.co.uk today", "o'brien", "[EMAIL_REDACTED]"),
    ("from user@[192.168.0.1] today", "user@", "[EMAIL_REDACTED]"),
    # Phone: country codes, parentheses, spaces, extensions, regional formats
    ("call +1 (212) 555-0100 ext. 4 now", "555-0100", "[PHONE_REDACTED]"),
    ("call (212) 555-0100 now", "555-0100", "[PHONE_REDACTED]"),
    ("call +44 20 7946 0958 now", "7946", "[PHONE_REDACTED]"),
    ("call 020 7946 0958 now", "7946", "[PHONE_REDACTED]"),
    ("call 555-123-4567 x123 now", "x123", "[PHONE_REDACTED]"),
    # API keys / secrets: punctuation, separators, known prefixes, key=value
    ("key sk-ant-api03-AbCdEf1234567890GhIjKl leaked", "AbCdEf", "[API_KEY_REDACTED]"),
    ("config api_key=abc.def-123_xyz leaked", "abc.def-123_xyz", "[API_KEY_REDACTED]"),
    ("Authorization: Bearer abcDEF123.ghiJKL456-mno", "abcDEF123", "[API_KEY_REDACTED]"),
    ("aws AKIAIOSFODNN7EXAMPLE leaked", "AKIAIOSFODNN7EXAMPLE", "[API_KEY_REDACTED]"),
    ("blob aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z/+== leaked", "aB3dE5fG7h", "[API_KEY_REDACTED]"),
    # IP: IPv6
    ("from 2001:db8::8a2e:370:7334 today", "2001:db8", "[IP_ADDRESS_REDACTED]"),
    ("from fe80::1%eth0 today", "fe80", "[IP_ADDRESS_REDACTED]"),
])
def test_pii_scrubber_extended_formats(dirty, secret, placeholder):
    clean_text = DataSanitizationPipeline().scrub_pii(dirty)
    assert secret not in clean_text
    assert placeholder in clean_text


@pytest.mark.parametrize("benign", [
    "Invalid octets 999.999.1.1 in log",
    "Deployed on 2024-01-15 at 12:30:45",
    "Request id 550e8400-e29b-41d4-a716-446655440000",
    "Commit 3f786850e387550fdc4b1c2e67e9d7f9c8a1b2c3 reverted",
    "Function test_regex_pii_scrubbing_pipeline_long_name failed",
    "Order 4111111111111112 shipped",
    "Ticket 900123456 escalated",
    "ZIP 45221-0001 and version 1.2.3",
    "token: expired",
])
def test_pii_scrubber_leaves_non_pii_alone(benign):
    assert DataSanitizationPipeline().scrub_pii(benign) == benign


def test_corporate_email_whitelist_is_case_insensitive_and_not_spoofable():
    pipeline = DataSanitizationPipeline()
    assert pipeline.scrub_pii("ping Admin@Enterprise.COM") == "ping Admin@Enterprise.COM"
    assert "[EMAIL_REDACTED]" in pipeline.scrub_pii("ping x@enterprise.com.evil.io")
