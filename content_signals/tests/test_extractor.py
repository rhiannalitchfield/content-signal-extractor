"""
Tests for content-signal-extractor.
Run with: python -m pytest tests/ -v
"""

from __future__ import annotations
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from content_signals.extractor import extract
from content_signals.models import RiskLevel, HarmTag
from content_signals.report import generate_report


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

THREAT_TEXT = "I know where you live and you better watch your back. I will kill you."
HARASSMENT_TEXT = "You're a worthless pathetic piece of garbage. Shut the fuck up loser."
SELF_HARM_TEXT = "I've been cutting myself and I want to die. I don't want to exist anymore."
PHISHING_TEXT = "Your account has been suspended. Click here to verify: http://192.168.1.1/verify.html Act now before it's deleted!"
CIB_TEXT = "Share this now! Share this now! Share this now! Wake up people! Make this viral! Copy and paste this everywhere! #ShareNow #WakeUp"
DOXXING_TEXT = "Her email is victim@email.com and she lives at 123 Main Street. Her phone is 555-867-5309."
CLEAN_TEXT = "Hey, can we reschedule the meeting to Thursday? Looking forward to seeing the team."
IMPERSONATION_TEXT = "This is your bank. I am from Bank of America official account. Verify your account immediately or it will be suspended."


# ---------------------------------------------------------------------------
# Basic extraction
# ---------------------------------------------------------------------------

class TestBasicExtraction:
    def test_empty_text_raises(self):
        with pytest.raises(ValueError):
            extract("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError):
            extract("   ")

    def test_clean_text_low_risk(self):
        result = extract(CLEAN_TEXT)
        assert result.overall_risk in (RiskLevel.NONE, RiskLevel.LOW)
        assert result.toxicity.score < 0.2
        assert not result.flags

    def test_result_has_all_fields(self):
        result = extract(CLEAN_TEXT)
        assert result.text_length > 0
        assert result.word_count > 0
        assert result.toxicity is not None
        assert result.pii is not None
        assert result.urls is not None
        assert result.cib is not None
        assert result.manipulation is not None

    def test_to_dict_is_json_safe(self):
        import json
        result = extract(CLEAN_TEXT)
        d = result.to_dict()
        # Should not raise
        json.dumps(d)
        assert "overall_risk" in d
        assert "harm_tags" in d
        assert "toxicity" in d


# ---------------------------------------------------------------------------
# Toxicity
# ---------------------------------------------------------------------------

class TestToxicity:
    def test_threat_detected(self):
        result = extract(THREAT_TEXT)
        assert result.toxicity.threat_language is True
        assert result.toxicity.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
        assert HarmTag.THREAT in result.harm_tags

    def test_aggression_detected(self):
        result = extract(HARASSMENT_TEXT)
        assert len(result.toxicity.aggression_markers) > 0
        assert HarmTag.HARASSMENT in result.harm_tags

    def test_self_harm_detected(self):
        result = extract(SELF_HARM_TEXT)
        assert result.toxicity.self_harm_language is True
        assert HarmTag.SELF_HARM in result.harm_tags
        assert "SELF_HARM_LANGUAGE_DETECTED" in result.flags

    def test_slurs_not_surfaced_verbatim(self):
        # Slur indicators should be True/False only — matched text not returned
        result = extract("that nigger needs to go")
        assert result.toxicity.slur_indicators is True
        # The matched slur text should NOT appear in aggression_markers
        for marker in result.toxicity.aggression_markers:
            assert "nigger" not in marker.lower()

    def test_clean_text_no_toxicity(self):
        result = extract(CLEAN_TEXT)
        assert result.toxicity.threat_language is False
        assert result.toxicity.slur_indicators is False
        assert result.toxicity.self_harm_language is False
        assert result.toxicity.score < 0.1

    def test_toxicity_score_range(self):
        for text in [THREAT_TEXT, HARASSMENT_TEXT, SELF_HARM_TEXT, CLEAN_TEXT]:
            result = extract(text)
            assert 0.0 <= result.toxicity.score <= 1.0


# ---------------------------------------------------------------------------
# PII
# ---------------------------------------------------------------------------

class TestPII:
    def test_email_detected(self):
        result = extract("Contact me at user@example.com for details.")
        assert "user@example.com" in result.pii.emails

    def test_phone_detected(self):
        result = extract("Call me at 555-867-5309 anytime.")
        assert len(result.pii.phone_numbers) > 0

    def test_username_detected(self):
        result = extract("Follow @rhiannalitchfield on LinkedIn.")
        assert "@rhiannalitchfield" in result.pii.usernames

    def test_address_detected(self):
        result = extract("She lives at 123 Main Street near downtown.")
        assert len(result.pii.potential_addresses) > 0

    def test_ssn_flagged(self):
        result = extract("My SSN is 123-45-6789 please keep it private.")
        assert result.pii.ssn_patterns is True
        assert "SSN_PATTERN_DETECTED" in result.flags

    def test_card_flagged(self):
        result = extract("Card number: 4532015112830366 expires 12/26")
        assert result.pii.card_patterns is True
        assert "PAYMENT_CARD_PATTERN_DETECTED" in result.flags

    def test_doxxing_combination(self):
        result = extract(DOXXING_TEXT)
        assert result.pii.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
        assert HarmTag.DOXXING in result.harm_tags

    def test_pii_count_accurate(self):
        result = extract("Email: a@b.com, phone: 555-123-4567")
        assert result.pii.pii_count >= 1


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

class TestURLs:
    def test_url_detected(self):
        result = extract("Visit https://example.com for more info.")
        assert result.urls.total_urls >= 1

    def test_ip_url_flagged(self):
        result = extract("Click here: http://192.168.1.1/malware.exe")
        assert len(result.urls.ip_based_urls) > 0
        assert "IP_BASED_URL_DETECTED" in result.flags

    def test_suspicious_tld_flagged(self):
        result = extract("Download at http://getfreestuff.xyz/download")
        assert len(result.urls.suspicious_tlds) > 0
        assert "SUSPICIOUS_TLD_DETECTED" in result.flags

    def test_shortener_detected(self):
        result = extract("Check this out: https://bit.ly/abc123")
        assert len(result.urls.shorteners) > 0

    def test_url_density_calculated(self):
        result = extract("https://a.com https://b.com https://c.com short text")
        assert result.urls.url_density > 0

    def test_clean_text_no_url_risk(self):
        result = extract(CLEAN_TEXT)
        assert result.urls.risk_level == RiskLevel.NONE


# ---------------------------------------------------------------------------
# CIB
# ---------------------------------------------------------------------------

class TestCIB:
    def test_cta_detected(self):
        result = extract(CIB_TEXT)
        assert result.cib.call_to_action_count >= 2

    def test_urgency_detected(self):
        result = extract("Act now! Limited time offer! Before it's deleted!")
        assert len(result.cib.urgency_markers) > 0

    def test_excessive_repetition(self):
        result = extract("share this now share this now share this now")
        assert result.cib.excessive_repetition is True

    def test_unusual_punctuation_caps(self):
        result = extract("THIS IS VERY IMPORTANT!!! DO NOT IGNORE!!! ACT NOW!!!")
        assert result.cib.unusual_punctuation is True

    def test_hashtag_density(self):
        result = extract("text #one #two #three #four #five short")
        assert result.cib.hashtag_density > 0

    def test_clean_text_no_cib(self):
        result = extract(CLEAN_TEXT)
        assert result.cib.call_to_action_count == 0
        assert result.cib.risk_level == RiskLevel.NONE


# ---------------------------------------------------------------------------
# Manipulation
# ---------------------------------------------------------------------------

class TestManipulation:
    def test_impersonation_detected(self):
        result = extract(IMPERSONATION_TEXT)
        assert len(result.manipulation.impersonation_markers) > 0
        assert HarmTag.IMPERSONATION in result.harm_tags
        assert "IMPERSONATION_MARKERS_DETECTED" in result.flags

    def test_false_urgency_detected(self):
        result = extract("Your account will be suspended. Verify immediately or access will be terminated.")
        assert len(result.manipulation.false_urgency) > 0
        assert "PHISHING_PATTERN_DETECTED" in result.flags

    def test_authority_claim_detected(self):
        result = extract("As a doctor, I can tell you that this treatment is safe.")
        assert len(result.manipulation.authority_claims) > 0

    def test_emotional_manipulation_detected(self):
        result = extract("After everything I've done for you, you're making me do this. You're my only hope.")
        assert len(result.manipulation.emotional_manipulation) > 0

    def test_social_proof_detected(self):
        result = extract("Everyone knows the truth. Scientists agree this is real. Wake up sheeple!")
        assert len(result.manipulation.social_proof_abuse) > 0

    def test_clean_text_no_manipulation(self):
        result = extract(CLEAN_TEXT)
        assert result.manipulation.risk_level == RiskLevel.NONE


# ---------------------------------------------------------------------------
# Harm tags and flags
# ---------------------------------------------------------------------------

class TestHarmTagsAndFlags:
    def test_phishing_tags(self):
        result = extract(PHISHING_TEXT)
        tags = result.harm_tags
        assert HarmTag.PHISHING in tags or HarmTag.SPAM in tags

    def test_no_tags_for_clean_text(self):
        result = extract(CLEAN_TEXT)
        assert len(result.harm_tags) == 0

    def test_flags_are_strings(self):
        result = extract(THREAT_TEXT)
        assert all(isinstance(f, str) for f in result.flags)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class TestReport:
    def test_report_has_sections(self):
        result = extract(THREAT_TEXT)
        report = generate_report(result)
        for section in ["OVERVIEW", "TOXICITY", "PII", "URLS", "CIB", "MANIPULATION"]:
            assert section in report

    def test_report_with_preview(self):
        result = extract(CLEAN_TEXT)
        report = generate_report(result, text_preview=CLEAN_TEXT)
        assert "TEXT PREVIEW" in report

    def test_report_flags_section(self):
        result = extract(THREAT_TEXT)
        report = generate_report(result)
        if result.flags:
            assert "FLAGS" in report
