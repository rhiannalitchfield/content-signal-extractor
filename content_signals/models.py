"""
Data models for content-signal-extractor.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    NONE    = "none"
    LOW     = "low"
    MEDIUM  = "medium"
    HIGH    = "high"


class HarmTag(str, Enum):
    HARASSMENT          = "harassment"
    HATE_SPEECH         = "hate_speech"
    THREAT              = "threat"
    SELF_HARM           = "self_harm"
    SPAM                = "spam"
    PHISHING            = "phishing"
    DOXXING             = "doxxing"
    IMPERSONATION       = "impersonation"
    MANIPULATION        = "manipulation"
    COORDINATED         = "coordinated"
    CSAM_SIGNAL         = "csam_signal"
    ADULT_CONTENT       = "adult_content"
    ILLEGAL_ACTIVITY    = "illegal_activity"
    MISINFORMATION      = "misinformation"


@dataclass
class PIIMatch:
    pii_type: str       # email, phone, url, address, username, ssn, card
    value: str          # matched value (may be partially redacted)
    start: int
    end: int


@dataclass
class ToxicitySignals:
    score: float                        # 0.0–1.0 composite
    threat_language: bool
    aggression_markers: list[str]       # matched phrases
    slur_indicators: bool               # True if slur patterns found (not surfaced verbatim)
    self_harm_language: bool
    sexual_content: bool
    risk_level: RiskLevel


@dataclass
class PIISignals:
    emails: list[str]
    phone_numbers: list[str]
    urls: list[str]
    usernames: list[str]               # @mentions
    potential_addresses: list[str]
    ssn_patterns: bool                 # True/False only — don't surface value
    card_patterns: bool
    pii_count: int
    risk_level: RiskLevel


@dataclass
class URLSignals:
    total_urls: int
    url_density: float                 # urls per 100 chars
    shorteners: list[str]             # t.co, bit.ly, etc.
    suspicious_tlds: list[str]        # .xyz, .tk, etc.
    ip_based_urls: list[str]
    risk_level: RiskLevel


@dataclass
class CIBSignals:
    """Coordinated Inauthentic Behavior signals."""
    templated_language: bool           # boilerplate / copy-paste patterns
    excessive_repetition: bool         # same phrase repeated 3+ times
    unusual_punctuation: bool          # !!!, ???, ALL CAPS ratio
    hashtag_density: float            # hashtags per 100 chars
    call_to_action_count: int         # "share this", "retweet", "spread the word"
    urgency_markers: list[str]        # "act now", "limited time", "before it's deleted"
    risk_level: RiskLevel


@dataclass
class ManipulationSignals:
    impersonation_markers: list[str]  # "I am from X", "official account"
    authority_claims: list[str]       # "as a doctor", "government official"
    emotional_manipulation: list[str] # guilt-tripping, love-bombing patterns
    false_urgency: list[str]
    social_proof_abuse: list[str]     # "everyone knows", "scientists agree"
    risk_level: RiskLevel


@dataclass
class SignalResult:
    """Complete extraction result for a piece of text."""
    text_length: int
    word_count: int
    overall_risk: RiskLevel
    harm_tags: list[HarmTag]

    toxicity: ToxicitySignals
    pii: PIISignals
    urls: URLSignals
    cib: CIBSignals
    manipulation: ManipulationSignals

    # Flat summary for quick downstream use
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to a plain dict (JSON-safe)."""
        return {
            "text_length": self.text_length,
            "word_count": self.word_count,
            "overall_risk": self.overall_risk.value,
            "harm_tags": [t.value for t in self.harm_tags],
            "flags": self.flags,
            "toxicity": {
                "score": self.toxicity.score,
                "threat_language": self.toxicity.threat_language,
                "aggression_markers": self.toxicity.aggression_markers,
                "slur_indicators": self.toxicity.slur_indicators,
                "self_harm_language": self.toxicity.self_harm_language,
                "sexual_content": self.toxicity.sexual_content,
                "risk_level": self.toxicity.risk_level.value,
            },
            "pii": {
                "emails": self.pii.emails,
                "phone_numbers": self.pii.phone_numbers,
                "urls": self.pii.urls,
                "usernames": self.pii.usernames,
                "potential_addresses": self.pii.potential_addresses,
                "ssn_patterns": self.pii.ssn_patterns,
                "card_patterns": self.pii.card_patterns,
                "pii_count": self.pii.pii_count,
                "risk_level": self.pii.risk_level.value,
            },
            "urls": {
                "total_urls": self.urls.total_urls,
                "url_density": self.urls.url_density,
                "shorteners": self.urls.shorteners,
                "suspicious_tlds": self.urls.suspicious_tlds,
                "ip_based_urls": self.urls.ip_based_urls,
                "risk_level": self.urls.risk_level.value,
            },
            "cib": {
                "templated_language": self.cib.templated_language,
                "excessive_repetition": self.cib.excessive_repetition,
                "unusual_punctuation": self.cib.unusual_punctuation,
                "hashtag_density": self.cib.hashtag_density,
                "call_to_action_count": self.cib.call_to_action_count,
                "urgency_markers": self.cib.urgency_markers,
                "risk_level": self.cib.risk_level.value,
            },
            "manipulation": {
                "impersonation_markers": self.manipulation.impersonation_markers,
                "authority_claims": self.manipulation.authority_claims,
                "emotional_manipulation": self.manipulation.emotional_manipulation,
                "false_urgency": self.manipulation.false_urgency,
                "social_proof_abuse": self.manipulation.social_proof_abuse,
                "risk_level": self.manipulation.risk_level.value,
            },
        }
