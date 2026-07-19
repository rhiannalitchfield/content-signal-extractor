"""
Core extraction engine for content-signal-extractor.
"""

from __future__ import annotations
import re
from collections import Counter

from .models import (
    SignalResult, RiskLevel, HarmTag,
    ToxicitySignals, PIISignals, URLSignals, CIBSignals, ManipulationSignals,
)
from .patterns import (
    EMAIL_RE, PHONE_RE, URL_RE, USERNAME_RE, ADDRESS_RE, SSN_RE, CARD_RE,
    URL_SHORTENERS, SUSPICIOUS_TLDS, IP_URL_RE,
    THREAT_RES, AGGRESSION_RES, SLUR_RES, SELF_HARM_RES,
    SEXUAL_CONTENT_RES, CSAM_RES,
    CTA_RES, URGENCY_RES, HASHTAG_RE,
    IMPERSONATION_RES, AUTHORITY_RES, EMOTIONAL_RES,
    FALSE_URGENCY_RES, SOCIAL_PROOF_RES,
)


# Bounds for the CIB heuristics, which scale super-linearly with input size.
# Coordinated-inauthentic patterns are dense and show up early, so these caps
# protect against pathological inputs without changing results on real posts.
_CIB_MAX_SENTENCES = 200
_CIB_MAX_WORDS = 5000


# ---------------------------------------------------------------------------
# Risk level helpers
# ---------------------------------------------------------------------------

def _risk(score: float) -> RiskLevel:
    if score == 0:       return RiskLevel.NONE
    if score < 0.3:      return RiskLevel.LOW
    if score < 0.65:     return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def _max_risk(*levels: RiskLevel) -> RiskLevel:
    order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]
    return max(levels, key=lambda l: order.index(l))


def _matches(res: list[re.Pattern], text: str) -> list[str]:
    """Return all matched strings across a list of compiled patterns."""
    found = []
    for pattern in res:
        for m in pattern.finditer(text):
            found.append(m.group(0).strip())
    return found


# ---------------------------------------------------------------------------
# Sub-extractors
# ---------------------------------------------------------------------------

def _extract_toxicity(text: str) -> ToxicitySignals:
    threat = any(p.search(text) for p in THREAT_RES)
    aggression = list(dict.fromkeys(_matches(AGGRESSION_RES, text)))  # dedup
    slurs = any(p.search(text) for p in SLUR_RES)
    self_harm = any(p.search(text) for p in SELF_HARM_RES)
    sexual = any(p.search(text) for p in SEXUAL_CONTENT_RES)

    # Composite score
    score = 0.0
    if threat:      score += 0.40
    if slurs:       score += 0.30
    if self_harm:   score += 0.40
    if aggression:  score += min(0.20, len(aggression) * 0.05)
    if sexual:      score += 0.10
    score = min(1.0, score)

    return ToxicitySignals(
        score=round(score, 4),
        threat_language=threat,
        aggression_markers=aggression[:10],  # cap list length
        slur_indicators=slurs,
        self_harm_language=self_harm,
        sexual_content=sexual,
        risk_level=_risk(score),
    )


def _extract_pii(text: str) -> PIISignals:
    emails = list(dict.fromkeys(EMAIL_RE.findall(text)))
    text_no_emails = EMAIL_RE.sub(' ', text)  # keep email domains out of the URL list
    phones = []
    for m in PHONE_RE.finditer(text):
        raw = m.group(0).strip()
        digits = re.sub(r'\D', '', raw)
        if 10 <= len(digits) <= 11:
            phones.append(raw)
    phones = list(dict.fromkeys(phones))

    urls = list(dict.fromkeys(URL_RE.findall(text_no_emails)))
    usernames = list(dict.fromkeys(USERNAME_RE.findall(text)))
    addresses = list(dict.fromkeys(ADDRESS_RE.findall(text)))
    has_ssn = bool(SSN_RE.search(text))
    has_card = bool(CARD_RE.search(text))

    pii_count = len(emails) + len(phones) + len(addresses) + (1 if has_ssn else 0) + (1 if has_card else 0)

    # Risk: SSN/card = high; multiple PII types = medium; any PII = low
    if has_ssn or has_card:
        risk = RiskLevel.HIGH
    elif pii_count >= 3 or (len(emails) > 0 and len(addresses) > 0):
        risk = RiskLevel.MEDIUM
    elif pii_count > 0:
        risk = RiskLevel.LOW
    else:
        risk = RiskLevel.NONE

    return PIISignals(
        emails=emails,
        phone_numbers=phones,
        urls=urls,
        usernames=usernames,
        potential_addresses=addresses,
        ssn_patterns=has_ssn,
        card_patterns=has_card,
        pii_count=pii_count,
        risk_level=risk,
    )


def _extract_urls(text: str) -> URLSignals:
    # Email addresses contain URL-shaped domains (jane@example.com -> example.com).
    # Blank out emails first so we don't miscount those domains as real URLs.
    text_no_emails = EMAIL_RE.sub(' ', text)
    urls = list(dict.fromkeys(URL_RE.findall(text_no_emails)))
    total = len(urls)
    density = round((total / max(len(text), 1)) * 100, 4)

    shorteners = []
    suspicious_tlds = []
    ip_urls = []

    for url in urls:
        url_lower = url.lower()
        # Shorteners
        for s in URL_SHORTENERS:
            if s in url_lower:
                shorteners.append(url)
                break
        # Suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if url_lower.endswith(tld) or f'{tld}/' in url_lower:
                suspicious_tlds.append(url)
                break
        # IP-based
        if IP_URL_RE.search(url):
            ip_urls.append(url)

    score = 0.0
    if ip_urls:         score += 0.4
    if suspicious_tlds: score += 0.3
    if shorteners:      score += 0.15
    if density > 0.5:   score += 0.15

    return URLSignals(
        total_urls=total,
        url_density=density,
        shorteners=list(dict.fromkeys(shorteners)),
        suspicious_tlds=list(dict.fromkeys(suspicious_tlds)),
        ip_based_urls=list(dict.fromkeys(ip_urls)),
        risk_level=_risk(min(1.0, score)),
    )


def _extract_cib(text: str) -> CIBSignals:
    # Templated language: repeated sentence structure heuristic.
    # The pairwise trigram comparison below is O(n^2) in sentence count, so cap
    # how many sentences we compare. Templated spam shows up in the first
    # handful of sentences; scanning more just burns time on large inputs.
    sentences = [s.strip() for s in re.split(r'[.!?\n]', text) if len(s.strip()) > 10]
    sentences = sentences[:_CIB_MAX_SENTENCES]
    templated = False
    if len(sentences) >= 3:
        # Check for high similarity via shared trigrams
        def trigrams(s: str) -> set:
            words = s.lower().split()
            return {' '.join(words[i:i+3]) for i in range(len(words)-2)}
        tg_sets = [trigrams(s) for s in sentences]
        for i in range(len(tg_sets)):
            for j in range(i+1, len(tg_sets)):
                if tg_sets[i] and tg_sets[j]:
                    overlap = len(tg_sets[i] & tg_sets[j]) / min(len(tg_sets[i]), len(tg_sets[j]))
                    if overlap > 0.5:
                        templated = True
                        break

    # Excessive repetition: same 3+ word phrase appears 3+ times. Cap the word
    # window so a very long document doesn't build an enormous phrase counter.
    words = text.lower().split()[:_CIB_MAX_WORDS]
    phrases = [' '.join(words[i:i+3]) for i in range(len(words)-2)]
    phrase_counts = Counter(phrases)
    excessive_rep = any(c >= 3 for c in phrase_counts.values())

    # Unusual punctuation
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    exclaim_count = text.count('!')
    question_count = text.count('?')
    unusual_punct = (
        caps_ratio > 0.3 or
        exclaim_count >= 3 or
        question_count >= 3 or
        '!!!' in text or '???' in text
    )

    hashtags = HASHTAG_RE.findall(text)
    hashtag_density = round((len(hashtags) / max(len(text), 1)) * 100, 4)

    cta_matches = _matches(CTA_RES, text)
    urgency_matches = list(dict.fromkeys(_matches(URGENCY_RES, text)))

    score = 0.0
    if templated:           score += 0.25
    if excessive_rep:       score += 0.20
    if len(cta_matches) >= 2: score += 0.25
    if len(urgency_matches) >= 2: score += 0.15
    if hashtag_density > 0.5:   score += 0.15

    return CIBSignals(
        templated_language=templated,
        excessive_repetition=excessive_rep,
        unusual_punctuation=unusual_punct,
        hashtag_density=hashtag_density,
        call_to_action_count=len(cta_matches),
        urgency_markers=urgency_matches[:10],
        risk_level=_risk(min(1.0, score)),
    )


def _extract_manipulation(text: str) -> ManipulationSignals:
    impersonation = list(dict.fromkeys(_matches(IMPERSONATION_RES, text)))
    authority = list(dict.fromkeys(_matches(AUTHORITY_RES, text)))
    emotional = list(dict.fromkeys(_matches(EMOTIONAL_RES, text)))
    false_urgency = list(dict.fromkeys(_matches(FALSE_URGENCY_RES, text)))
    social_proof = list(dict.fromkeys(_matches(SOCIAL_PROOF_RES, text)))

    score = 0.0
    if impersonation:   score += 0.35
    if false_urgency:   score += 0.30
    if emotional:       score += 0.20
    if authority:       score += 0.10
    if social_proof:    score += 0.05

    return ManipulationSignals(
        impersonation_markers=impersonation[:5],
        authority_claims=authority[:5],
        emotional_manipulation=emotional[:5],
        false_urgency=false_urgency[:5],
        social_proof_abuse=social_proof[:5],
        risk_level=_risk(min(1.0, score)),
    )


# ---------------------------------------------------------------------------
# Harm tag inference
# ---------------------------------------------------------------------------

def _infer_harm_tags(
    toxicity: ToxicitySignals,
    pii: PIISignals,
    urls: URLSignals,
    cib: CIBSignals,
    manipulation: ManipulationSignals,
    text: str,
) -> list[HarmTag]:
    tags = set()

    if toxicity.threat_language:
        tags.add(HarmTag.THREAT)
    if toxicity.slur_indicators:
        tags.add(HarmTag.HATE_SPEECH)
    if toxicity.self_harm_language:
        tags.add(HarmTag.SELF_HARM)
    if toxicity.sexual_content:
        tags.add(HarmTag.ADULT_CONTENT)
    if toxicity.aggression_markers:
        tags.add(HarmTag.HARASSMENT)
    if any(p.search(text) for p in CSAM_RES):
        tags.add(HarmTag.CSAM_SIGNAL)

    if pii.ssn_patterns or pii.card_patterns or (pii.emails and pii.potential_addresses):
        tags.add(HarmTag.DOXXING)

    if urls.suspicious_tlds or urls.ip_based_urls or manipulation.false_urgency:
        tags.add(HarmTag.PHISHING)

    if cib.call_to_action_count >= 2 or cib.templated_language:
        tags.add(HarmTag.COORDINATED)
    if cib.call_to_action_count >= 1 or urls.total_urls >= 3:
        tags.add(HarmTag.SPAM)

    if manipulation.impersonation_markers:
        tags.add(HarmTag.IMPERSONATION)
    if manipulation.emotional_manipulation or manipulation.social_proof_abuse:
        tags.add(HarmTag.MANIPULATION)

    return sorted(tags, key=lambda t: t.value)


# ---------------------------------------------------------------------------
# Flag generation
# ---------------------------------------------------------------------------

def _build_flags(
    toxicity: ToxicitySignals,
    pii: PIISignals,
    urls: URLSignals,
    cib: CIBSignals,
    manipulation: ManipulationSignals,
    text: str,
) -> list[str]:
    flags = []
    if toxicity.threat_language:
        flags.append("THREAT_LANGUAGE_DETECTED")
    if toxicity.slur_indicators:
        flags.append("SLUR_INDICATORS_DETECTED")
    if toxicity.self_harm_language:
        flags.append("SELF_HARM_LANGUAGE_DETECTED")
    if any(p.search(text) for p in CSAM_RES):
        flags.append("CSAM_SIGNAL_DETECTED")
    if pii.ssn_patterns:
        flags.append("SSN_PATTERN_DETECTED")
    if pii.card_patterns:
        flags.append("PAYMENT_CARD_PATTERN_DETECTED")
    if pii.emails and pii.potential_addresses:
        flags.append("PII_COMBINATION_DOXXING_RISK")
    if urls.ip_based_urls:
        flags.append("IP_BASED_URL_DETECTED")
    if urls.suspicious_tlds:
        flags.append("SUSPICIOUS_TLD_DETECTED")
    if manipulation.impersonation_markers:
        flags.append("IMPERSONATION_MARKERS_DETECTED")
    if manipulation.false_urgency:
        flags.append("PHISHING_PATTERN_DETECTED")
    if cib.templated_language and cib.call_to_action_count >= 1:
        flags.append("CIB_PATTERN_DETECTED")
    return flags


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def extract(text: str) -> SignalResult:
    """
    Extract T&S signals from a text string.

    Args:
        text: Input text to analyze.

    Returns:
        SignalResult with all signal categories populated.
    """
    if not text or not text.strip():
        raise ValueError("Input text must be a non-empty string.")

    toxicity    = _extract_toxicity(text)
    pii         = _extract_pii(text)
    urls        = _extract_urls(text)
    cib         = _extract_cib(text)
    manipulation = _extract_manipulation(text)

    harm_tags = _infer_harm_tags(toxicity, pii, urls, cib, manipulation, text)
    flags = _build_flags(toxicity, pii, urls, cib, manipulation, text)

    overall_risk = _max_risk(
        toxicity.risk_level,
        pii.risk_level,
        urls.risk_level,
        cib.risk_level,
        manipulation.risk_level,
    )

    return SignalResult(
        text_length=len(text),
        word_count=len(text.split()),
        overall_risk=overall_risk,
        harm_tags=harm_tags,
        toxicity=toxicity,
        pii=pii,
        urls=urls,
        cib=cib,
        manipulation=manipulation,
        flags=flags,
    )
