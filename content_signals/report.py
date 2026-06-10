"""
Report generation for content-signal-extractor.
"""

from __future__ import annotations
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from .models import SignalResult, RiskLevel


RISK_ICON = {
    RiskLevel.NONE:   "⚪",
    RiskLevel.LOW:    "🟢",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.HIGH:   "🔴",
}

BAR_WIDTH = 20


def _bar(score: float, width: int = BAR_WIDTH) -> str:
    filled = round(score * width)
    return "█" * filled + "░" * (width - filled)


def _section(title: str) -> str:
    return f"\n[ {title} ]"


def generate_report(
    result: SignalResult,
    text_preview: Optional[str] = None,
    output_path: Optional[Union[str, Path]] = None,
) -> str:
    lines = []
    SEP = "=" * 60
    THIN = "-" * 60

    lines += [
        SEP,
        "  Content Signal Extractor — Analysis Report",
        f"  Generated : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        SEP,
    ]

    # ── Overview ──────────────────────────────────────────────────────────
    risk_icon = RISK_ICON[result.overall_risk]
    lines += [
        _section("OVERVIEW"),
        f"  Text length    : {result.text_length} chars / {result.word_count} words",
        f"  Overall risk   : {risk_icon} {result.overall_risk.value.upper()}",
        f"  Harm tags      : {', '.join(t.value for t in result.harm_tags) or 'none'}",
    ]

    if result.flags:
        lines.append(_section("FLAGS"))
        for flag in result.flags:
            lines.append(f"  ⚑  {flag}")

    # ── Toxicity ──────────────────────────────────────────────────────────
    t = result.toxicity
    lines += [
        _section(f"TOXICITY  {RISK_ICON[t.risk_level]} {t.risk_level.value.upper()}"),
        f"  Score          : {t.score:.4f}  {_bar(t.score)}",
        f"  Threat language: {'YES' if t.threat_language else 'no'}",
        f"  Slur indicators: {'YES' if t.slur_indicators else 'no'}",
        f"  Self-harm lang : {'YES' if t.self_harm_language else 'no'}",
        f"  Sexual content : {'YES' if t.sexual_content else 'no'}",
    ]
    if t.aggression_markers:
        lines.append(f"  Aggression ({len(t.aggression_markers)}): {' | '.join(t.aggression_markers[:5])}")

    # ── PII ───────────────────────────────────────────────────────────────
    p = result.pii
    lines += [
        _section(f"PII  {RISK_ICON[p.risk_level]} {p.risk_level.value.upper()}"),
        f"  PII count      : {p.pii_count}",
        f"  SSN patterns   : {'YES' if p.ssn_patterns else 'no'}",
        f"  Card patterns  : {'YES' if p.card_patterns else 'no'}",
    ]
    if p.emails:
        lines.append(f"  Emails ({len(p.emails)})   : {', '.join(p.emails[:5])}")
    if p.phone_numbers:
        lines.append(f"  Phones ({len(p.phone_numbers)})   : {', '.join(p.phone_numbers[:5])}")
    if p.usernames:
        lines.append(f"  Usernames ({len(p.usernames)}): {', '.join(p.usernames[:5])}")
    if p.potential_addresses:
        lines.append(f"  Addresses ({len(p.potential_addresses)}): {', '.join(p.potential_addresses[:3])}")

    # ── URLs ──────────────────────────────────────────────────────────────
    u = result.urls
    lines += [
        _section(f"URLS  {RISK_ICON[u.risk_level]} {u.risk_level.value.upper()}"),
        f"  Total URLs     : {u.total_urls}",
        f"  Density        : {u.url_density:.4f} per 100 chars",
    ]
    if u.shorteners:
        lines.append(f"  Shorteners ({len(u.shorteners)}): {', '.join(u.shorteners[:3])}")
    if u.suspicious_tlds:
        lines.append(f"  Suspicious TLDs: {', '.join(u.suspicious_tlds[:3])}")
    if u.ip_based_urls:
        lines.append(f"  IP-based URLs  : {', '.join(u.ip_based_urls[:3])}")

    # ── CIB ───────────────────────────────────────────────────────────────
    c = result.cib
    lines += [
        _section(f"CIB (COORDINATED BEHAVIOR)  {RISK_ICON[c.risk_level]} {c.risk_level.value.upper()}"),
        f"  Templated lang : {'YES' if c.templated_language else 'no'}",
        f"  Excess repeat  : {'YES' if c.excessive_repetition else 'no'}",
        f"  Unusual punct  : {'YES' if c.unusual_punctuation else 'no'}",
        f"  Hashtag density: {c.hashtag_density:.4f} per 100 chars",
        f"  CTAs found     : {c.call_to_action_count}",
    ]
    if c.urgency_markers:
        lines.append(f"  Urgency ({len(c.urgency_markers)})  : {' | '.join(c.urgency_markers[:4])}")

    # ── Manipulation ──────────────────────────────────────────────────────
    m = result.manipulation
    lines += [
        _section(f"MANIPULATION  {RISK_ICON[m.risk_level]} {m.risk_level.value.upper()}"),
    ]
    if m.impersonation_markers:
        lines.append(f"  Impersonation  : {' | '.join(m.impersonation_markers[:3])}")
    if m.authority_claims:
        lines.append(f"  Authority claim: {' | '.join(m.authority_claims[:3])}")
    if m.emotional_manipulation:
        lines.append(f"  Emotional manip: {' | '.join(m.emotional_manipulation[:3])}")
    if m.false_urgency:
        lines.append(f"  False urgency  : {' | '.join(m.false_urgency[:3])}")
    if m.social_proof_abuse:
        lines.append(f"  Social proof   : {' | '.join(m.social_proof_abuse[:3])}")
    if not any([m.impersonation_markers, m.authority_claims, m.emotional_manipulation,
                m.false_urgency, m.social_proof_abuse]):
        lines.append("  No manipulation signals detected.")

    # ── Text preview ──────────────────────────────────────────────────────
    if text_preview:
        preview = text_preview[:200] + ("..." if len(text_preview) > 200 else "")
        lines += [_section("TEXT PREVIEW"), f"  {preview}"]

    lines += ["", SEP, "  END OF REPORT", SEP]

    report = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
    return report
