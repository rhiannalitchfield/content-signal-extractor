# content-signal-extractor

A lightweight Python library and CLI for extracting structured **Trust & Safety signals** from text — zero external dependencies, rules-based, fast, and fully auditable.

Feed it a piece of text. Get back structured JSON signals a human reviewer or downstream classifier can act on.

---

## Signal Categories

| Category | What it detects |
|---|---|
| **Toxicity** | Threat language, aggression markers, slur indicators, self-harm language, sexual content |
| **PII** | Emails, phone numbers, URLs, @usernames, addresses, SSN patterns, payment card patterns |
| **URLs** | Total count, density, URL shorteners, suspicious TLDs, IP-based URLs |
| **CIB** | Coordinated inauthentic behavior: templated language, excessive repetition, call-to-action density, urgency markers, hashtag density |
| **Manipulation** | Impersonation markers, authority claims, emotional manipulation, false urgency / phishing patterns, social proof abuse |

Every result also includes:
- **Overall risk level** — `none / low / medium / high`
- **Harm tags** — inferred category labels (`harassment`, `phishing`, `doxxing`, `threat`, `spam`, `coordinated`, `impersonation`, etc.)
- **Flags** — named high-signal findings for fast triage (`THREAT_LANGUAGE_DETECTED`, `SSN_PATTERN_DETECTED`, `PHISHING_PATTERN_DETECTED`, etc.)

---

## Installation

```bash
git clone https://github.com/rhiannalitchfield/content-signal-extractor
cd content-signal-extractor
pip install -e .
```

**Python 3.8+. No external dependencies.**

---

## Quick Start

### As a library

```python
from content_signals import extract

result = extract("Your account has been suspended. Click here to verify: http://192.168.1.1/verify.html Act now!")

print(result.overall_risk)          # RiskLevel.HIGH
print(result.harm_tags)             # [HarmTag.PHISHING, HarmTag.SPAM]
print(result.flags)                 # ['IP_BASED_URL_DETECTED', 'PHISHING_PATTERN_DETECTED']
print(result.toxicity.score)        # 0.0
print(result.manipulation.false_urgency)  # ['Your account has been suspended...']

# Full JSON output
import json
print(json.dumps(result.to_dict(), indent=2))
```

### As a CLI

```bash
# Analyze inline text
content-signals "You better watch your back. I know where you live @user123."

# Analyze a file
content-signals --file message.txt

# JSON output
content-signals --file message.txt --format json

# Save report to file
content-signals --file message.txt --output report.txt

# Flags only (for pipeline use)
content-signals --file message.txt --flags-only

# Read from stdin
echo "Your text here" | content-signals --stdin
```

---

## Output

### Text Report

```
============================================================
  Content Signal Extractor — Analysis Report
  Generated : 2024-03-20 14:00 UTC
============================================================

[ OVERVIEW ]
  Text length    : 312 chars / 52 words
  Overall risk   : 🔴 HIGH
  Harm tags      : impersonation, phishing, spam

[ FLAGS ]
  ⚑  IMPERSONATION_MARKERS_DETECTED
  ⚑  PHISHING_PATTERN_DETECTED
  ⚑  IP_BASED_URL_DETECTED

[ TOXICITY  ⚪ NONE ]
  Score          : 0.0000  ░░░░░░░░░░░░░░░░░░░░
  Threat language: no
  Slur indicators: no
  Self-harm lang : no
  Sexual content : no

[ PII  🟢 LOW ]
  PII count      : 1
  Emails         : victim@example.com

[ URLS  🔴 HIGH ]
  Total URLs     : 1
  Density        : 0.3205 per 100 chars
  IP-based URLs  : http://192.168.1.1/verify.html

[ MANIPULATION  🔴 HIGH ]
  Impersonation  : This is your bank
  False urgency  : Your account will be suspended
```

### JSON Output

```json
{
  "overall_risk": "high",
  "harm_tags": ["impersonation", "phishing", "spam"],
  "flags": ["IMPERSONATION_MARKERS_DETECTED", "PHISHING_PATTERN_DETECTED"],
  "toxicity": {
    "score": 0.0,
    "threat_language": false,
    "slur_indicators": false,
    ...
  },
  "manipulation": {
    "impersonation_markers": ["This is your bank"],
    "false_urgency": ["Your account will be suspended"],
    "risk_level": "high"
  }
}
```

---

## Risk Levels

| Level | Meaning |
|---|---|
| `none` | No signals detected in this category |
| `low` | Minor signals present; likely benign but worth logging |
| `medium` | Multiple signals or moderate-severity match; warrants review |
| `high` | High-confidence harmful signal; immediate action likely needed |

---

## Design Notes

**Rules-based by design.** No ML model, no API calls, no external dependencies. Every signal is traceable to a specific pattern in `patterns.py` — you can read, audit, and modify the logic directly. This makes it suitable for production pipelines where explainability and latency matter.

**Slurs are flagged, not surfaced.** `slur_indicators` returns `True/False` only. The matched text is never included in the output to avoid replicating harmful content in logs and reports.

**PII is extracted, not redacted.** The library extracts PII for signal purposes — if you need redaction, pipe the output into a separate processing step. SSN and card patterns return `True/False` only for the same reason as slurs.

**Harm tags are inferred, not labeled.** Tags like `phishing` and `doxxing` are inferred from signal combinations, not assigned by a classifier. Treat them as routing suggestions, not ground truth.

---

## Project Structure

```
content-signal-extractor/
├── content_signals/
│   ├── __init__.py       # Public API: extract(), SignalResult
│   ├── models.py         # Data models: SignalResult, RiskLevel, HarmTag, etc.
│   ├── patterns.py       # All regex patterns and keyword lists
│   ├── extractor.py      # Core extraction engine
│   ├── report.py         # Text report generation
│   └── cli.py            # Command-line interface
├── examples/
│   └── sample_texts.py   # Example texts for testing
├── tests/
│   └── test_extractor.py # 43 tests across all signal categories
├── setup.py
├── pyproject.toml
└── README.md
```

---

## Extending

**Add a new pattern:** Add a compiled regex to `patterns.py`, import it in `extractor.py`, and wire it into the relevant `_extract_*` function.

**Add a new signal category:** Create a new dataclass in `models.py`, add it to `SignalResult`, write an `_extract_*` function in `extractor.py`, and add the relevant section to `report.py`.

**Use as a pipeline pre-processor:** The `--flags-only` CLI flag outputs one flag per line — easy to pipe into downstream tooling:

```bash
content-signals --file message.txt --flags-only | grep "THREAT\|PHISHING"
```

---

## Part of the T&S Tooling Portfolio

This tool is part of a suite of open-source Trust & Safety tools:

- [incident-timeline-builder](https://github.com/rhiannalitchfield/incident-timeline-builder) — Build structured incident timelines with escalation detection and response lag analysis
- [prompt-pressure-suite](https://github.com/rhiannalitchfield/prompt-pressure-suite) — Eval framework for measuring LLM behavior under adversarial follow-up pressure

---

## License

MIT
