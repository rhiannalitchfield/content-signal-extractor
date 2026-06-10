"""
Pattern library for content-signal-extractor.
All regex patterns and keyword lists in one auditable place.
"""

from __future__ import annotations
import re

# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

PHONE_RE = re.compile(
    r'(?<!\d)'
    r'(\+?1[\s.\-]?)?'
    r'(\(?\d{3}\)?[\s.\-]?)'
    r'(\d{3}[\s.\-]?)'
    r'(\d{4})'
    r'(?!\d)'
)

URL_RE = re.compile(
    r'https?://[^\s<>"\']+|'
    r'www\.[^\s<>"\']+|'
    r'\b[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
    re.IGNORECASE
)

USERNAME_RE = re.compile(r'@[A-Za-z0-9_]{1,50}')

# Street address heuristic: number + street name + street type
ADDRESS_RE = re.compile(
    r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,40}'
    r'(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|'
    r'Lane|Ln|Court|Ct|Place|Pl|Way|Circle|Cir)\b',
    re.IGNORECASE
)

SSN_RE = re.compile(r'\b(?!000|666|9\d{2})\d{3}[-\s]?\d{2}[-\s]?\d{4}\b')

CARD_RE = re.compile(
    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|'       # Visa
    r'5[1-5][0-9]{14}|'                      # Mastercard
    r'3[47][0-9]{13}|'                       # Amex
    r'6(?:011|5[0-9]{2})[0-9]{12})\b'       # Discover
)

# ---------------------------------------------------------------------------
# URL sub-patterns
# ---------------------------------------------------------------------------

URL_SHORTENERS = {
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'buff.ly',
    'short.io', 'rebrand.ly', 'tiny.cc', 'is.gd', 'v.gd', 'lnkd.in',
}

SUSPICIOUS_TLDS = {
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click',
    '.download', '.loan', '.review', '.stream', '.win', '.racing',
}

IP_URL_RE = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
)

# ---------------------------------------------------------------------------
# Toxicity patterns
# ---------------------------------------------------------------------------

THREAT_PATTERNS = [
    r'\b(i(?:\'ll| will| am going to|\'m going to)) (kill|hurt|destroy|end|eliminate|attack|shoot|stab|beat)\b',
    r'\b(you(?:\'re| are) (dead|finished|going to (die|pay|regret))|watch your back)\b',
    r'\b(gonna (get|find|hurt|kill) you)\b',
    r'\b(i know where you (live|work|go))\b',
    r'\b(better watch (out|yourself))\b',
    r'\b(hope you (die|rot|suffer|burn))\b',
    r'\b(kill (yourself|urself|ur self))\b',
    r'\byou should (die|kill yourself|not exist)\b',
]
THREAT_RES = [re.compile(p, re.IGNORECASE) for p in THREAT_PATTERNS]

AGGRESSION_PATTERNS = [
    r'\b(shut (the fuck |the )?(up|it))\b',
    r'\b(you(?:\'re| are) (a )?(pathetic|worthless|disgusting|trash|garbage|scum|stupid|idiot|moron|loser|piece of (shit|crap)))\b',
    r'\b(go (fuck|screw|kill) (yourself|urself))\b',
    r'\b(nobody (likes|cares about|wants) you)\b',
    r'\b(die (already|bitch|loser))\b',
    r'\b(i hate (you|this|everything))\b',
    r'\b(f+u+c+k+ ?(you|off|this))\b',
]
AGGRESSION_RES = [re.compile(p, re.IGNORECASE) for p in AGGRESSION_PATTERNS]

# Slur detection — flag presence only, don't surface the matched text
SLUR_PATTERNS = [
    r'\bn[i1!]+g+[ae3]+r',
    r'\bf+[a4@]+g+[o0]+t',
    r'\bk[i1]+k[e3]+\b',
    r'\bs+p[i1]+[ck]+\b',
    r'\bc+h[i1]+n+[ck]+\b',
    r'\bw+[e3]+tb+[a4]+c+k',
    r'\btr[a4@]+nn[yi1!]+\b',
    r'\br[e3]+t[a4]+rd',
]
SLUR_RES = [re.compile(p, re.IGNORECASE) for p in SLUR_PATTERNS]

SELF_HARM_PATTERNS = [
    r'\b(cut(ting)? (myself|yourself|my (wrists?|arms?|legs?)))\b',
    r'\b(want(ing)? to (die|hurt myself|end it|not exist))\b',
    r'\b(suicid(e|al|ally))\b',
    r'\b(kill(ing)? (my|your)?self)\b',
    r'\b(self[\s\-]?harm(ing)?)\b',
    r'\b(overdos(e|ing))\b',
    r'\b(don\'t want to (live|be here|exist) anymore)\b',
    r'\b(no (reason|point) (to live|in living|in going on))\b',
]
SELF_HARM_RES = [re.compile(p, re.IGNORECASE) for p in SELF_HARM_PATTERNS]

SEXUAL_CONTENT_PATTERNS = [
    r'\b(send (nudes?|pics?|photos?|pictures?))\b',
    r'\b(nude|naked|nsfw|explicit)\b',
    r'\b(sex(ual|ually|ting)?)\b',
    r'\b(porn(ography|ographic)?)\b',
    r'\b(dick pic|cock pic|tit pic)\b',
    r'\b(only ?fans|of content)\b',
]
SEXUAL_CONTENT_RES = [re.compile(p, re.IGNORECASE) for p in SEXUAL_CONTENT_PATTERNS]

# CSAM-specific signals (very conservative — presence alone is high signal)
CSAM_PATTERNS = [
    r'\b(minor|child|kid|teen|underage).{0,30}(nude|naked|explicit|sexual|sex)',
    r'\b(cp|csam|csa)\b',
    r'\b(loli(ta)?|shota)\b',
    r'\b(jailbait)\b',
]
CSAM_RES = [re.compile(p, re.IGNORECASE) for p in CSAM_PATTERNS]

# ---------------------------------------------------------------------------
# CIB patterns
# ---------------------------------------------------------------------------

CALL_TO_ACTION_PATTERNS = [
    r'\b(share (this|now|immediately|before it\'?s? (gone|deleted|censored)))\b',
    r'\b(retweet|re-tweet|rt this)\b',
    r'\b(spread (the word|this|awareness))\b',
    r'\b(copy (and )?paste|copy\/paste)\b',
    r'\b(send this to (everyone|all your|your friends))\b',
    r'\b(forward this|pass this on)\b',
    r'\b(make this viral|go viral)\b',
]
CTA_RES = [re.compile(p, re.IGNORECASE) for p in CALL_TO_ACTION_PATTERNS]

URGENCY_PATTERNS = [
    r'\b(act (now|immediately|fast|quickly))\b',
    r'\b(limited (time|offer|spots?))\b',
    r'\b(before (it\'?s? (too late|deleted|removed|gone|censored)))\b',
    r'\b(don\'?t (wait|delay|miss this))\b',
    r'\b(urgent(ly)?|emergency|breaking)\b',
    r'\b(expires? (soon|today|in \d+ (hours?|minutes?|days?)))\b',
    r'\b(last chance|final (warning|notice|reminder))\b',
    r'\b(they (don\'?t want you to|are trying to|will) (know|see|hear))\b',
]
URGENCY_RES = [re.compile(p, re.IGNORECASE) for p in URGENCY_PATTERNS]

HASHTAG_RE = re.compile(r'#[A-Za-z0-9_]+')

# ---------------------------------------------------------------------------
# Manipulation patterns
# ---------------------------------------------------------------------------

IMPERSONATION_PATTERNS = [
    r'\b(i am (from|with|representing|an official of|a member of))\b',
    r'\b(official (account|representative|spokesperson|channel))\b',
    r'\b(this is (your|a) (bank|government|irs|fbi|police|amazon|apple|google|microsoft|paypal))\b',
    r'\b(verified (account|representative))\b',
    r'\b(speaking on behalf of)\b',
]
IMPERSONATION_RES = [re.compile(p, re.IGNORECASE) for p in IMPERSONATION_PATTERNS]

AUTHORITY_CLAIM_PATTERNS = [
    r'\b(as a (doctor|physician|nurse|lawyer|attorney|officer|agent|expert|professor|scientist|researcher))\b',
    r'\b(i am a (licensed|certified|trained|qualified|professional))\b',
    r'\b(in my (professional|medical|legal|expert) (opinion|experience|view))\b',
    r'\b(government (official|agent|employee|representative))\b',
    r'\b(law enforcement)\b',
]
AUTHORITY_RES = [re.compile(p, re.IGNORECASE) for p in AUTHORITY_CLAIM_PATTERNS]

EMOTIONAL_MANIPULATION_PATTERNS = [
    r'\b(if you (really |truly )?(loved|cared (about|for)|respected) me)\b',
    r'\b(you\'?re? (the only one|my only hope|all i have))\b',
    r'\b(after everything (i\'?ve?|we\'?ve?) done for you)\b',
    r'\b(you\'?ll? (regret|be sorry) (this|when|if))\b',
    r'\b(nobody (else )?(will|would|cares|understands))\b',
    r'\b(you\'?re? making me (do this|feel this way|hurt))\b',
    r'\b(i\'?ll? (hurt myself|do something (drastic|stupid)) if)\b',
]
EMOTIONAL_RES = [re.compile(p, re.IGNORECASE) for p in EMOTIONAL_MANIPULATION_PATTERNS]

FALSE_URGENCY_PATTERNS = [
    r'\b(your (account|card|subscription|access) (will be|has been) (suspended|terminated|cancelled|locked))\b',
    r'\b(verify (your|your account|your information) (immediately|now|within \d+))\b',
    r'\b(unusual (activity|sign.?in|login) (detected|found|noticed))\b',
    r'\b(click (here|this link|below) (to|and) (verify|confirm|restore|secure))\b',
    r'\b(you have (won|been selected|been chosen))\b',
    r'\b(claim (your|the) (prize|reward|gift|money) (now|today|immediately))\b',
]
FALSE_URGENCY_RES = [re.compile(p, re.IGNORECASE) for p in FALSE_URGENCY_PATTERNS]

SOCIAL_PROOF_PATTERNS = [
    r'\b(everyone (knows|is saying|agrees|is doing))\b',
    r'\b(scientists (say|agree|confirm|prove|have proven))\b',
    r'\b(studies (show|prove|confirm))\b',
    r'\b(experts (agree|say|confirm|recommend))\b',
    r'\b(the (truth|facts|evidence|data|science) (is|shows|proves|confirms))\b',
    r'\b(most people (don\'?t know|have no idea|are unaware))\b',
    r'\b(wake up (people|sheeple|everyone))\b',
]
SOCIAL_PROOF_RES = [re.compile(p, re.IGNORECASE) for p in SOCIAL_PROOF_PATTERNS]
