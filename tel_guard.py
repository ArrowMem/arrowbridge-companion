"""Remove any telephone number the model produced before the reply leaves this process.

911 is the only number allowed through on its own. An optional safety module can add the numbers
it stands behind (see companion_server.py); with none present, every other telephone-shaped
string the model writes is removed.

Why a filter on the way out and not a prompt instruction: a model can be talked out of an
instruction. This runs on the finished reply, so it holds whatever the model decided to say.

What it deliberately does not do: judge whether a number is correct. A number can be real and
still be one nobody here vouches for, and the person reading it cannot tell the difference.
"""

import logging
import re

logger = logging.getLogger("companion.tel_guard")

# The one universal emergency number. A guard that strips "call 911" would be a worse defect than
# the one it exists for.
UNIVERSAL_EMERGENCY = frozenset({"911"})

# Shapes, not semantics, and the order matters: the longest form is tried first so a ten-digit
# number is never partly matched as a shorter one.
#
#   1-800-555-0100 / (613) 555-0100 / 613.555.0100   a North American number, any separator
#   12345 / 123456                                   a five or six digit short code
#   911 / 988                                        a three digit emergency or help line
_TEL = re.compile(
    r"(?<![\d-])(?:1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"
    r"|\b\d{5,6}\b"
    r"|\b9(?:11|88)\b"
)

# The false positive this accepts on purpose: a bare five or six digit run is usually a short
# code in a chat reply, but it could be a quantity. Removing a quantity costs the reader one
# confusing sentence. Letting an invented help line through costs them the call they needed to
# make. Do not "fix" this by making the pattern fire only near certain words.


def scan(text, allowed=UNIVERSAL_EMERGENCY):
    """Every telephone-shaped string in `text` that is not in `allowed`."""
    return [m for m in _TEL.findall(text or "") if m not in allowed]


def redact(text, allowed=UNIVERSAL_EMERGENCY):
    """Return (cleaned_text, offenders). Offenders are removed, not masked.

    Removed rather than replaced with a placeholder: a reader seeing "call [number removed]"
    learns that a number existed and goes looking for it. The sentence should simply not offer
    one.
    """
    offenders = []

    def _sub(match):
        found = match.group(0)
        if found in allowed:
            return found
        offenders.append(found)
        return ""

    cleaned = _TEL.sub(_sub, text or "")
    if offenders:
        # Loud, and without the surrounding sentence: the number is not personal, the text
        # around it is the user's own words and must never reach a log line.
        logger.error("tel-guard: model produced %d number(s) not on the allow list", len(offenders))
    # Collapse the double spaces a removal leaves behind, without touching line structure.
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return re.sub(r" ([.,;:!?])", r"\1", cleaned), offenders
