"""
Shannon entropy analysis for detecting high-entropy strings
that are likely to be secrets, even without a known pattern.
"""

import math
import re
from typing import List, Tuple

# Character sets used for entropy analysis
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "0123456789abcdefABCDEF"

# Minimum length for entropy candidates
MIN_STRING_LENGTH = 20

# Entropy thresholds (bits per character)
BASE64_ENTROPY_THRESHOLD = 4.5
HEX_ENTROPY_THRESHOLD = 3.0


def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    Returns bits per character (0.0 to ~6.0 for printable ASCII).
    """
    if not data:
        return 0.0

    freq: dict = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def _extract_tokens(line: str, charset: str) -> List[str]:
    """
    Extract contiguous substrings composed only of charset characters.
    """
    pattern = f"[{re.escape(charset)}]{{" + str(MIN_STRING_LENGTH) + ",}"
    return re.findall(pattern, line)


def find_high_entropy_strings(
    line: str,
    line_number: int = 0,
    filepath: str = "",
) -> List[Tuple[str, float, str]]:
    """
    Scan a line for high-entropy strings that may be secrets.

    Returns a list of (token, entropy_score, charset_type) tuples.
    """
    results = []

    # Base64-like tokens
    for token in _extract_tokens(line, BASE64_CHARS):
        entropy = shannon_entropy(token)
        if entropy >= BASE64_ENTROPY_THRESHOLD:
            results.append((token, entropy, "base64"))

    # Hex tokens
    for token in _extract_tokens(line, HEX_CHARS):
        entropy = shannon_entropy(token)
        if entropy >= HEX_ENTROPY_THRESHOLD:
            results.append((token, entropy, "hex"))

    return results


def is_likely_secret(value: str) -> bool:
    """
    Quick boolean check: is this string likely a secret by entropy alone?
    """
    if len(value) < MIN_STRING_LENGTH:
        return False

    b64_entropy = shannon_entropy(value)
    if b64_entropy >= BASE64_ENTROPY_THRESHOLD:
        return True

    # Check hex specifically
    if all(c in HEX_CHARS for c in value):
        hex_entropy = shannon_entropy(value)
        if hex_entropy >= HEX_ENTROPY_THRESHOLD:
            return True

    return False