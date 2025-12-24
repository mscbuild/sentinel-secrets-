# sentinel/scanner.py
import re
from sentinel.entropy import shannon_entropy

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Generic API Key": r"(?i)(api_key|secret|token)[\"']?\s*[:=]\s*[\"'][^\"']+"
}

ENTROPY_THRESHOLD = 4.5

def scan_text(text: str):
    findings = []

    for name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, text):
            findings.append({
                "type": name,
                "value": match.group(),
                "entropy": shannon_entropy(match.group())
            })

    for word in text.split():
        if shannon_entropy(word) > ENTROPY_THRESHOLD and len(word) > 20:
            findings.append({
                "type": "High entropy string",
                "value": word,
                "entropy": shannon_entropy(word)
            })

    return findings
