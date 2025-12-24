import re
from sentinel.entropy import shannon_entropy
from sentinel.ignore import IgnoreRules

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Generic API Key": r"(?i)(api_key|secret|token)[\"']?\s*[:=]\s*[\"'][^\"']+"
}

ENTROPY_THRESHOLD = 4.5


def scan_text(text: str, file_path: str = "") -> list:
    """
    Сканирует текст на наличие секретов по regex и энтропии.
    Применяет правила игнорирования из .sentinelignore.
    :param text: Текст для сканирования
    :param file_path: Путь файла (для ignore)
    :return: Список findings
    """
    raw_findings = []

    # Ищем по regex
    for name, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, text):
            raw_findings.append({
                "type": name,
                "value": match.group(),
                "entropy": shannon_entropy(match.group()),
                "file": file_path
            })

    # Ищем по энтропии (случайные токены, пароли)
    for word in text.split():
        if shannon_entropy(word) > ENTROPY_THRESHOLD and len(word) > 20:
            raw_findings.append({
                "type": "High entropy string",
                "value": word,
                "entropy": shannon_entropy(word),
                "file": file_path
            })

    # Фильтруем через .sentinelignore
    ignore = IgnoreRules()
    findings = ignore.filter(raw_findings)

    return findings
