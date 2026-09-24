import re


SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "schtasks",
    "autorun",
    "download",
    "payload",
    "ransom",
    "bitcoin",
    "encrypt",
    "decrypt",
    "keylogger",
]


def extract_strings(file_path, min_length=4):
    try:
        with open(file_path, "rb") as file:
            data = file.read()

        strings = re.findall(
            rb"[\x20-\x7E]{%d,}" % min_length,
            data
        )

        decoded = [s.decode("ascii", errors="ignore") for s in strings]

        return decoded

    except OSError as error:
        return [f"ERROR: {error}"]


def find_suspicious_strings(strings):
    findings = []

    for string in strings:
        lower_string = string.lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lower_string:
                findings.append({
                    "keyword": keyword,
                    "string": string
                })

    return findings
