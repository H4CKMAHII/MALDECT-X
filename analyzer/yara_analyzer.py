import yara


def scan_with_yara(file_path, rule_path):
    try:
        rules = yara.compile(filepath=rule_path)

        matches = rules.match(file_path)

        return [
            {
                "rule": match.rule,
                "tags": list(match.tags),
            }
            for match in matches
        ]

    except Exception as error:
        return [{
            "rule": "ERROR",
            "tags": [str(error)]
        }]
