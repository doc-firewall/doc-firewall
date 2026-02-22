import unicodedata


def normalize_text(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    stealth = [
        "\u200b",
        "\u200c",
        "\u200d",
        "\ufeff",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    ]
    for ch in stealth:
        s = s.replace(ch, "")
    return s
