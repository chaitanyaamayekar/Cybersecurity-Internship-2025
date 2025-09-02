import re

SQLI_PATTERNS = [
    r\"'\\s*or\\s*1=1\",          # ' or 1=1
    r\"union\\s+select\",         # UNION SELECT
    r\"--\\s*$\",                 # comment tail
    r\";\\s*drop\\s+table\",      # ; drop table
    r\"xp_cmdshell\",             # mssql
    r\"information_schema\",      # MySQL/PG
]

SQLI_REGEXES = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in SQLI_PATTERNS]

def http_payload_suspicious(payload: bytes) -> str | None:
    try:
        text = payload.decode(errors=\"ignore\")
    except Exception:
        return None
    for rx in SQLI_REGEXES:
        if rx.search(text):
            return f\"SQLI:{rx.pattern}\"
    return None
