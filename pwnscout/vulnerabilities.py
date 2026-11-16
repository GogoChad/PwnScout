"""Heuristic scanner for potentially risky imported libc/API functions."""
RISKY_FUNCTIONS = {
    "gets": ("Critical", "Reads input without a length limit."),
    "strcpy": ("High", "Copies a string without a destination-size parameter."),
    "strcat": ("High", "Concatenates without a destination-size parameter."),
    "sprintf": ("High", "Formats output without a destination-size parameter."),
    "scanf": ("Medium", "Check format string and destination widths."),
    "vsprintf": ("High", "Formats output without a destination-size parameter."),
    "system": ("Medium", "Review command construction for injection risks."),
    "popen": ("Medium", "Review command construction and input validation."),
    "strncpy": ("Low", "Can still produce unterminated strings; review usage."),
    "memcpy": ("Medium", "Review length calculations and destination capacity."),
}
SAFE_REPLACEMENTS = {
    "gets": "fgets",
    "strcpy": "snprintf / explicit bounded copy",
    "strcat": "strncat / snprintf with careful sizing",
    "sprintf": "snprintf",
    "vsprintf": "vsnprintf",
}


def find_risky_imports(imports):
    findings = []
    for name in sorted(set(imports)):
        if name in RISKY_FUNCTIONS:
            severity, reason = RISKY_FUNCTIONS[name]
            findings.append({
                "function": name,
                "severity": severity,
                "reason": reason,
                "suggestion": SAFE_REPLACEMENTS.get(name, "Validate inputs and review call sites."),
            })
    return findings
