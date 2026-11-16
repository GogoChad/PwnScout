from pwnscout.vulnerabilities import find_risky_imports


def test_detects_unsafe_functions():
    findings = find_risky_imports(["puts", "gets", "strcpy"])
    names = {item["function"] for item in findings}
    assert names == {"gets", "strcpy"}
    assert next(x for x in findings if x["function"] == "gets")["severity"] == "Critical"


def test_deduplicates_imports():
    assert len(find_risky_imports(["gets", "gets"])) == 1


def test_unknown_functions_are_ignored():
    assert find_risky_imports(["puts", "printf"]) == []
