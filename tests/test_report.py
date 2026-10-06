import json

from recovery.demo import render, run


def test_demo_records_observed_outcomes_without_secrets():
    report = run()
    assert [s["result"]["state"] for s in report["steps"]] == [
        "CONNECTED",
        "CONNECTED",
        "UNKNOWN",
        "BLOCKED",
        "CONNECTED",
    ]
    assert [s["provider_rotations"] for s in report["steps"]] == [0, 1, 2, 2, 2]
    text = json.dumps(report)
    for key in ["access_token", "refresh_token", "code_verifier", "sealed"]:
        assert key not in text


def test_html_escapes_untrusted_evidence():
    bad = "<script>alert(1)</script>"
    report = {
        "disclosure": bad,
        "steps": [
            {
                "title": bad,
                "result": {"state": bad, "reason": bad},
                "provider_rotations": 0,
                "evidence": bad,
            }
        ],
    }
    result = render(report)
    assert bad not in result
    assert "&lt;script&gt;" in result
