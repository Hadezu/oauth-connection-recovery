"""Run only synthetic loopback services. Generate sanitized JSON and self-contained HTML."""

import argparse
import html
import json
import tempfile
import time
from pathlib import Path

import requests
from cryptography.fernet import Fernet

from .client import ConnectionProblem, Connections
from .provider import provider


def expire(c):
    with c.db() as db:
        row = db.execute("SELECT sealed FROM connections WHERE tenant='sample-team'").fetchone()
        data = c.unseal("sample-team", row["sealed"])
        data["expires_at"] = 0
        db.execute(
            "UPDATE connections SET sealed=? WHERE tenant='sample-team'",
            (c.seal("sample-team", data),),
        )


def connect(c):
    url = c.start("sample-team")
    callback = requests.get(url, allow_redirects=False, timeout=2).headers["Location"]
    c.callback("sample-team", callback)


def run():
    steps = []
    with tempfile.TemporaryDirectory() as temp, provider() as p:
        c = Connections(Path(temp) / "vault.db", Fernet.generate_key(), p.url)

        def record(title, result):
            steps.append(
                {
                    "title": title,
                    "result": result,
                    "evidence": c.report(),
                    "provider_rotations": p.validator.refresh_count,
                }
            )

        connect(c)
        record("01 / Connect", {"state": "CONNECTED", "resource": c.records("sample-team")})
        expire(c)
        c.records("sample-team")
        record(
            "02 / Renew access",
            {"state": "CONNECTED", "rotation": "One refresh, replacement token saved"},
        )
        expire(c)
        p.fault = "lost_response"
        c.timeout = 0.05
        try:
            c.access("sample-team")
        except ConnectionProblem as exc:
            assert str(exc) == "UNKNOWN"
        record(
            "03 / Lose the response",
            {"state": "UNKNOWN", "reason": "Provider rotated, client timed out"},
        )
        rotations = p.validator.refresh_count
        try:
            c.access("sample-team")
        except ConnectionProblem as exc:
            assert str(exc) == "connection_not_ready"
        assert rotations == p.validator.refresh_count
        record("04 / Try again", {"state": "BLOCKED", "reason": "No second refresh request sent"})
        time.sleep(0.3)
        c.timeout = 2
        connect(c)
        record("05 / Reconnect", {"state": "CONNECTED", "resource": c.records("sample-team")})
    return {
        "disclosure": "Independent demonstration; synthetic account and local OAuthLib provider. Not a client deployment or vendor approval.",
        "steps": steps,
    }


def render(report):
    parts = []
    for step in report["steps"]:
        title = html.escape(step["title"])
        status = html.escape(step["result"]["state"])
        evidence = html.escape(json.dumps(step, indent=2))
        reason = html.escape(
            step["result"].get(
                "reason",
                step["result"].get("rotation", "Protected sample resource read successfully"),
            )
        )
        parts.append(
            f'<section><p class="number">{title}</p><h2>{status}</h2><p>{reason}</p><p class="metric">Provider rotations: <b>{step["provider_rotations"]}</b></p><details><summary>Inspect captured evidence</summary><pre>{evidence}</pre></details></section>'
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OAuth Connection Recovery Lab</title><style>*{box-sizing:border-box}body{margin:0;background:#eff2eb;color:#173a36;font:17px/1.6 system-ui}main{max-width:1060px;margin:auto;padding:56px 24px}header{border-bottom:1px solid #748d83;padding-bottom:36px}h1{font-size:clamp(36px,6vw,68px);letter-spacing:-.05em;line-height:1.08;max-width:800px}.eyebrow,.number{font:12px/1.6 monospace;text-transform:uppercase;letter-spacing:.08em;color:#805039}.intro{max-width:720px}article{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:36px}section{background:#fffef7;border:1px solid #a9b8ab;padding:28px;min-width:0}section:nth-child(3){background:#183c36;color:#eef2e6}section:nth-child(3) .number{color:#edc3a2}section:last-child{grid-column:1/-1}h2{font-size:32px;margin:16px 0}.metric{font-size:14px}summary{cursor:pointer;text-decoration:underline;padding:12px 0}pre{font:12px/1.5 monospace;white-space:pre-wrap;overflow-wrap:anywhere}footer{margin-top:36px;font-size:13px}a{color:inherit}a:focus-visible,summary:focus-visible{outline:3px solid #ad6037;outline-offset:4px}@media(max-width:650px){article{grid-template-columns:1fr}main{padding:28px 18px}section{padding:22px}}</style><main><header><p class="eyebrow">Ivan Matiushkin / API integration evidence</p><h1>The token rotated.<br>The response never arrived.</h1><p class="intro">A real local HTTP walkthrough: connect, renew, lose the acknowledgement, stop unsafe retries and reconnect. These are captured outcomes, not animated success counters.</p></header><article>'
        + "".join(parts)
        + "</article><footer>"
        + html.escape(report["disclosure"])
        + "</footer></main></html>"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="evidence")
    args = parser.parse_args()
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    report = run()
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output / "report.html").write_text(render(report), encoding="utf-8")
    print("Five real HTTP stages captured; sanitized report:", output / "report.html")


if __name__ == "__main__":
    main()
