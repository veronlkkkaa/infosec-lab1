"""Fail CI on CodeQL findings except the reviewed Bearer-only CSRF setting."""

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY_PATH = "src/main/kotlin/ru/itmo/infosec/lab1/security/SecurityConfig.kt"
CSRF_LINE = 25
CSRF_SOURCE = ".csrf { it.disable() }"
CSRF_RULE = "java/spring-disabled-csrf-protection"


def is_reviewed_csrf(result):
    locations = result.get("locations", [])
    if result.get("ruleId") != CSRF_RULE or len(locations) != 1:
        return False
    physical = locations[0].get("physicalLocation", {})
    region = physical.get("region", {})
    return (
        physical.get("artifactLocation", {}).get("uri") == SECURITY_PATH
        and region.get("startLine") == CSRF_LINE
        and region.get("endLine", CSRF_LINE) == CSRF_LINE
    )


def main():
    # One reviewed line: stateless API, explicit Bearer header; no cookie/session/Basic.
    # Do not expand this exception to other rules, files or CSRF settings.
    lines = (ROOT / SECURITY_PATH).read_text(encoding="utf-8").splitlines()
    if len(lines) < CSRF_LINE or lines[CSRF_LINE - 1].strip() != CSRF_SOURCE:
        raise SystemExit("Reviewed CSRF location changed; review and update this exception.")

    reports = sorted((ROOT / "build/reports/codeql").glob("*.sarif"))
    if not reports:
        raise SystemExit("CodeQL SARIF report is missing.")

    accepted = 0
    blocking = 0
    for report in reports:
        runs = json.loads(report.read_text(encoding="utf-8")).get("runs")
        if not isinstance(runs, list) or not runs:
            raise SystemExit("CodeQL report has no analysis runs.")
        for run in runs:
            if run.get("tool", {}).get("driver", {}).get("name") != "CodeQL":
                raise SystemExit("Unexpected SARIF producer.")
            for invocation in run.get("invocations", []):
                if invocation.get("executionSuccessful") is False:
                    raise SystemExit("CodeQL reported an unsuccessful invocation.")
                if any(
                    notification.get("level") == "error"
                    for notification in invocation.get("toolExecutionNotifications", [])
                ):
                    raise SystemExit("CodeQL reported an analysis error.")
            results = run.get("results")
            if not isinstance(results, list):
                raise SystemExit("CodeQL report is missing its results array.")
            for result in results:
                if is_reviewed_csrf(result):
                    accepted += 1
                else:
                    blocking += 1
                    print("Blocking CodeQL rule: " + str(result.get("ruleId", "unknown")))

    summary = (
        "### CodeQL SAST\n\n"
        "| Findings | Reviewed CSRF exception | Blocking |\n"
        "|---|---|---|\n"
        f"| {accepted + blocking} | {accepted} | {blocking} |\n\n"
        "The sole reviewed exception is disabled CSRF on the Bearer-only security chain. "
        "All other findings block CI. The original SARIF is retained unchanged.\n"
    )
    print(summary)
    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary_path).open("a", encoding="utf-8") as output:
            output.write(summary)
    if blocking:
        raise SystemExit("Review and fix the CodeQL findings.")


if __name__ == "__main__":
    main()
