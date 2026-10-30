import pytest

from saferun.engine import CheckResult, CheckStatus, Finding, Severity, Verdict, compute_verdict


def f(sev):
    return Finding("c", "r", sev, "m")


def chk(status, *sevs, analysis=True):
    st = status
    return CheckResult("c", st, findings=[f(s) for s in sevs], detail="why", analysis=analysis)


P, F, W = CheckStatus.PASSED, CheckStatus.FINDINGS, CheckStatus


def test_clean_run_passes():
    v, reasons, complete = compute_verdict([chk(P), chk(W.NOT_APPLICABLE)])
    assert v is Verdict.PASS and complete and reasons


@pytest.mark.parametrize("sev", [Severity.HIGH, Severity.CRITICAL])
def test_high_or_critical_fails(sev):
    assert compute_verdict([chk(P), chk(F, sev)])[0] is Verdict.FAIL


@pytest.mark.parametrize("sev", [Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN])
def test_lower_severities_warn(sev):
    assert compute_verdict([chk(F, sev)])[0] is Verdict.WARNING


def test_info_only_still_passes():
    assert compute_verdict([chk(F, Severity.INFO)])[0] is Verdict.PASS


@pytest.mark.parametrize("status", [W.ERROR, W.TIMEOUT, W.UNAVAILABLE, W.SKIPPED, W.INCOMPLETE])
def test_operational_problem_never_passes_even_beside_clean_checks(status):
    v, reasons, complete = compute_verdict([chk(P), chk(status)])
    assert v is Verdict.WARNING and not complete
    assert any(status.value in r for r in reasons)


def test_finding_outranks_operational_problem_but_both_reported():
    v, reasons, complete = compute_verdict([chk(F, Severity.HIGH), chk(W.ERROR)])
    assert v is Verdict.FAIL and not complete
    assert len(reasons) >= 2


def test_nothing_validated_is_warning_not_pass():
    v, reasons, complete = compute_verdict([chk(W.NOT_APPLICABLE), chk(P, analysis=False)])
    assert v is Verdict.WARNING and not complete and "nothing was validated" in " ".join(reasons)
    assert compute_verdict([])[0] is Verdict.WARNING


def test_partial_workspace_blocks_pass():
    v, reasons, complete = compute_verdict([chk(P)], partial_workspace="2 entries skipped")
    assert v is Verdict.WARNING and not complete and "partial scan" in reasons[0]


def test_truncated_findings_warn():
    c = chk(P)
    c.truncated_findings = 5
    assert compute_verdict([c])[0] is Verdict.WARNING


def test_status_properties_are_disjoint():
    for s in CheckStatus:
        assert not (s.completed and s.operational_problem)
