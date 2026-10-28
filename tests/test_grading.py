"""
Unit tests for TLS grading and cipher suite policy enforcement.
Responsible: Edinam Afi Ezuh (Module 7)
"""

from pki_lifecycle.grading.policy import TLSGradingEngine


def test_tls13_receives_top_grade():
    grade, findings = TLSGradingEngine.evaluate_configuration("TLSv1.3", "TLS_AES_256_GCM_SHA384")
    assert grade == "A+"
    assert len(findings) == 0


def test_tls12_with_aead_receives_grade_a():
    grade, findings = TLSGradingEngine.evaluate_configuration("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256")
    assert grade == "A"
    assert len(findings) == 0


def test_tls12_with_cbc_receives_grade_b_with_warning():
    grade, findings = TLSGradingEngine.evaluate_configuration("TLSv1.2", "ECDHE-RSA-AES256-SHA384")
    assert grade == "B"
    assert any("Non-AEAD" in f for f in findings)


def test_obsolete_tls10_receives_failing_grade():
    grade, findings = TLSGradingEngine.evaluate_configuration("TLSv1.0", "ECDHE-RSA-AES128-SHA")
    assert grade == "F"
    assert any("Obsolete protocol" in f for f in findings)
