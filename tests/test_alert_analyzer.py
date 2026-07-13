from src.alert_analyzer import analyze_alert, classify_risk


def test_classify_risk_levels():
    assert classify_risk(3) == "LOW"
    assert classify_risk(7) == "MEDIUM"
    assert classify_risk(12) == "HIGH"


def test_pattern_does_not_downgrade_high_risk():
    result = analyze_alert({"level": 12, "event": "Authentication failure"})

    assert result["risk"] == "HIGH"


def test_pattern_escalates_low_to_medium():
    result = analyze_alert({"level": 3, "event": "Authentication failure"})

    assert result["risk"] == "MEDIUM"
