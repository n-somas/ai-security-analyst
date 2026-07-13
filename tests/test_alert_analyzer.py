from src.alert_analyzer import (
    analyze_alert,
    calculate_threat_score,
    classify_risk,
)


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


def test_threat_score_is_capped_at_100():
    score, _ = calculate_threat_score(
        {
            "level": 15,
            "event": "SQL injection authentication failure sudo to root ssh",
            "src_ip": "203.0.113.50",
            "mitre": "T1110.001",
        },
        "HIGH",
    )

    assert score == 100


def test_medium_risk_has_minimum_score():
    result = analyze_alert({"level": 3, "event": "Authentication failure"})

    assert result["threat_score"] >= 40


def test_score_reasons_are_returned():
    result = analyze_alert(
        {
            "level": 7,
            "event": "Authentication failure",
            "src_ip": "203.0.113.50",
            "mitre": "T1110.001",
        }
    )

    assert result["score_reasons"]
    assert any("Wazuh-Level" in reason for reason in result["score_reasons"])
