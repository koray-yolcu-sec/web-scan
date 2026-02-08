"""
SecurityScorer testleri
"""

import pytest

from src.trscan.models import Finding
from src.trscan.scorer import SecurityScorer


def test_calculate_score_perfect():
    """Mükemmel skor (100) testi"""
    scorer = SecurityScorer(shark_mode=False)

    findings = []
    score_impacts = []

    score, categories, quick_wins, top_priorities = scorer.calculate_score(
        findings, {}, score_impacts
    )

    assert score.score == 100
    assert score.color == "Yeşil"
    assert score.label == "İyi"


def test_calculate_score_critical_issues():
    """Kritik sorunlar ile skor testi"""
    scorer = SecurityScorer(shark_mode=False)

    findings = [
        Finding(
            title="HTTPS Eksik",
            severity="Kırmızı",
            score_impact=-35,
            description="...",
            evidence="...",
            solution="...",
            mini_trick="...",
            reference="OWASP",
            category="tls",
        )
    ]
    score_impacts = [-35]

    score, categories, quick_wins, top_priorities = scorer.calculate_score(
        findings, {}, score_impacts
    )

    assert score.score == 65
    assert score.color == "Sarı"
    assert score.label == "Orta"


def test_calculate_score_shark_mode():
    """Shark mode skor testi"""
    scorer = SecurityScorer(shark_mode=True)

    findings = [
        Finding(
            title="HSTS Eksik",
            severity="Kırmızı",
            score_impact=-10,
            description="...",
            evidence="...",
            solution="...",
            mini_trick="...",
            reference="OWASP",
            category="header",
        )
    ]
    score_impacts = [-10]

    score, categories, quick_wins, top_priorities = scorer.calculate_score(
        findings, {}, score_impacts
    )

    # Shark mode: -10 * 1.3 = -13
    # Score: 100 - 13 = 87
    assert score.score == 87


def test_calculate_score_clamp_to_zero():
    """Skor 0'ın altına düşerse clamp testi"""
    scorer = SecurityScorer(shark_mode=False)

    findings = [
        Finding(
            title="Çok Büyük Etki",
            severity="Kırmızı",
            score_impact=-150,
            description="...",
            evidence="...",
            solution="...",
            mini_trick="...",
            reference="OWASP",
            category="tls",
        )
    ]
    score_impacts = [-150]

    score, categories, quick_wins, top_priorities = scorer.calculate_score(
        findings, {}, score_impacts
    )

    assert score.score == 0
    assert score.color == "Kırmızı"


def test_get_quick_wins():
    """Quick wins testi"""
    scorer = SecurityScorer(shark_mode=False)

    findings = [
        Finding(
            title="X-Frame-Options Eksik",
            severity="Sarı",
            score_impact=-8,
            description="...",
            evidence="...",
            solution="...",
            mini_trick="...",
            reference="OWASP",
            category="header",
        ),
        Finding(
            title="HTTPS Eksik",
            severity="Kırmızı",
            score_impact=-35,
            description="...",
            evidence="...",
            solution="...",
            mini_trick="...",
            reference="OWASP",
            category="tls",
        ),
    ]

    quick_wins = scorer._get_quick_wins(findings)

    assert len(quick_wins) > 0
    assert any("X-Frame" in win for win in quick_wins)


def test_get_top_priorities():
    """Top priorities testi"""
    scorer = SecurityScorer(shark_mode=False)

    findings = [
        Finding(
            title="HTTPS Eksik",
            severity="Kırmızı",
            score_impact=-35,
            description="...",
            evidence="...",
            solution="...",
            mini_trick="...",
            reference="OWASP",
            category="tls",
        ),
        Finding(
            title="Referrer-Policy Eksik",
            severity="Sarı",
            score_impact=-4,
            description="...",
            evidence="...",
            solution="...",
            mini_trick="...",
            reference="OWASP",
            category="header",
        ),
    ]

    top_priorities = scorer._get_top_priorities(findings)

    assert len(top_priorities) > 0
    assert "HTTPS Eksik" in top_priorities[0]


def test_get_score_classification():
    """Skor sınıflandırma testi"""
    scorer = SecurityScorer(shark_mode=False)

    # Kırmızı
    color, label, meaning = scorer._get_score_classification(25)
    assert color == "Kırmızı"
    assert label == "Düşük"

    # Sarı
    color, label, meaning = scorer._get_score_classification(60)
    assert color == "Sarı"
    assert label == "Orta"

    # Yeşil
    color, label, meaning = scorer._get_score_classification(85)
    assert color == "Yeşil"
    assert label == "İyi"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
