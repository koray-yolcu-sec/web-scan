from ..models.scan_result import Finding, SecurityScore


class SecurityScorer:
    """Güvenlik skoru hesaplayıcı"""

    def __init__(self, shark_mode: bool = False):
        self.shark_mode = shark_mode

        # Skorlama modeli
        self.scoring_model = {
            # Kritik eksikler
            "https_missing": -35,
            "cors_wildcard_credentials": -15,
            "hsts_missing": -10,
            "csp_missing": -10,
            "x_frame_options_missing": -8,
            # Cookie güvenliği
            "session_cookie_secure_missing": -5,
            "session_cookie_httponly_missing": -4,
            "session_cookie_samesite_missing": -3,
            # Diğer header'lar
            "x_content_type_options_missing": -5,
            "referrer_policy_missing": -4,
            "permissions_policy_missing": -3,
            # Bilgi sızdırma
            "server_version_disclosure": -3,
            "x_powered_by_disclosure": -1,
            "meta_generator_version": -1,
            # DNS güvenliği
            "spf_missing": -3,
            "dmarc_missing": -5,
            "dmarc_policy_none": -2,
            "dkim_missing": -2,
            "caa_missing": -1,
            # Sayfa yapısı
            "mixed_content": -8,
            "form_get_method": -2,
            # TLS
            "http_accessible_with_https": -5,
            "certificate_expired": -20,
            "certificate_near_expiry": -5,
        }

        # Shark mode'da skor kırma oranı
        self.shark_mode_multiplier = 1.3

    def calculate_score(
        self, findings: list[Finding], categories: dict, score_impacts: list[int]
    ) -> tuple[SecurityScore, dict, list[str], list[str]]:
        """
        Güvenlik skorunu hesaplar

        Args:
            findings: Bulgu listesi
            categories: Kategori bazlı özet
            score_impacts: Her bulgunun score_impact listesi

        Returns:
            (SecurityScore, categories_summary, quick_wins, top_priorities)
        """
        # Başlangıç skoru: 100
        total_score = 100

        # Tüm negatif etkileri topla
        total_impact = sum(score_impacts)

        # Skoru güncelle
        total_score += total_impact

        # Shark mode için ekstra kırma
        if self.shark_mode and total_impact < 0:
            total_impact = int(total_impact * self.shark_mode_multiplier)
            total_score = 100 + total_impact

        # 0-100 aralığına clamp
        total_score = max(0, min(100, total_score))

        # Renk ve etiket belirle
        color, label, meaning = self._get_score_classification(total_score)

        # SecurityScore oluştur
        security_score = SecurityScore(score=total_score, color=color, label=label, meaning=meaning)

        # Quick wins (kolay düzeltilebilirler)
        quick_wins = self._get_quick_wins(findings)

        # Top priorities (öncelik listesi)
        top_priorities = self._get_top_priorities(findings)

        # Kategori özeti
        categories_summary = self._get_categories_summary(findings)

        return security_score, categories_summary, quick_wins, top_priorities

    def _get_score_classification(self, score: int) -> tuple[str, str, str]:
        """
        Skor sınıflandırması

        Returns:
            (color, label, meaning)
        """
        if score >= 80:
            color = "Yeşil"
            label = "İyi"
            meaning = "Site genel olarak güvenli görünüyor. Küçük iyileştirmeler yapılabilir."
        elif score >= 50:
            color = "Sarı"
            label = "Orta"
            meaning = "Site temel güvenlik önlemlerine sahip ama önemli iyileştirmeler gerekli."
        else:
            color = "Kırmızı"
            label = "Düşük"
            meaning = "Site ciddi güvenlik eksiklikleri barındırıyor. Acil düzeltme gerekli."

        return color, label, meaning

    def _get_quick_wins(self, findings: list[Finding]) -> list[str]:
        """Hızlı düzeltilebilir bulgular"""
        quick_wins = []

        quick_fix_categories = ["header", "cookie"]

        for finding in findings:
            if finding.category in quick_fix_categories and finding.score_impact < 0:
                # Yalnızca kolay düzeltilebilir bulgular
                if any(
                    keyword in finding.title.lower()
                    for keyword in ["eksik", "yok", "flag", "missing"]
                ):
                    quick_wins.append(f"{finding.title} (-{abs(finding.score_impact)})")

        # En önemlileri ilk 5
        return quick_wins[:5]

    def _get_top_priorities(self, findings: list[Finding]) -> list[str]:
        """Öncelik listesi (en kritik bulgular)"""
        # Kırmızı ve yüksek etkiye sahip bulgular
        priorities = []

        for finding in findings:
            if finding.severity == "Kırmızı" and finding.score_impact < -5:
                priorities.append(
                    {
                        "title": finding.title,
                        "impact": finding.score_impact,
                        "category": finding.category,
                    }
                )

        # Etkiye göre sırala (en büyük etki önce)
        priorities.sort(key=lambda x: x["impact"])

        # İlk 5 öncelik
        return [f"{p['title']} ({p['category']})" for p in priorities[:5]]

    def _get_categories_summary(self, findings: list[Finding]) -> dict:
        """Kategori bazlı özet"""
        summary = {
            "Kritik": 0,
            "Yüksek": 0,
            "Orta": 0,
            "Düşük": 0,
            "Bilgi": 0,
        }

        for finding in findings:
            # Bulgunun etkisine göre kategorize et
            impact = abs(finding.score_impact)

            if finding.severity == "Kırmızı":
                if impact >= 20:
                    summary["Kritik"] += 1
                else:
                    summary["Yüksek"] += 1
            elif finding.severity == "Sarı":
                summary["Orta"] += 1
            else:
                summary["Düşük"] += 1

        return summary

    def get_scoring_explanation(self) -> str:
        """Skorlama modelini açıklar"""
        explanation = """
## Skorlama Modeli

TR-Pasif Web Güvenlik Skoru, 0-100 arası bir puanlama sistemidir.

### Başlangıç
- Başlangıç puanı: 100

### Puan Düşmeleri (Negatif Etkiler)

#### Kritik Eksikler
- HTTPS yoksa: -35
- CORS wildcard + credentials: -15
- HSTS yoksa: -10
- CSP yoksa veya zayıfsa: -10
- X-Frame-Options yoksa: -8

#### Cookie Güvenliği
- Session cookie Secure eksik: -5
- Session cookie HttpOnly eksik: -4
- Session cookie SameSite eksik: -3

#### Diğer Header'lar
- X-Content-Type-Options yoksa: -5
- Referrer-Policy yoksa: -4
- Permissions-Policy yoksa: -3

#### Bilgi Sızdırma
- Server header versiyon bilgisi: -3
- X-Powered-By disclosure: -1
- Meta generator versiyon: -1

#### DNS Güvenliği
- SPF eksik: -3
- DMARC eksik: -5
- DMARC policy none: -2
- DKIM eksik: -2
- CAA eksik: -1

#### Sayfa Yapısı
- Mixed content: -8
- Form GET methodu: -2

#### TLS
- HTTP açık (HTTPS var): -5
- Sertifika dolmuş: -20
- Sertifika yakında dolacak: -5

### Renk Eşikleri
- **0-49**: Kırmızı - Düşük güvenlik
- **50-79**: Sarı - Orta güvenlik
- **80-100**: Yeşil - İyi güvenlik

### Shark Mode 🦈
Shark mode aktifse, tüm negatif etkiler %30 daha fazla kırılır.
Bu mod daha katı standartlar uygular ve production için önerilir.
"""
        return explanation
