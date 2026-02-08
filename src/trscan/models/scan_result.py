from datetime import datetime

from pydantic import BaseModel


class Finding(BaseModel):
    """Bulunan güvenlik açığı/eksiklik modeli"""

    title: str  # Türkçe başlık
    severity: str  # "Kırmızı" | "Sarı" | "Yeşil"
    score_impact: int  # Puan düşme miktarı (negatif)
    description: str  # Etki açıklaması (1-2 cümle)
    evidence: str  # Kanıt (header/çıktı/URL)
    solution: str  # Adım adım çözüm
    mini_trick: str  # Pratik öneri
    reference: str  # OWASP vb. referans
    category: str  # Kategori (header, cookie, tls vb.)


class CookieInfo(BaseModel):
    """Cookie bilgisi modeli"""

    name: str
    value: str  # Maskelenmiş
    domain: str
    path: str
    secure: bool
    httponly: bool
    samesite: str | None
    max_age: int | None
    is_session: bool
    is_third_party: bool


class HeaderAnalysis(BaseModel):
    """HTTP header analizi modeli"""

    csp_present: bool
    csp_has_default_src: bool
    csp_has_unsafe_inline: bool
    csp_has_unsafe_eval: bool
    csp_has_wildcard: bool
    csp_has_frame_ancestors: bool
    csp_quality_score: int  # 0-100

    hsts_present: bool
    hsts_max_age: int | None
    hsts_include_subdomains: bool
    hsts_preload: bool

    x_frame_options_present: bool
    x_frame_options_value: str | None

    x_content_type_options_present: bool

    referrer_policy_present: bool
    referrer_policy_value: str | None

    permissions_policy_present: bool
    permissions_policy_policies: list[str]

    cross_origin_opener_policy_present: bool
    cross_origin_embedder_policy_present: bool
    cross_origin_resource_policy_present: bool

    cache_control_present: bool
    cache_control_value: str | None

    server_header: str | None
    x_powered_by: str | None

    cors_origin: str | None
    cors_credentials: bool


class TLSInfo(BaseModel):
    """TLS/Sertifika bilgisi modeli"""

    https_enabled: bool
    http_accessible: bool
    certificate_valid: bool
    certificate_issuer: str | None
    certificate_subject: str | None
    certificate_expiry_date: datetime | None
    certificate_expiry_days: int | None
    tls_version: str | None
    alpn_protocol: str | None


class DNSInfo(BaseModel):
    """DNS güvenlik bilgisi modeli"""

    spf_present: bool
    spf_record: str | None
    dkim_present: bool
    dkim_records: list[str]
    dmarc_present: bool
    dmarc_record: str | None
    dmarc_policy: str | None  # none | quarantine | reject
    caa_present: bool
    caa_records: list[str]
    mx_present: bool
    mx_records: list[str]


class PageInfo(BaseModel):
    """Sayfa yapısı bilgisi modeli"""

    has_forms: bool
    forms_count: int
    has_autocomplete_disabled: bool
    has_iframes: bool
    iframes_count: int
    external_scripts_count: int
    mixed_content_detected: bool
    meta_generator: str | None
    server_header: str | None


class SecurityScore(BaseModel):
    """Güvenlik skoru modeli"""

    score: int  # 0-100
    color: str  # "Kırmızı" | "Sarı" | "Yeşil"
    label: str  # "Düşük" | "Orta" | "İyi"
    meaning: str  # "Bu skor ne anlama geliyor?" açıklaması


class ScanResult(BaseModel):
    """Tam tarama sonucu modeli"""

    target_url: str
    scan_date: datetime
    scan_duration_seconds: float

    score: SecurityScore
    findings: list[Finding]

    headers: HeaderAnalysis | None
    cookies: list[CookieInfo]
    tls: TLSInfo | None
    dns: DNSInfo | None
    page: PageInfo | None

    robots_txt_exists: bool
    robots_txt_content: str | None
    sitemap_xml_exists: bool
    security_txt_exists: bool
    security_txt_content: str | None

    login_path_exists: bool
    admin_path_exists: bool

    shark_mode: bool  # Daha katı puanlama modu
    max_requests: int
    timeout: int

    # Özet listeler
    quick_wins: list[str]  # Hızlı düzeltilebilirler
    top_priorities: list[str]  # Öncelik listesi (top-5)
    categories_summary: dict  # Kategori bazlı özet
