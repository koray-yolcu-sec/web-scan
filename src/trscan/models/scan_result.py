from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from datetime import datetime


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
    samesite: Optional[str]
    max_age: Optional[int]
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
    hsts_max_age: Optional[int]
    hsts_include_subdomains: bool
    hsts_preload: bool
    
    x_frame_options_present: bool
    x_frame_options_value: Optional[str]
    
    x_content_type_options_present: bool
    
    referrer_policy_present: bool
    referrer_policy_value: Optional[str]
    
    permissions_policy_present: bool
    permissions_policy_policies: List[str]
    
    cross_origin_opener_policy_present: bool
    cross_origin_embedder_policy_present: bool
    cross_origin_resource_policy_present: bool
    
    cache_control_present: bool
    cache_control_value: Optional[str]
    
    server_header: Optional[str]
    x_powered_by: Optional[str]
    
    cors_origin: Optional[str]
    cors_credentials: bool


class TLSInfo(BaseModel):
    """TLS/Sertifika bilgisi modeli"""
    
    https_enabled: bool
    http_accessible: bool
    certificate_valid: bool
    certificate_issuer: Optional[str]
    certificate_subject: Optional[str]
    certificate_expiry_date: Optional[datetime]
    certificate_expiry_days: Optional[int]
    tls_version: Optional[str]
    alpn_protocol: Optional[str]


class DNSInfo(BaseModel):
    """DNS güvenlik bilgisi modeli"""
    
    spf_present: bool
    spf_record: Optional[str]
    dkim_present: bool
    dkim_records: List[str]
    dmarc_present: bool
    dmarc_record: Optional[str]
    dmarc_policy: Optional[str]  # none | quarantine | reject
    caa_present: bool
    caa_records: List[str]
    mx_present: bool
    mx_records: List[str]


class PageInfo(BaseModel):
    """Sayfa yapısı bilgisi modeli"""
    
    has_forms: bool
    forms_count: int
    has_autocomplete_disabled: bool
    has_iframes: bool
    iframes_count: int
    external_scripts_count: int
    mixed_content_detected: bool
    meta_generator: Optional[str]
    server_header: Optional[str]


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
    findings: List[Finding]
    
    headers: Optional[HeaderAnalysis]
    cookies: List[CookieInfo]
    tls: Optional[TLSInfo]
    dns: Optional[DNSInfo]
    page: Optional[PageInfo]
    
    robots_txt_exists: bool
    robots_txt_content: Optional[str]
    sitemap_xml_exists: bool
    security_txt_exists: bool
    security_txt_content: Optional[str]
    
    login_path_exists: bool
    admin_path_exists: bool
    
    shark_mode: bool  # Daha katı puanlama modu
    max_requests: int
    timeout: int
    
    # Özet listeler
    quick_wins: List[str]  # Hızlı düzeltilebilirler
    top_priorities: List[str]  # Öncelik listesi (top-5)
    categories_summary: dict  # Kategori bazlı özet