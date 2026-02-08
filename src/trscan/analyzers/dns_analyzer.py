from typing import Dict, List, Tuple
from ..models.scan_result import DNSInfo, Finding


class DNSAnalyzer:
    """DNS güvenlik analizcisi"""
    
    def __init__(self, shark_mode: bool = False):
        self.shark_mode = shark_mode
        self.findings: List[Finding] = []
    
    def analyze(self, dns_records: Dict) -> Tuple[DNSInfo, List[Finding]]:
        """
        DNS güvenlik kayıtlarını analiz eder
        
        Args:
            dns_records: DNS kayıtları
            
        Returns:
            (DNSInfo, List[Finding])
        """
        self.findings = []
        
        dns_info = DNSInfo(
            spf_present=len(dns_records.get('spf', [])) > 0,
            spf_record=dns_records.get('spf', [''])[0] if dns_records.get('spf') else None,
            dkim_present=len(dns_records.get('dkim', [])) > 0,
            dkim_records=dns_records.get('dkim', []),
            dmarc_present=len(dns_records.get('dmarc', [])) > 0,
            dmarc_record=dns_records.get('dmarc', [''])[0] if dns_records.get('dmarc') else None,
            dmarc_policy=self._parse_dmarc_policy(dns_records.get('dmarc', [])),
            caa_present=len(dns_records.get('caa', [])) > 0,
            caa_records=dns_records.get('caa', []),
            mx_present=len(dns_records.get('mx', [])) > 0,
            mx_records=dns_records.get('mx', []),
        )
        
        # SPF analizi
        if not dns_info.spf_present:
            self.findings.append(Finding(
                title="SPF Kaydı Eksik",
                severity="Sarı",
                score_impact=-3,
                description="SPF (Sender Policy Framework) kaydı eksik. E-posta spoofing'e karşı savunmasız.",
                evidence="TXT SPF: (yok)",
                solution="1. SPF kaydı ekleyin\n2. Geçerli mail sunucularınızı belirtin\n3. -all ile diğerlerini reddedebilirsiniz",
                mini_trick="Örnek: v=spf1 ip4:1.2.3.4 include:_spf.google.com ~all",
                reference="OWASP Email Security",
                category="dns"
            ))
        elif '~all' in dns_info.spf_record.lower():
            self.findings.append(Finding(
                title="SPF Policy: ~all (SoftFail) Kullanılıyor",
                severity="Sarı",
                score_impact=-1,
                description="SPF'te ~all (SoftFail) kullanılıyor, -all (HardFail) daha güvenli.",
                evidence=f"SPF: {dns_info.spf_record}",
                solution="~all yerine -all kullanın (hard fail)",
                mini_trick="~all = SoftFail (test aşaması), -all = HardFail (production)",
                reference="OWASP Email Security",
                category="dns"
            ))
        
        # DMARC analizi
        if not dns_info.dmarc_present:
            self.findings.append(Finding(
                title="DMARC Kaydı Eksik",
                severity="Sarı",
                score_impact=-5,
                description="DMARC kaydı eksik. SPF ve DKIM'i birleştiren ve raporlayan mekanizma yok.",
                evidence="TXT DMARC: (yok)",
                solution="1. DMARC kaydı ekleyin\n2. p=none ile başlayın\n3. Raporları inceleyin\n4. p=reject ile güçlendirin",
                mini_trick="Örnek: v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                reference="OWASP DMARC",
                category="dns"
            ))
        elif dns_info.dmarc_policy == 'none':
            self.findings.append(Finding(
                title="DMARC Policy: none (İzleme Modu)",
                severity="Sarı",
                score_impact=-2,
                description="DMARC policy none, sadece izleme yapıyor, koruma yok.",
                evidence=f"DMARC: {dns_info.dmarc_record}",
                solution="Raporları inceledikten sonra p=quarantine veya p=reject'e geçin",
                mini_trick="none → quarantine → reject, aşamalı geçiş yapın",
                reference="OWASP DMARC",
                category="dns"
            ))
        
        # DKIM analizi
        if not dns_info.dkim_present:
            self.findings.append(Finding(
                title="DKIM Kaydı Bulunamadı (Selector Hakkı)",
                severity="Sarı",
                score_impact=-2,
                description="Yaygın DKIM selector'larında kayıt bulunamadı. Ancak farklı selector kullanıyor olabilirsiniz.",
                evidence="TXT DKIM: (bulunamadı)",
                solution="1. DKIM kurulu olduğunu doğrulayın\n2. Selector kontrolü yapın\n3. Gerekirse DKIM kurun",
                mini_trick="DKIM selector'ı genellikle 'default', 'google', 'k1' vb. olur",
                reference="OWASP DKIM",
                category="dns"
            ))
        
        # CAA analizi
        if not dns_info.caa_present:
            self.findings.append(Finding(
                title="CAA Kaydı Eksik",
                severity="Sarı",
                score_impact=-1,
                description="CAA (Certificate Authority Authorization) kaydı eksik. Kimin sertifika yayınlayabileceği belirtilmemiş.",
                evidence="CAA: (yok)",
                solution="CAA kaydı ekleyin, sadece güvenilir CA'lara izin verin",
                mini_trick="Örnek: issueletsencrypt.org; issuewild digicert.com",
                reference="OWASP CAA",
                category="dns"
            ))
        
        return dns_info, self.findings
    
    def _parse_dmarc_policy(self, dmarc_records: List[str]) -> str:
        """
        DMARC policy'sini parse eder
        
        Returns: 'none' | 'quarantine' | 'reject' | None
        """
        for record in dmarc_records:
            if 'p=' in record.lower():
                policy_part = record.lower().split('p=')[1].split(';')[0].strip()
                if policy_part in ['none', 'quarantine', 'reject']:
                    return policy_part
        return None