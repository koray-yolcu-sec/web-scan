import asyncio
from typing import Dict, List, Optional
import dns.resolver
import dns.exception


class DNSFetcher:
    """DNS kayıtlarını çeken fetcher sınıfı"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def _query_txt(self, domain: str, record_type: str) -> List[str]:
        """TXT kaydı sorgular"""
        try:
            answers = self.resolver.resolve(domain, record_type, lifetime=self.timeout)
            results = []
            for rdata in answers:
                results.append(str(rdata).strip('"'))
            return results
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return []
        except Exception:
            return []
    
    def _query_mx(self, domain: str) -> List[str]:
        """MX kaydı sorgular"""
        try:
            answers = self.resolver.resolve(domain, 'MX', lifetime=self.timeout)
            results = []
            for rdata in answers:
                results.append(str(rdata.exchange))
            return results
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return []
        except Exception:
            return []
    
    def _query_caa(self, domain: str) -> List[str]:
        """CAA kaydı sorgular"""
        try:
            answers = self.resolver.resolve(domain, 'CAA', lifetime=self.timeout)
            results = []
            for rdata in answers:
                results.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
            return results
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return []
        except Exception:
            return []
    
    def fetch_all_records(self, domain: str) -> Dict[str, List[str]]:
        """
        Tüm güvenlik DNS kayıtlarını çeker
        
        Returns:
            {
                'spf': List[str],
                'dkim': List[str],
                'dmarc': List[str],
                'caa': List[str],
                'mx': List[str],
            }
        """
        results = {
            'spf': [],
            'dkim': [],
            'dmarc': [],
            'caa': [],
            'mx': [],
        }
        
        # SPF kaydı (TXT)
        txt_records = self._query_txt(domain, 'TXT')
        for record in txt_records:
            if 'v=spf1' in record.lower():
                results['spf'].append(record)
        
        # DKIM kaydı (TXT - selector._domainkey)
        # Yaygın selector'ları dene
        common_selectors = ['default', 'google', 'k1', 'smtp', 'mail']
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_records = self._query_txt(dkim_domain, 'TXT')
            if dkim_records:
                results['dkim'].extend([f"{selector}: {rec}" for rec in dkim_records])
        
        # DMARC kaydı (_dmarc.domain)
        dmarc_domain = f"_dmarc.{domain}"
        results['dmarc'] = self._query_txt(dmarc_domain, 'TXT')
        
        # CAA kaydı
        results['caa'] = self._query_caa(domain)
        
        # MX kaydı
        results['mx'] = self._query_mx(domain)
        
        return results
    
    def parse_dmarc_policy(self, dmarc_records: List[str]) -> Optional[str]:
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