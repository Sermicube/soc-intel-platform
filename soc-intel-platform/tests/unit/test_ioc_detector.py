"""
tests/unit/test_ioc_detector.py
─────────────────────────────────────────────────────────────
Tests unitarios para el módulo de detección de tipos de IOC.

Ejecutar: pytest tests/unit/test_ioc_detector.py -v
"""

import pytest
from app.core.ioc_detector import IOCDetector, detect_ioc_type
from app.models.schemas import IOCType


class TestIPDetection:
    def test_valid_ipv4(self):
        assert detect_ioc_type("192.168.1.1") == IOCType.IP

    def test_valid_ipv4_public(self):
        assert detect_ioc_type("8.8.8.8") == IOCType.IP

    def test_valid_ipv4_limits(self):
        assert detect_ioc_type("255.255.255.255") == IOCType.IP
        assert detect_ioc_type("0.0.0.0") == IOCType.IP

    def test_invalid_ip_out_of_range(self):
        assert detect_ioc_type("999.999.999.999") != IOCType.IP

    def test_invalid_ip_incomplete(self):
        assert detect_ioc_type("192.168.1") != IOCType.IP


class TestHashDetection:
    def test_md5_hash(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == IOCType.HASH_MD5

    def test_sha1_hash(self):
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.HASH_SHA1

    def test_sha256_hash(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_ioc_type(h) == IOCType.HASH_SHA256

    def test_sha256_uppercase(self):
        h = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        assert detect_ioc_type(h) == IOCType.HASH_SHA256

    def test_invalid_hash_wrong_chars(self):
        assert detect_ioc_type("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") != IOCType.HASH_MD5


class TestURLDetection:
    def test_http_url(self):
        assert detect_ioc_type("http://malware.example.com/payload") == IOCType.URL

    def test_https_url(self):
        assert detect_ioc_type("https://phishing.site/login?user=admin") == IOCType.URL

    def test_url_with_port(self):
        assert detect_ioc_type("http://1.2.3.4:8080/evil") == IOCType.URL

    def test_simple_domain_not_url(self):
        assert detect_ioc_type("example.com") != IOCType.URL


class TestDomainDetection:
    def test_simple_domain(self):
        assert detect_ioc_type("malware.example.com") == IOCType.DOMAIN

    def test_tld_only_domain(self):
        assert detect_ioc_type("evil.io") == IOCType.DOMAIN

    def test_subdomain(self):
        assert detect_ioc_type("c2.attack.ru") == IOCType.DOMAIN

    def test_onion_domain(self):
        assert detect_ioc_type("abc123def456.onion") == IOCType.DOMAIN


class TestApplicableSources:
    def test_ip_uses_all_sources(self):
        sources = IOCDetector.get_applicable_sources(IOCType.IP)
        assert "virustotal" in sources
        assert "abuseipdb" in sources
        assert "shodan" in sources

    def test_domain_only_vt(self):
        sources = IOCDetector.get_applicable_sources(IOCType.DOMAIN)
        assert "virustotal" in sources
        assert "abuseipdb" not in sources
        assert "shodan" not in sources

    def test_hash_only_vt(self):
        sources = IOCDetector.get_applicable_sources(IOCType.HASH_SHA256)
        assert sources == ["virustotal"]

    def test_unknown_no_sources(self):
        sources = IOCDetector.get_applicable_sources(IOCType.UNKNOWN)
        assert sources == []


class TestEdgeCases:
    def test_empty_string(self):
        assert detect_ioc_type("") == IOCType.UNKNOWN

    def test_whitespace_stripped(self):
        assert detect_ioc_type("  8.8.8.8  ") == IOCType.IP

    def test_none_like_string(self):
        assert detect_ioc_type("null") != IOCType.IP

    def test_very_long_string(self):
        result = detect_ioc_type("a" * 3000)
        assert result == IOCType.UNKNOWN
