"""Tests for domain matching and allowlist functionality."""

import pytest
from emaillm import domain_matches


class TestDomainMatches:
    """Test domain_matches function."""
    
    def test_exact_domain_match(self):
        """Test exact domain matching."""
        assert domain_matches("example.com", "example.com") is True
        assert domain_matches("test.com", "test.com") is True
    
    def test_no_match_different_domains(self):
        """Test that different domains don't match."""
        assert domain_matches("example.com", "other.com") is False
        assert domain_matches("test.org", "test.com") is False
    
    def test_subdomain_matches_parent(self):
        """Test that subdomains match parent domain."""
        assert domain_matches("sub.example.com", "example.com") is True
        assert domain_matches("deep.sub.example.com", "example.com") is True
        assert domain_matches("mail.example.com", "example.com") is True
    
    def test_wildcard_matches_subdomain(self):
        """Test that wildcard pattern matches subdomains."""
        assert domain_matches("sub.example.com", "*.example.com") is True
        assert domain_matches("deep.sub.example.com", "*.example.com") is True
    
    def test_wildcard_does_not_match_base_domain(self):
        """Test that wildcard doesn't match base domain."""
        assert domain_matches("example.com", "*.example.com") is False
    
    def test_wildcard_matches_deep_subdomain(self):
        """Test wildcard with deep subdomains."""
        assert domain_matches("a.b.c.example.com", "*.example.com") is True
    
    def test_case_insensitive_matching(self):
        """Test that matching is case-insensitive."""
        assert domain_matches("EXAMPLE.COM", "example.com") is True
        assert domain_matches("Example.Com", "EXAMPLE.COM") is True
        assert domain_matches("SUB.EXAMPLE.COM", "*.example.com") is True
    
    def test_empty_domain_email(self):
        """Test handling of empty email domain."""
        assert domain_matches("", "example.com") is False
    
    def test_empty_allowed_domain(self):
        """Test handling of empty allowed domain."""
        assert domain_matches("example.com", "") is False
    
    def test_complex_wildcard_patterns(self):
        """Test complex wildcard scenarios."""
        # Multiple sublevels
        assert domain_matches("a.b.c.d.example.com", "*.example.com") is True
        
        # Wildcard with multiple subdomains in email
        assert domain_matches("mail.sub.example.com", "*.sub.example.com") is True
        
        # Should not match different parent
        assert domain_matches("sub.other.com", "*.example.com") is False
    
    def test_tld_extraction(self):
        """Test TLD extraction works correctly."""
        # These tests verify tldextract is working
        assert domain_matches("example.co.uk", "example.co.uk") is True
        assert domain_matches("sub.example.co.uk", "example.co.uk") is True
        assert domain_matches("sub.example.co.uk", "*.example.co.uk") is True
    
    def test_unicode_domains(self):
        """Test unicode domain handling."""
        # IDN domains should be handled
        assert domain_matches("münchen.de", "münchen.de") is True
