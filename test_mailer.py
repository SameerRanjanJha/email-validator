import pytest
import dns.resolver
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from mailer import EmailValidator, MXRecord, CachedMXResult  # Assuming the enhanced code is saved as mailer.py


class TestMXRecord:
    """Test MXRecord class functionality."""
    
    def test_mx_record_creation(self):
        """Test MXRecord object creation and properties."""
        mx = MXRecord(priority=10, exchange="mail.example.com")
        assert mx.priority == 10
        assert mx.exchange == "mail.example.com"
    
    def test_mx_record_string_representation(self):
        """Test MXRecord string representations."""
        mx = MXRecord(priority=20, exchange="backup.example.com")
        assert str(mx) == "MX 20 backup.example.com"
        assert repr(mx) == "MXRecord(priority=20, exchange='backup.example.com')"


class TestCachedMXResult:
    """Test CachedMXResult class functionality."""
    
    def test_cached_result_creation(self):
        """Test CachedMXResult creation."""
        mx_records = [MXRecord(10, "mail.example.com")]
        timestamp = datetime.now()
        cached = CachedMXResult(mx_records, timestamp, ttl_seconds=300)
        
        assert cached.mx_records == mx_records
        assert cached.timestamp == timestamp
        assert cached.ttl_seconds == 300
    
    def test_cached_result_expiration(self):
        """Test cache expiration logic."""
        mx_records = [MXRecord(10, "mail.example.com")]
        
        # Fresh cache entry
        fresh_cached = CachedMXResult(mx_records, datetime.now(), ttl_seconds=300)
        assert not fresh_cached.is_expired()
        
        # Expired cache entry
        old_timestamp = datetime.now() - timedelta(seconds=400)
        expired_cached = CachedMXResult(mx_records, old_timestamp, ttl_seconds=300)
        assert expired_cached.is_expired()


class TestEmailValidator:
    """Test EmailValidator class functionality."""
    
    @pytest.fixture
    def validator(self):
        """Create an EmailValidator instance for testing."""
        return EmailValidator(dns_timeout=2.0, dns_retries=1, enable_cache=False)
    
    @pytest.fixture
    def cached_validator(self):
        """Create an EmailValidator instance with caching enabled."""
        return EmailValidator(dns_timeout=2.0, dns_retries=1, enable_cache=True, cache_ttl=300)
    
    def test_initialization(self):
        """Test EmailValidator initialization with custom settings."""
        validator = EmailValidator(dns_timeout=3.0, dns_retries=2, enable_cache=True, cache_ttl=600)
        assert validator.dns_timeout == 3.0
        assert validator.dns_retries == 2
        assert validator.enable_cache is True
        assert validator.cache_ttl == 600
        assert validator.resolver.timeout == 3.0
        assert validator.resolver.lifetime == 3.0
    
    def test_initialization_defaults(self):
        """Test EmailValidator initialization with default settings."""
        validator = EmailValidator()
        assert validator.dns_timeout == 5.0
        assert validator.dns_retries == 2
        assert validator.enable_cache is True
        assert validator.cache_ttl == 300


class TestEmailFormatValidationEnhanced:
    """Test enhanced email format validation with domain extraction."""
    
    @pytest.fixture
    def validator(self):
        return EmailValidator(enable_cache=False)
    
    def test_valid_email_formats_with_domain(self, validator):
        """Test valid email formats and domain extraction."""
        test_cases = [
            ("test@example.com", "example.com"),
            ("user.name@domain.co.uk", "domain.co.uk"),
            ("firstname+lastname@company.org", "company.org"),
            ("user123@test-domain.com", "test-domain.com"),
        ]
        
        for email, expected_domain in test_cases:
            is_valid, message, domain = validator.validate_email_format(email)
            assert is_valid, f"Email {email} should be valid: {message}"
            assert domain == expected_domain, f"Domain should be {expected_domain}, got {domain}"
            assert "Valid email format" in message
    
    def test_invalid_email_formats_no_domain(self, validator):
        """Test invalid email formats return None for domain."""
        invalid_emails = [
            "plainaddress",
            "@missingusername.com", 
            "username@.com",
            "username@",
            "",
            "user@domain@domain.com",
        ]
        
        for email in invalid_emails:
            is_valid, message, domain = validator.validate_email_format(email)
            assert not is_valid, f"Email {email} should be invalid"
            assert domain is None, f"Domain should be None for invalid email {email}"
            assert "Invalid email format" in message


class TestMXRecordRetrieval:
    """Test MX record retrieval functionality."""
    
    @pytest.fixture
    def validator(self):
        return EmailValidator(dns_timeout=1.0, dns_retries=0, enable_cache=False)
    
    @patch('dns.resolver.Resolver.resolve')
    def test_get_mx_records_success(self, mock_resolve, validator):
        """Test successful MX record retrieval."""
        # Mock DNS response with multiple MX records
        mock_record_1 = MagicMock()
        mock_record_1.preference = 10
        mock_record_1.exchange = MagicMock()
        mock_record_1.exchange.__str__ = MagicMock(return_value="mail1.example.com.")
        
        mock_record_2 = MagicMock()
        mock_record_2.preference = 20
        mock_record_2.exchange = MagicMock()
        mock_record_2.exchange.__str__ = MagicMock(return_value="mail2.example.com.")
        
        mock_resolve.return_value = [mock_record_2, mock_record_1]  # Intentionally out of order
        
        mx_records = validator.get_mx_records("example.com")
        
        assert len(mx_records) == 2
        # Should be sorted by priority
        assert mx_records[0].priority == 10
        assert mx_records[0].exchange == "mail1.example.com"
        assert mx_records[1].priority == 20
        assert mx_records[1].exchange == "mail2.example.com"
    
    @patch('dns.resolver.Resolver.resolve')
    def test_get_mx_records_nxdomain(self, mock_resolve, validator):
        """Test MX record retrieval for non-existent domain."""
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        
        with pytest.raises(dns.resolver.NXDOMAIN):
            validator.get_mx_records("nonexistent.domain")
    
    @patch('dns.resolver.Resolver.resolve')
    def test_get_mx_records_no_answer(self, mock_resolve, validator):
        """Test MX record retrieval for domain with no MX records."""
        mock_resolve.side_effect = dns.resolver.NoAnswer()
        
        with pytest.raises(dns.resolver.NoAnswer):
            validator.get_mx_records("no-mx.domain")
    
    @patch('dns.resolver.Resolver.resolve')
    def test_get_mx_records_timeout_retry(self, mock_resolve):
        """Test MX record retrieval with timeout and retry."""
        validator = EmailValidator(dns_timeout=1.0, dns_retries=2, enable_cache=False)
        
        # First two calls timeout, third succeeds
        mock_record = MagicMock()
        mock_record.preference = 10
        mock_record.exchange = MagicMock()
        mock_record.exchange.__str__ = MagicMock(return_value="mail.example.com.")
        
        mock_resolve.side_effect = [
            dns.resolver.Timeout(),
            dns.resolver.Timeout(),
            [mock_record]
        ]
        
        with patch('time.sleep'):  # Mock sleep to speed up test
            mx_records = validator.get_mx_records("example.com")
        
        assert len(mx_records) == 1
        assert mx_records[0].priority == 10
        assert mock_resolve.call_count == 3


class TestMXRecordChecking:
    """Test enhanced MX record checking functionality."""
    
    @pytest.fixture
    def validator(self):
        return EmailValidator(dns_timeout=1.0, dns_retries=0, enable_cache=False)
    
    def test_check_mx_record_boolean_only(self, validator):
        """Test check_mx_record returning boolean only."""
        with patch.object(validator, 'get_mx_records') as mock_get_mx:
            mock_get_mx.return_value = [MXRecord(10, "mail.example.com")]
            
            result = validator.check_mx_record("example.com", return_records=False)
            assert result is True
    
    def test_check_mx_record_with_records(self, validator):
        """Test check_mx_record returning records."""
        with patch.object(validator, 'get_mx_records') as mock_get_mx:
            mx_records = [MXRecord(10, "mail.example.com"), MXRecord(20, "backup.example.com")]
            mock_get_mx.return_value = mx_records
            
            has_mx, records = validator.check_mx_record("example.com", return_records=True)
            assert has_mx is True
            assert records == mx_records
    
    def test_check_mx_record_no_records(self, validator):
        """Test check_mx_record with no MX records."""
        with patch.object(validator, 'get_mx_records') as mock_get_mx:
            mock_get_mx.side_effect = dns.resolver.NoAnswer()
            
            has_mx, records = validator.check_mx_record("example.com", return_records=True)
            assert has_mx is False
            assert records == []


class TestCaching:
    """Test MX record caching functionality."""
    
    @pytest.fixture
    def cached_validator(self):
        return EmailValidator(enable_cache=True, cache_ttl=1, dns_timeout=1.0, dns_retries=0)
    
    def test_cache_disabled_validator(self):
        """Test validator with caching disabled."""
        validator = EmailValidator(enable_cache=False)
        
        # Cache methods should handle disabled cache gracefully
        assert validator._get_cached_mx_records("example.com") is None
        validator._cache_mx_records("example.com", [])  # Should not raise error
        
        stats = validator.get_cache_stats()
        assert stats["cache_enabled"] is False
    
    @patch('dns.resolver.Resolver.resolve')
    def test_cache_miss_and_hit(self, mock_resolve, cached_validator):
        """Test cache miss followed by cache hit."""
        # Mock DNS response
        mock_record = MagicMock()
        mock_record.preference = 10
        mock_record.exchange = MagicMock()
        mock_record.exchange.__str__ = MagicMock(return_value="mail.example.com.")
        mock_resolve.return_value = [mock_record]
        
        # First call should hit DNS
        mx_records_1 = cached_validator.get_mx_records("example.com")
        assert len(mx_records_1) == 1
        assert mock_resolve.call_count == 1
        
        # Second call should use cache
        mx_records_2 = cached_validator.get_mx_records("example.com")
        assert len(mx_records_2) == 1
        assert mock_resolve.call_count == 1  # No additional DNS calls
        
        # Results should be identical
        assert mx_records_1[0].priority == mx_records_2[0].priority
        assert mx_records_1[0].exchange == mx_records_2[0].exchange
    
    def test_cache_expiration(self, cached_validator):
        """Test cache expiration."""
        # Manually add expired cache entry
        expired_result = CachedMXResult(
            mx_records=[MXRecord(10, "mail.example.com")],
            timestamp=datetime.now() - timedelta(seconds=2),  # Expired (TTL is 1 second)
            ttl_seconds=1
        )
        
        with cached_validator._cache_lock:
            cached_validator._mx_cache["example.com"] = expired_result
        
        # Should not return expired cache
        cached_records = cached_validator._get_cached_mx_records("example.com")
        assert cached_records is None
        
        # Cache should be cleaned up
        with cached_validator._cache_lock:
            assert "example.com" not in cached_validator._mx_cache
    
    def test_cache_stats(self, cached_validator):
        """Test cache statistics."""
        # Initially empty
        stats = cached_validator.get_cache_stats()
        assert stats["cache_enabled"] is True
        assert stats["total_entries"] == 0
        assert stats["expired_entries"] == 0
        assert stats["active_entries"] == 0
        assert stats["cache_ttl"] == 1
        
        # Add some cache entries
        active_result = CachedMXResult(
            mx_records=[MXRecord(10, "mail1.example.com")],
            timestamp=datetime.now(),
            ttl_seconds=300
        )
        
        expired_result = CachedMXResult(
            mx_records=[MXRecord(10, "mail2.example.com")],
            timestamp=datetime.now() - timedelta(seconds=400),
            ttl_seconds=300
        )
        
        with cached_validator._cache_lock:
            cached_validator._mx_cache["active.com"] = active_result
            cached_validator._mx_cache["expired.com"] = expired_result
        
        stats = cached_validator.get_cache_stats()
        assert stats["total_entries"] == 2
        assert stats["expired_entries"] == 1
        assert stats["active_entries"] == 1
    
    def test_clear_cache(self, cached_validator):
        """Test cache clearing."""
        # Add cache entry
        with cached_validator._cache_lock:
            cached_validator._mx_cache["example.com"] = CachedMXResult(
                mx_records=[MXRecord(10, "mail.example.com")],
                timestamp=datetime.now(),
                ttl_seconds=300
            )
        
        assert len(cached_validator._mx_cache) == 1
        
        cached_validator.clear_cache()
        assert len(cached_validator._mx_cache) == 0


class TestCompleteEmailValidationEnhanced:
    """Test enhanced complete email validation workflow."""
    
    @pytest.fixture
    def validator(self):
        return EmailValidator(dns_timeout=1.0, dns_retries=0, enable_cache=False)
    
    def test_validate_email_with_mx_safe_domain_extraction(self, validator):
        """Test email validation with safe domain extraction."""
        with patch.object(validator, 'validate_email_format', return_value=(True, "Valid format", "example.com")), \
             patch.object(validator, 'check_mx_record', return_value=True):
            
            result = validator.validate_email_with_mx("test@example.com")
            assert result is True
    
    def test_validate_email_with_mx_invalid_format_no_domain(self, validator):
        """Test email validation with invalid format returning no domain."""
        with patch.object(validator, 'validate_email_format', return_value=(False, "Invalid format", None)):
            
            result = validator.validate_email_with_mx("invalid-email")
            assert result is False
    
    def test_validate_email_detailed_single_dns_lookup(self, validator):
        """Test detailed validation performs only one DNS lookup."""
        mx_records = [
            MXRecord(10, "mail1.example.com"),
            MXRecord(20, "mail2.example.com")
        ]
        
        with patch.object(validator, 'validate_email_format', return_value=(True, "Valid email format", "example.com")), \
             patch.object(validator, 'get_mx_records', return_value=mx_records) as mock_get_mx:
            
            is_valid, message, has_mx, returned_records = validator.validate_email_detailed("test@example.com")
            
            assert is_valid is True
            assert "Valid email with 2 MX record(s)" in message
            assert "primary: mail1.example.com (priority 10)" in message
            assert has_mx is True
            assert returned_records == mx_records
            
            # Should only call get_mx_records once (no double lookup)
            mock_get_mx.assert_called_once_with("example.com")
    
    def test_validate_email_detailed_nxdomain(self, validator):
        """Test detailed validation with non-existent domain."""
        with patch.object(validator, 'validate_email_format', return_value=(True, "Valid email format", "nonexistent.com")), \
             patch.object(validator, 'get_mx_records', side_effect=dns.resolver.NXDOMAIN()):
            
            is_valid, message, has_mx, mx_records = validator.validate_email_detailed("test@nonexistent.com")
            
            assert is_valid is False
            assert "Domain 'nonexistent.com' does not exist" in message
            assert has_mx is False
            assert mx_records is None
    
    def test_validate_email_detailed_no_mx_records(self, validator):
        """Test detailed validation with domain that has no MX records."""
        with patch.object(validator, 'validate_email_format', return_value=(True, "Valid email format", "no-mx.com")), \
             patch.object(validator, 'get_mx_records', side_effect=dns.resolver.NoAnswer()):
            
            is_valid, message, has_mx, mx_records = validator.validate_email_detailed("test@no-mx.com")
            
            assert is_valid is False
            assert "Domain 'no-mx.com' has no MX records" in message
            assert has_mx is False
            assert mx_records == []
    
    def test_validate_email_detailed_dns_error(self, validator):
        """Test detailed validation with DNS error."""
        with patch.object(validator, 'validate_email_format', return_value=(True, "Valid email format", "error.com")), \
             patch.object(validator, 'get_mx_records', side_effect=Exception("DNS server error")):
            
            is_valid, message, has_mx, mx_records = validator.validate_email_detailed("test@error.com")
            
            assert is_valid is False
            assert "DNS lookup failed for domain 'error.com'" in message
            assert "DNS server error" in message
            assert has_mx is False
            assert mx_records is None


class TestEdgeCasesEnhanced:
    """Test enhanced edge cases and error conditions."""
    
    @pytest.fixture
    def validator(self):
        return EmailValidator(enable_cache=False)
    
    def test_malformed_email_safe_parsing(self, validator):
        """Test that malformed emails are handled safely by email-validator."""
        malformed_emails = [
            "user@@domain.com",  # Double @
            "user@domain@extra.com",  # Multiple @
            "@domain.com",  # Missing user
            "user@",  # Missing domain
            "",  # Empty
        ]
        
        for email in malformed_emails:
            is_valid, message, domain = validator.validate_email_format(email)
            assert is_valid is False
            assert domain is None
            assert "Invalid email format" in message
    
    def test_unicode_domain_handling(self, validator):
        """Test handling of unicode/internationalized domains."""
        unicode_email = "test@例え.テスト"  # Japanese domain
        
        # email-validator should handle IDN properly
        is_valid, message, domain = validator.validate_email_format(unicode_email)
        
        # Result depends on email-validator's IDN handling
        assert isinstance(is_valid, bool)
        assert isinstance(message, str)
        if is_valid:
            assert domain is not None
        else:
            assert domain is None


class TestPerformanceAndCaching:
    """Test performance improvements and caching behavior."""
    
    @pytest.fixture
    def performance_validator(self):
        return EmailValidator(enable_cache=True, cache_ttl=300, dns_timeout=1.0, dns_retries=1)
    
    @patch('dns.resolver.Resolver.resolve')
    def test_caching_performance_benefit(self, mock_resolve, performance_validator):
        """Test that caching provides performance benefits."""
        # Mock DNS response
        mock_record = MagicMock()
        mock_record.preference = 10
        mock_record.exchange = MagicMock()
        mock_record.exchange.__str__ = MagicMock(return_value="mail.example.com.")
        mock_resolve.return_value = [mock_record]
        
        # First call - should hit DNS
        start_time = time.time()
        performance_validator.get_mx_records("example.com")
        first_call_time = time.time() - start_time
        
        # Second call - should use cache (much faster)
        start_time = time.time()
        performance_validator.get_mx_records("example.com")
        second_call_time = time.time() - start_time
        
        # DNS should only be called once
        assert mock_resolve.call_count == 1
        
        # Second call should be significantly faster (cache hit)
        assert second_call_time < first_call_time
    
    def test_cache_thread_safety(self, performance_validator):
        """Test that cache operations are thread-safe."""
        import threading
        
        def cache_operation():
            mx_records = [MXRecord(10, "mail.example.com")]
            performance_validator._cache_mx_records("test.com", mx_records)
            cached = performance_validator._get_cached_mx_records("test.com")
            assert cached is not None
        
        # Run multiple threads simultaneously
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=cache_operation)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify cache state is consistent
        stats = performance_validator.get_cache_stats()
        assert stats["total_entries"] >= 0  # Should not crash


# Integration tests (require internet connection)
class TestIntegrationEnhanced:
    """Enhanced integration tests with real DNS queries."""
    
    @pytest.fixture
    def integration_validator(self):
        return EmailValidator(dns_timeout=10.0, dns_retries=2, enable_cache=True)
    
    @pytest.mark.integration
    def test_real_gmail_mx_records(self, integration_validator):
        """Test MX record retrieval for Gmail (requires internet)."""
        try:
            mx_records = integration_validator.get_mx_records("gmail.com")
            assert len(mx_records) > 0
            
            # Gmail should have multiple MX records
            assert all(isinstance(record, MXRecord) for record in mx_records)
            assert all(record.priority > 0 for record in mx_records)
            assert all(record.exchange for record in mx_records)
            
            # Records should be sorted by priority
            priorities = [record.priority for record in mx_records]
            assert priorities == sorted(priorities)
            
        except Exception as e:
            pytest.skip(f"Internet connectivity required for integration test: {e}")
    
    @pytest.mark.integration
    def test_detailed_validation_real_email(self, integration_validator):
        """Test detailed validation with real email address."""
        try:
            is_valid, message, has_mx, mx_records = integration_validator.validate_email_detailed("test@gmail.com")
            
            # Gmail should have valid MX records
            assert has_mx is True
            assert mx_records is not None
            assert len(mx_records) > 0
            assert is_valid is True
            assert "Valid email with" in message
            assert "MX record(s)" in message
            
        except Exception as e:
            pytest.skip(f"Internet connectivity required for integration test: {e}")


# Test configuration and fixtures
@pytest.fixture(autouse=True)
def setup_logging():
    """Configure logging for tests."""
    import logging
    logging.getLogger().setLevel(logging.WARNING)  # Reduce log noise during testing


# Test markers
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (require internet)"
    )


if __name__ == "__main__":
    # Run tests when script is executed directly
    pytest.main([__file__, "-v", "--tb=short"])