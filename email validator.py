import dns.resolver
import logging
import time
from typing import Tuple, List, Optional, Union
from email_validator import validate_email, EmailNotValidError
from functools import lru_cache
from datetime import datetime, timedelta
import threading

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MXRecord:
    """Represents an MX record with priority and exchange information."""
    
    def __init__(self, priority: int, exchange: str):
        self.priority = priority
        self.exchange = exchange
    
    def __str__(self):
        return f"MX {self.priority} {self.exchange}"
    
    def __repr__(self):
        return f"MXRecord(priority={self.priority}, exchange='{self.exchange}')"

class CachedMXResult:
    """Cached MX lookup result with expiration."""
    
    def __init__(self, mx_records: List[MXRecord], timestamp: datetime, ttl_seconds: int = 300):
        self.mx_records = mx_records
        self.timestamp = timestamp
        self.ttl_seconds = ttl_seconds
    
    def is_expired(self) -> bool:
        return datetime.now() - self.timestamp > timedelta(seconds=self.ttl_seconds)

class EmailValidator:
    """Enhanced email validator with DNS timeout, retries, caching, and better error handling."""
    
    def __init__(self, dns_timeout: float = 5.0, dns_retries: int = 2, 
                 enable_cache: bool = True, cache_ttl: int = 300):
        """
        Initialize email validator with DNS configuration and optional caching.
        
        Args:
            dns_timeout: DNS query timeout in seconds
            dns_retries: Number of DNS query retries
            enable_cache: Enable MX record caching
            cache_ttl: Cache TTL in seconds (default: 5 minutes)
        """
        self.dns_timeout = dns_timeout
        self.dns_retries = dns_retries
        self.enable_cache = enable_cache
        self.cache_ttl = cache_ttl
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout
        
        # Initialize cache if enabled
        if self.enable_cache:
            self._mx_cache = {}
            self._cache_lock = threading.Lock()
        
        logger.info(f"EmailValidator initialized with timeout={dns_timeout}s, "
                   f"retries={dns_retries}, cache={'enabled' if enable_cache else 'disabled'}")
    
    def _get_cached_mx_records(self, domain: str) -> Optional[List[MXRecord]]:
        """Get cached MX records if available and not expired."""
        if not self.enable_cache:
            return None
        
        with self._cache_lock:
            if domain in self._mx_cache:
                cached_result = self._mx_cache[domain]
                if not cached_result.is_expired():
                    logger.debug(f"Using cached MX records for {domain}")
                    return cached_result.mx_records
                else:
                    logger.debug(f"Cached MX records for {domain} expired, removing")
                    del self._mx_cache[domain]
        
        return None
    
    def _cache_mx_records(self, domain: str, mx_records: List[MXRecord]):
        """Cache MX records for the specified domain."""
        if not self.enable_cache:
            return
        
        with self._cache_lock:
            self._mx_cache[domain] = CachedMXResult(
                mx_records=mx_records,
                timestamp=datetime.now(),
                ttl_seconds=self.cache_ttl
            )
            logger.debug(f"Cached {len(mx_records)} MX records for {domain}")
    
    def get_mx_records(self, domain: str) -> List[MXRecord]:
        """
        Get MX records for a domain with retry logic and caching.
        
        Args:
            domain: Domain name to check
            
        Returns:
            List[MXRecord]: List of MX records, empty if none found
            
        Raises:
            dns.resolver.NXDOMAIN: Domain does not exist
            dns.resolver.NoAnswer: Domain exists but has no MX records
            dns.resolver.Timeout: DNS query timed out
            Exception: Other DNS-related errors
        """
        # Check cache first
        cached_records = self._get_cached_mx_records(domain)
        if cached_records is not None:
            return cached_records
        
        # Perform DNS lookup with retries
        last_exception = None
        for attempt in range(self.dns_retries + 1):
            try:
                logger.debug(f"DNS MX lookup attempt {attempt + 1} for domain: {domain}")
                dns_records = self.resolver.resolve(domain, 'MX')
                
                # Convert DNS records to our MXRecord objects
                mx_records = [
                    MXRecord(priority=record.preference, exchange=str(record.exchange).rstrip('.'))
                    for record in dns_records
                ]
                
                # Sort by priority (lower number = higher priority)
                mx_records.sort(key=lambda x: x.priority)
                
                logger.info(f"Found {len(mx_records)} MX record(s) for {domain}")
                
                # Cache the results
                self._cache_mx_records(domain, mx_records)
                
                return mx_records
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                # These are definitive answers, no need to retry
                logger.warning(f"No MX records for {domain}")
                self._cache_mx_records(domain, [])  # Cache empty result
                raise
                
            except dns.resolver.Timeout as e:
                last_exception = e
                logger.warning(f"DNS timeout for {domain} (attempt {attempt + 1})")
                if attempt < self.dns_retries:
                    time.sleep(0.5 * (attempt + 1))  # Exponential backoff
                    continue
                    
            except Exception as e:
                last_exception = e
                logger.error(f"DNS lookup failed for {domain} (attempt {attempt + 1}): {str(e)}")
                if attempt < self.dns_retries:
                    time.sleep(0.5 * (attempt + 1))  # Exponential backoff
                    continue
        
        # All retries failed
        logger.error(f"All DNS lookup attempts failed for {domain}")
        if last_exception:
            raise last_exception
        else:
            raise Exception(f"DNS lookup failed for {domain} after {self.dns_retries + 1} attempts")
    
    def check_mx_record(self, domain: str, return_records: bool = False) -> Union[bool, Tuple[bool, List[MXRecord]]]:
        """
        Check if domain has MX records with retry logic.
        
        Args:
            domain: Domain name to check
            return_records: If True, return the actual MX records along with boolean result
            
        Returns:
            Union[bool, Tuple[bool, List[MXRecord]]]: 
                - If return_records=False: True if MX records exist, False otherwise
                - If return_records=True: (has_mx_records, mx_records_list)
        """
        try:
            mx_records = self.get_mx_records(domain)
            has_mx = len(mx_records) > 0
            
            if return_records:
                return has_mx, mx_records
            else:
                return has_mx
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            if return_records:
                return False, []
            else:
                return False
                
        except Exception as e:
            logger.error(f"MX record check failed for {domain}: {str(e)}")
            if return_records:
                return False, []
            else:
                return False
    
    def validate_email_format(self, email: str) -> Tuple[bool, str, Optional[str]]:
        """
        Validate email format using email-validator library.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple[bool, str, Optional[str]]: (is_valid, message, domain)
        """
        try:
            # Use email-validator for comprehensive format validation
            validated_email = validate_email(
                email,
                check_deliverability=False  # We'll do our own MX check
            )
            
            domain = validated_email.domain
            logger.debug(f"Email format valid: {email} -> normalized: {validated_email.email}, domain: {domain}")
            return True, "Valid email format", domain
            
        except EmailNotValidError as e:
            logger.warning(f"Invalid email format: {email} - {str(e)}")
            return False, f"Invalid email format: {str(e)}", None
    
    def validate_email_with_mx(self, email: str) -> bool:
        """
        Simple email validation with MX record check.
        
        Args:
            email: Email address to validate
            
        Returns:
            bool: True if email is valid and has MX records
        """
        # Check format first and extract domain safely
        format_valid, _, domain = self.validate_email_format(email)
        if not format_valid or not domain:
            return False
        
        # Check MX record using the extracted domain
        return self.check_mx_record(domain)
    
    def validate_email_detailed(self, email: str) -> Tuple[bool, str, bool, Optional[List[MXRecord]]]:
        """
        Validates email with detailed feedback including MX records.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple[bool, str, bool, Optional[List[MXRecord]]]: 
                (is_valid, message, has_mx_record, mx_records)
        """
        logger.info(f"Validating email: {email}")
        
        # Check format first and extract domain safely
        format_valid, format_message, domain = self.validate_email_format(email)
        if not format_valid or not domain:
            logger.info(f"Email validation failed - format: {email}")
            return False, format_message, False, None
        
        # Check MX records using the safely extracted domain (single lookup)
        try:
            mx_records = self.get_mx_records(domain)
            has_mx = len(mx_records) > 0
            
            if has_mx:
                # Create detailed message with MX information
                primary_mx = mx_records[0] if mx_records else None
                if primary_mx:
                    message = f"Valid email with {len(mx_records)} MX record(s), primary: {primary_mx.exchange} (priority {primary_mx.priority})"
                else:
                    message = f"Valid email with {len(mx_records)} MX record(s)"
                
                logger.info(f"Email validation successful: {email}")
                return True, message, True, mx_records
            else:
                logger.info(f"Email validation failed - no MX records: {email}")
                return False, f"Domain '{domain}' has no MX records", False, []
                
        except dns.resolver.NXDOMAIN:
            logger.info(f"Email validation failed - domain does not exist: {email}")
            return False, f"Domain '{domain}' does not exist", False, None
            
        except dns.resolver.NoAnswer:
            logger.info(f"Email validation failed - no MX records: {email}")
            return False, f"Domain '{domain}' has no MX records", False, []
            
        except Exception as e:
            logger.error(f"Email validation error for {email}: {str(e)}")
            return False, f"DNS lookup failed for domain '{domain}': {str(e)}", False, None
    
    def clear_cache(self):
        """Clear the MX record cache."""
        if self.enable_cache:
            with self._cache_lock:
                self._mx_cache.clear()
                logger.info("MX record cache cleared")
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        if not self.enable_cache:
            return {"cache_enabled": False}
        
        with self._cache_lock:
            total_entries = len(self._mx_cache)
            expired_entries = sum(1 for result in self._mx_cache.values() if result.is_expired())
            
            return {
                "cache_enabled": True,
                "total_entries": total_entries,
                "expired_entries": expired_entries,
                "active_entries": total_entries - expired_entries,
                "cache_ttl": self.cache_ttl
            }


def run_interactive_test():
    """Run interactive email validation with graceful Ctrl+C handling."""
    validator = EmailValidator(enable_cache=True, cache_ttl=300)
    
    print("=== Interactive Email Validator ===")
    print("Enter email addresses to validate (or 'quit' to exit)")
    print("Commands: 'cache' for cache stats, 'clear' to clear cache")
    print("Press Ctrl+C to exit gracefully\n")
    
    try:
        while True:
            try:
                user_input = input("Enter email or command: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    break
                elif user_input.lower() == 'cache':
                    stats = validator.get_cache_stats()
                    print(f"\nCache Statistics:")
                    for key, value in stats.items():
                        print(f"  {key}: {value}")
                    print()
                    continue
                elif user_input.lower() == 'clear':
                    validator.clear_cache()
                    print("✓ Cache cleared\n")
                    continue
                
                if not user_input:
                    print("Please enter a valid email address.\n")
                    continue
                
                print(f"\nValidating: {user_input}")
                print("-" * 60)
                
                # Detailed validation with MX records
                is_valid, message, has_mx, mx_records = validator.validate_email_detailed(user_input)
                
                # Format validation check
                format_valid, format_message, domain = validator.validate_email_format(user_input)
                print(f"Format valid:  {'✓' if format_valid else '✗'}")
                if domain:
                    print(f"Domain:        {domain}")
                
                # MX records information
                print(f"MX records:    {'✓' if has_mx else '✗'}")
                if mx_records and len(mx_records) > 0:
                    print(f"MX count:      {len(mx_records)}")
                    print("MX details:")
                    for i, mx in enumerate(mx_records[:3]):  # Show first 3 MX records
                        print(f"  {i+1}. {mx}")
                    if len(mx_records) > 3:
                        print(f"  ... and {len(mx_records) - 3} more")
                
                # Overall result
                print(f"Overall:       {'✓ VALID' if is_valid else '✗ INVALID'}")
                print(f"Details:       {message}")
                print()
                
            except EOFError:
                # Handle Ctrl+D
                break
                
    except KeyboardInterrupt:
        print("\n\n👋 Email validation interrupted. Goodbye!")
    except Exception as e:
        logger.error(f"Unexpected error in interactive mode: {e}")
        print(f"❌ An unexpected error occurred: {e}")
    
    print("Exiting email validator...")


def main():
    """Main function demonstrating the enhanced email validator."""
    # Initialize validator with caching enabled
    validator = EmailValidator(dns_timeout=3.0, dns_retries=1, enable_cache=True, cache_ttl=300)
    
    # Test with different email addresses
    test_emails = [
        "yash.trivedi@tvsmotor.com",           # Valid with MX records
        "logeshwaran.e@hettich.com",         # Valid format, may have MX records
        "invalid.email@nonexistentdomain12345.com",  # Invalid domain
        "not-an-email",                      # Invalid format
        "test@gmail.com",                    # Should be valid
        "user@example.com",                  # May or may not have MX records
    ]
    
    print("=== Enhanced Email Validator Demo ===\n")
    
    print("=== Simple Validation ===")
    for email in test_emails:
        is_valid = validator.validate_email_with_mx(email)
        print(f"{email:40} -> {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    print(f"\n=== Detailed Validation with MX Records ===")
    for email in test_emails:
        is_valid, message, has_mx, mx_records = validator.validate_email_detailed(email)
        status = "✓" if is_valid else "✗"
        print(f"{email:40} -> {status} {message}")
        
        if mx_records and len(mx_records) > 0:
            print(f"{'':42}    Primary MX: {mx_records[0]}")
    
    print(f"\n=== Cache Performance Demo ===")
    # Test the same email twice to show caching
    test_email = "test@gmail.com"
    print(f"First lookup for {test_email}:")
    start_time = time.time()
    validator.validate_email_detailed(test_email)
    first_time = time.time() - start_time
    
    print(f"Second lookup for {test_email} (should use cache):")
    start_time = time.time()
    validator.validate_email_detailed(test_email)
    second_time = time.time() - start_time
    
    print(f"First lookup time: {first_time:.3f}s")
    print(f"Second lookup time: {second_time:.3f}s")
    print(f"Speed improvement: {(first_time/second_time):.1f}x faster")
    
    # Show cache stats
    stats = validator.get_cache_stats()
    print(f"\nCache Statistics: {stats}")
    
    print("\n" + "="*60)
    # Run interactive test
    run_interactive_test()


if __name__ == "__main__":
    main()