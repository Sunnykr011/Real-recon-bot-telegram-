"""
Utility functions for the reconnaissance bot
"""

import re
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

def split_text(text: str, max_length: int = 4000) -> list:
    """
    Split text into chunks suitable for Telegram messages
    
    Args:
        text: Text to split
        max_length: Maximum length per chunk
        
    Returns:
        List of text chunks
    """
    if len(text) <= max_length:
        return [text]
    
    chunks = []
    current_chunk = ""
    
    # Split by lines first to avoid breaking formatting
    lines = text.split('\n')
    
    for line in lines:
        # If adding this line would exceed limit
        if len(current_chunk) + len(line) + 1 > max_length:
            if current_chunk:
                chunks.append(current_chunk.strip())
                current_chunk = line
            else:
                # Line itself is too long, split it
                while len(line) > max_length:
                    chunks.append(line[:max_length])
                    line = line[max_length:]
                current_chunk = line
        else:
            if current_chunk:
                current_chunk += '\n' + line
            else:
                current_chunk = line
    
    if current_chunk:
        chunks.append(current_chunk.strip())
    
    return chunks

def validate_domain(domain: str) -> bool:
    """
    Validate domain name format
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid domain format
    """
    if not domain:
        return False
    
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '')
    
    # Remove path if present
    domain = domain.split('/')[0]
    
    # Basic domain validation regex
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}$'
    )
    
    # Also allow single-word domains and localhost
    simple_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*$')
    
    return bool(domain_pattern.match(domain) or simple_pattern.match(domain))

def sanitize_url(url: str) -> str:
    """
    Sanitize URL for safe display
    
    Args:
        url: URL to sanitize
        
    Returns:
        Sanitized URL
    """
    try:
        parsed = urlparse(url)
        # Reconstruct with only safe components
        sanitized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            sanitized += f"?{parsed.query[:200]}"  # Limit query length
        return sanitized
    except Exception:
        return url[:200]  # Fallback to truncation

def format_timestamp() -> str:
    """
    Get formatted timestamp for reports
    
    Returns:
        Formatted timestamp string
    """
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from URL
    
    Args:
        url: URL to extract domain from
        
    Returns:
        Domain name or empty string if invalid
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""

def is_valid_url(url: str) -> bool:
    """
    Check if URL is valid
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid URL
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def clean_text_for_telegram(text: str) -> str:
    """
    Clean text for safe Telegram display
    
    Args:
        text: Text to clean
        
    Returns:
        Cleaned text
    """
    if not text:
        return ""
    
    # Remove or escape problematic characters
    text = text.replace('`', '\\`')
    text = text.replace('*', '\\*')
    text = text.replace('_', '\\_')
    text = text.replace('[', '\\[')
    text = text.replace(']', '\\]')
    
    # Limit length
    if len(text) > 500:
        text = text[:497] + "..."
    
    return text

def get_domain_variations(domain: str) -> list:
    """
    Get common variations of a domain for comprehensive scanning
    
    Args:
        domain: Base domain
        
    Returns:
        List of domain variations
    """
    variations = [domain]
    
    # Add www variant
    if not domain.startswith('www.'):
        variations.append(f'www.{domain}')
    else:
        variations.append(domain[4:])  # Remove www
    
    # Add common subdomains
    common_subs = ['mail', 'ftp', 'admin', 'test', 'dev', 'staging']
    for sub in common_subs:
        variations.append(f'{sub}.{domain}')
    
    return list(set(variations))

def calculate_confidence_score(indicators: dict) -> float:
    """
    Calculate confidence score based on multiple indicators
    
    Args:
        indicators: Dictionary of confidence indicators
        
    Returns:
        Confidence score between 0 and 1
    """
    base_score = 0.5
    
    # Adjust based on indicators
    if indicators.get('error_patterns_matched', 0) > 0:
        base_score += 0.2
    
    if indicators.get('response_status') == 200:
        base_score += 0.1
    
    if indicators.get('content_length', 0) > 1000:
        base_score += 0.1
    
    if indicators.get('suspicious_headers', 0) > 0:
        base_score += 0.1
    
    return min(base_score, 1.0)

class RateLimiter:
    """Simple rate limiter for API requests"""
    
    def __init__(self, max_requests: int = 10, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
    
    def can_make_request(self) -> bool:
        """Check if request can be made within rate limits"""
        import time
        now = time.time()
        
        # Remove old requests outside time window
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time < self.time_window]
        
        return len(self.requests) < self.max_requests
    
    def record_request(self):
        """Record a new request"""
        import time
        self.requests.append(time.time())
    
    def get_wait_time(self) -> int:
        """Get time to wait before next request"""
        if not self.requests:
            return 0
        
        import time
        oldest_request = min(self.requests)
        wait_time = self.time_window - (time.time() - oldest_request)
        return max(0, int(wait_time))

def log_scan_activity(domain: str, scan_type: str, results_count: int):
    """Log scan activity for monitoring"""
    logger.info(f"Scan completed - Domain: {domain}, Type: {scan_type}, Results: {results_count}")

def generate_scan_id() -> str:
    """Generate unique scan ID"""
    import uuid
    import time
    return f"scan_{int(time.time())}_{str(uuid.uuid4())[:8]}"