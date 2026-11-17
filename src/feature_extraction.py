from __future__ import annotations
import ipaddress, math, re
from collections import Counter
from urllib.parse import urlsplit

SUSPICIOUS = ('login','verify','account','secure','update','webscr','signin','password','banking','confirm','wallet','suspend','unlock','billing')
SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rb.gy'}
FEATURE_NAMES = ['url_length','dot_count','hyphen_count','digit_count','special_char_count','has_https','is_ip_address','subdomain_count','suspicious_keyword_count','domain_length','path_length','parameter_count','has_at_symbol','url_entropy','is_shortened']

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 2048:
        raise ValueError('Enter a URL with 1 to 2048 characters.')
    if any(ord(c) < 32 or c.isspace() for c in value):
        raise ValueError('The URL cannot contain spaces or control characters.')
    candidate = value if '://' in value else 'http://' + value
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {'http','https'} or not parts.hostname:
        raise ValueError('Enter a valid HTTP or HTTPS URL with a hostname.')
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError('The URL contains an invalid port.') from exc
    return candidate

def url_length(url): return len(url)
def dot_count(url): return url.count('.')
def hyphen_count(url): return url.count('-')
def digit_count(url): return sum(ch.isdigit() for ch in url)
def special_char_count(url): return sum(not ch.isalnum() for ch in url)
def has_https(url): return int(urlsplit(url).scheme.lower() == 'https')
def is_ip_address(url):
    try: ipaddress.ip_address(urlsplit(url).hostname or ''); return 1
    except ValueError: return 0
def subdomain_count(url):
    host=(urlsplit(url).hostname or '').lower().rstrip('.')
    try: ipaddress.ip_address(host); return 0
    except ValueError: return max(0,len(host.split('.'))-2)
def suspicious_keyword_count(url):
    value=url.lower(); return sum(value.count(word) for word in SUSPICIOUS)
def domain_length(url): return len(urlsplit(url).hostname or '')
def path_length(url): return len(urlsplit(url).path)
def parameter_count(url): return len([p for p in urlsplit(url).query.split('&') if p])
def has_at_symbol(url): return int('@' in url)
def url_entropy(url):
    if not url: return 0.0
    counts=Counter(url); n=len(url)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())
def is_shortened(url): return int((urlsplit(url).hostname or '').lower().rstrip('.') in SHORTENERS)

_EXTRACTORS=[url_length,dot_count,hyphen_count,digit_count,special_char_count,has_https,is_ip_address,subdomain_count,suspicious_keyword_count,domain_length,path_length,parameter_count,has_at_symbol,url_entropy,is_shortened]
def extract_features(url: str) -> dict[str, float | int]:
    normalized=normalize_url(url)
    return {name: fn(normalized) for name,fn in zip(FEATURE_NAMES,_EXTRACTORS)}
