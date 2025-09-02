#!/usr/bin/env python3
"""
Bot Attack Simulator
Simulates various bot attack patterns with distinguishable characteristics
"""

import requests
import time
import random
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional
import logging
from dataclasses import dataclass
import click
from faker import Faker
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

fake = Faker()

@dataclass
class AttackConfig:
    target_url: str
    attack_ip: str = "192.168.1.100"
    attack_duration: int = 600
    request_rate: float = 5.0
    attack_type: str = "scraping"

class BotAttacker:
    """Simulates various types of bot attacks"""
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self.session = requests.Session()
        self.attack_start = time.time()
        self.requests_made = 0
        self.attack_patterns = {
            'scraping': self._scraping_attack,
            'credential_stuffing': self._credential_stuffing_attack,
            'ddos': self._ddos_attack,
            'parameter_tampering': self._parameter_tampering_attack,
            'cookie_manipulation': self._cookie_manipulation_attack,
            'header_anomaly': self._header_anomaly_attack
        }
        

        self._setup_bot_headers()
    
    def _setup_bot_headers(self):
        """Setup headers that appear human-like but have subtle flaws"""
        # Mix of human-like user agents AND bot signatures that will trigger WAF rules
        human_like_user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            # Subtle flaws: slightly off version numbers or combinations
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.1 Safari/537.36',  # .1 instead of .0
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',  # 10_15_8 doesn't exist
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.1) Gecko/20100101 Firefox/119.0',  # rv:109.1 unusual
            # ADD: Bot signatures that will trigger WAF rules (30% of requests)
            'python-requests/2.31.0',
            'urllib/3.2',
            'curl/8.0.1',
            'wget/1.21.3',
            'scrapy/2.11.0',
            'bot-crawler/1.0',
        ]
        
        # Human-like IP ranges (residential/mobile) to appear legitimate
        human_like_ip_ranges = [
            '73.158.',      # Comcast residential
            '24.21.',       # Charter/Spectrum
            '98.234.',      # AT&T residential  
            '75.56.',       # Verizon FiOS
            '173.79.',      # T-Mobile
            '166.137.',     # Verizon Wireless
            '185.92.',      # European residential
            '45.134.',      # Various residential proxies
        ]
        
        # Generate human-like IP but with subtle patterns bots might use
        base_ip = random.choice(human_like_ip_ranges)
        # Subtle flaw: limited range in last two octets (more predictable)
        self.bot_ip = base_ip + f"{random.randint(100, 199)}.{random.randint(100, 199)}"
        

        # Always use human-like headers with subtle flaws
        selected_ua = random.choice(human_like_user_agents)
        
        # Generate browser-consistent headers but with subtle issues
        base_headers = {
            'User-Agent': selected_ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # ADD: Sometimes skip common browser headers to trigger WAF "Missing Headers" rule (20% of requests)
        if random.random() < 0.2:
            # Remove some headers that browsers always send
            headers_to_remove = random.choice([
                ['Accept-Language'],  # Missing language header
                ['Accept-Encoding'],  # Missing encoding header  
                ['Accept-Language', 'Accept-Encoding'],  # Missing both
                ['Upgrade-Insecure-Requests'],  # Missing upgrade header
            ])
            for header in headers_to_remove:
                base_headers.pop(header, None)
        
        # Add subtle flaws based on attack type
        if self.config.attack_type == 'scraping':
            # Subtle flaw: slightly wrong Accept header ordering
            base_headers['Accept'] = 'text/html,application/xml;q=0.9,application/xhtml+xml,image/webp,*/*;q=0.8'
            # Subtle flaw: Accept-Language too simple
            base_headers['Accept-Language'] = 'en-US,en;q=0.9'  # Missing other common languages
            
        elif self.config.attack_type == 'credential_stuffing':
            # Subtle flaw: wrong Content-Type priority
            base_headers['Accept'] = 'text/html,application/xhtml+xml;q=0.9,application/xml;q=0.8'
            # Subtle flaw: too precise quality values
            base_headers['Accept-Language'] = 'en-US;q=1.0,en;q=0.9'
            
        elif self.config.attack_type == 'ddos':
            # Subtle flaw: missing cache control that humans would have
            pass  # Use base headers but don't add cache control
            
        else:
            # Subtle flaw: Accept-Encoding order is wrong
            base_headers['Accept-Encoding'] = 'deflate, gzip'  # Wrong order
        
        # Add DNT header occasionally (but inconsistently)
        if random.random() < 0.3:  # Less frequent than humans
            base_headers['DNT'] = '1'
            
        self.session.headers.update(base_headers)
    
    def _scraping_attack(self) -> Dict:
        """Simulate web scraping behavior with human-like cookies but subtle flaws"""
        endpoints = ['/', '/api/data', '/api/stats', '/search', '/login.html']
        endpoint = random.choice(endpoints)
        
        # More human-like parameters
        params = {}
        if random.random() < 0.6:
            params['utm_source'] = random.choice(['google', 'bing', 'direct'])
            params['utm_medium'] = 'organic'
        
        # Human-like cookies with subtle flaws
        cookies = self._generate_human_like_cookies_with_flaws('scraping')
        
        return {
            'endpoint': endpoint,
            'params': params,
            'cookies': cookies,
            'method': 'GET'
        }
    
    def _credential_stuffing_attack(self) -> Dict:
        """Simulate credential stuffing/brute force attack with human-like appearance"""
        endpoint = '/login.html'
        
        # More realistic credential attempts
        usernames = ['john.smith', 'admin', 'user123', 'testuser', 'demo', 'guest']
        passwords = ['password123', 'Password1!', 'admin123', 'qwerty123', 'welcome1', 'test123']
        
        data = {
            'username': random.choice(usernames),
            'password': random.choice(passwords),
            'remember_me': random.choice(['true', 'false']),
            'login_type': 'standard'
        }
        
        # Human-like cookies with subtle flaws for credential stuffing
        cookies = self._generate_human_like_cookies_with_flaws('credential_stuffing')
        
        return {
            'endpoint': endpoint,
            'params': {},
            'cookies': cookies,
            'method': 'POST',
            'data': data
        }
    
    def _ddos_attack(self) -> Dict:
        """Simulate DDoS attack pattern with human-like cookies"""
        endpoints = ['/api/data', '/search', '/', '/api/stats']
        endpoint = random.choice(endpoints)
        
        # More realistic parameters that don't immediately scream attack
        params = {}
        if endpoint == '/search':
            params['q'] = random.choice(['test', 'demo', 'search term', 'data'])
            params['page'] = random.randint(1, 10)
        elif endpoint == '/api/data':
            params['limit'] = random.choice([10, 20, 50])  # Reasonable limits
            params['format'] = 'json'
        
        # Human-like cookies with subtle flaws for DDoS
        cookies = self._generate_human_like_cookies_with_flaws('ddos')
        
        return {
            'endpoint': endpoint,
            'params': params,
            'cookies': cookies,
            'method': 'GET'
        }
    
    def _parameter_tampering_attack(self) -> Dict:
        """Simulate parameter tampering and injection attempts with human-like appearance"""
        endpoints = ['/api/data', '/search', '/api/stats']
        endpoint = random.choice(endpoints)
        
        # More subtle injection attempts mixed with normal parameters
        subtle_payloads = [
            "test' OR '1'='1",  # Less obvious SQL injection
            "admin",  # Simple but could be malicious
            "../config",  # Path traversal but subtle
            "{{config}}",  # Template injection but subtle
            "test<script>",  # Partial XSS
        ]
        
        params = {}
        if endpoint == '/search':
            params['q'] = random.choice(['normal search'] + subtle_payloads)
            params['filter'] = random.choice(['all', 'recent', 'popular'])
        elif endpoint == '/api/data':
            params['id'] = random.choice([str(random.randint(1, 1000))] + subtle_payloads)
            params['format'] = 'json'
        else:
            params['query'] = random.choice(['stats'] + subtle_payloads)
        
        # Human-like cookies with subtle flaws for parameter tampering
        cookies = self._generate_human_like_cookies_with_flaws('parameter_tampering')
        
        return {
            'endpoint': endpoint,
            'params': params,
            'cookies': cookies,
            'method': 'GET'
        }
    
    def _cookie_manipulation_attack(self) -> Dict:
        """Simulate highly sophisticated cookie manipulation attacks that try to mimic humans with subtle flaws"""
        endpoint = random.choice(['/', '/api/data', '/api/stats', '/search', '/login'])
        
        # Advanced attack types that are much harder to detect
        attack_type = random.choice([
            'entropy_manipulation', 'timing_pattern', 'browser_spoofing', 
            'analytics_mimicry', 'session_hijacking', 'fingerprint_evasion',
            'privacy_contradiction', 'automation_signature'
        ])
        
        if attack_type == 'entropy_manipulation':
            # Sophisticated low-entropy patterns that look random but aren't
            cookies = {
                'session_id': self._generate_low_entropy_session(),  # Subtle pattern
                'user_id': f"u_{random.randint(100000, 199999)}",  # Limited range
                'fingerprint': ''.join(random.choices('abcdef0123456789', k=32)),  # Low entropy hex
                '_ga': f"GA1.2.{random.randint(100000000, 199999999)}.{int(time.time())}",  # Constrained range
                'device_id': ''.join(random.choices('ABCD1234', k=16)),  # Very low entropy
                'csrf_token': ''.join(['x'] * 32),  # All same character
            }
            
        elif attack_type == 'timing_pattern':
            # Systematic timing patterns that reveal automation
            timestamp = int(time.time())
            cookies = {
                'session_id': f"T{timestamp % 1000000}{random.randint(10, 99)}",
                'user_id': f"u_{timestamp % 1000000}",  # Time-based but obvious
                'last_action': str(timestamp),  # Too precise timing
                'visit_count': str(random.randint(1, 5)),  # Too low for session age
                'page_load_time': '0.001',  # Impossibly fast
                '_ga': f"GA1.2.{timestamp}.{timestamp + random.randint(1, 100)}",
            }
            
        elif attack_type == 'browser_spoofing':
            # Mixed browser signals that don't make sense together
            browser_spoof = random.choice(['chrome_firefox_mix', 'safari_chrome_mix', 'impossible_versions'])
            if browser_spoof == 'chrome_firefox_mix':
                cookies = {
                    'session_id': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=20)),
                    '__cfduid': f"{random.randint(10**10, 10**11-1)}",  # Chrome cookie
                    '__ff_session': f"ff_{random.randint(10**6, 10**7-1)}",  # Firefox cookie - contradiction!
                    '_chrome_ver': '120.0.0.0',
                    '_ff_ver': '119.0',  # Can't have both browsers
                }
            elif browser_spoof == 'safari_chrome_mix':
                cookies = {
                    'session_id': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=18)),
                    '__webkit_id': f"wk_{random.randint(10**8, 10**9-1)}",  # Safari
                    '__cfduid': f"{random.randint(10**15, 10**16-1)}",  # Chrome - contradiction!
                    '_safari_ver': '17.1',
                    '_chrome_ver': '120.0.0.0',  # Can't have both
                }
            else:  # impossible_versions
                cookies = {
                    'session_id': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16)),
                    '_chrome_ver': '999.0.0.0',  # Future version
                    '_ff_ver': '200.0',  # Impossible version  
                    '_safari_ver': '99.0',  # Future version
                }
                
        elif attack_type == 'analytics_mimicry':
            # Fake analytics that look real but have systematic errors
            cookies = {
                'session_id': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.choice([10, 12, 14]))),  # Wrong lengths
                '_ga': f"GA1.2.{random.randint(111111111, 222222222)}.{int(time.time())}",  # Limited range
                '_gid': f"GA1.2.{random.randint(111111111, 222222222)}",  # Same limited range
                '_gat': '1',  # Always set (suspicious)
                '_gac': f"1.{random.randint(1000000000, 1999999999)}",  # Wrong format
                '__utma': f"{random.randint(1, 999)}.{random.randint(1, 999)}",  # Too simple
                '_fbp': f"fb.1.{int(time.time())}.{random.randint(1, 999999)}"  # Wrong pattern length
            }
            
        elif attack_type == 'session_hijacking':
            # Patterns that suggest session hijacking or sharing
            base_session = random.randint(10000, 99999)
            cookies = {
                'session_id': f"hijacked_{base_session}_{random.randint(1, 10)}",  # Multiple sessions
                'original_session': f"orig_{base_session}",
                'user_id': f"u_{random.randint(1, 1000)}",  # Low user ID range
                'concurrent_sessions': str(random.randint(5, 20)),  # Too many sessions
                'ip_history': f"{random.randint(1, 255)}.{random.randint(1, 255)}.x.x",  # Partial IP leak
                'auth_token': f"auth_{random.randint(1000, 9999)}",  # Predictable auth
            }
            
        elif attack_type == 'fingerprint_evasion':
            # Attempts to evade fingerprinting but creates suspicious patterns
            cookies = {
                'session_id': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.choice([24, 28, 36]))),  # Unusual lengths
                'anti_fingerprint': 'enabled',
                'canvas_block': 'true',
                'webgl_disabled': 'true', 
                'font_randomization': 'active',
                'timezone_spoof': random.choice(['UTC+0', 'GMT', 'PST']),  # Limited options
                'language_override': 'en-US',  # Always same language
                'screen_fake': f"{random.choice(['1920x1080', '1366x768'])}"  # Limited screen sizes
            }
            
        elif attack_type == 'privacy_contradiction':
            # Privacy settings that contradict the tracking behavior
            cookies = {
                'session_id': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16)),
                'privacy_consent': 'false',  # Says no tracking
                'do_not_track': '1',  # DNT header
                'tracking_enabled': 'true',  # But tracking anyway - contradiction!
                'gdpr_consent': 'required',  # Never actually consented
                'cookie_consent': 'denied',  # Denied cookies but has them
                '_ga': f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}",  # Tracking despite denial
                '_fbp': f"fb.1.{int(time.time())}.{random.randint(100000000, 999999999)}",  # Facebook tracking despite denial
            }
            
        else:  # automation_signature
            # Subtle automation tool signatures (obfuscated but detectable)
            import base64
            automation_signatures = {
                'tool_type': 'selenium',
                'headless': 'true', 
                'webdriver': 'chrome',
                'automation_session': f"auto_{random.randint(10000, 99999)}"
            }
            
            cookies = {
                'session_id': f"auto_{int(time.time()) % 100000}_{random.randint(100, 999)}",
            }
            
            # Obfuscate automation signatures
            for key, value in automation_signatures.items():
                if random.random() < 0.7:
                    # Base64 encode key names
                    encoded_key = base64.b64encode(key.encode()).decode()[:8]
                    cookies[f"_{encoded_key}"] = value
                else:
                    cookies[key] = value
                    
            # Add some legitimate-looking cookies to blend in
            cookies.update({
                'user_id': f"u_{random.randint(100000, 999999)}",
                '_ga': f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}",
                'csrf_token': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
            })
        
        return {
            'endpoint': endpoint,
            'params': {'test': f'sophisticated_cookie_{attack_type}'},
            'cookies': cookies,
            'method': 'GET'
        }
    
    def _generate_low_entropy_session(self) -> str:
        """Generate session ID with suspiciously low entropy"""
        patterns = [
            # Repeated patterns
            lambda: ('abc123' * 6)[:random.randint(12, 24)],
            # Limited character set
            lambda: ''.join(random.choices('ABCD1234', k=random.randint(16, 32))),
            # Sequential patterns  
            lambda: ''.join([chr(65 + (i % 26)) for i in range(random.randint(12, 20))]),
            # Date-based patterns (predictable)
            lambda: f"{int(time.time())}{random.randint(100, 999)}",
            # Keyboard patterns
            lambda: 'qwerty123456' + str(random.randint(100, 999)),
        ]
        return random.choice(patterns)()
    
    def _generate_human_like_cookies_with_flaws(self, attack_type: str) -> Dict:
        """Generate sophisticated human-like cookies with subtle detectable flaws"""
        # Base human-like session ID with high entropy
        session_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        
        # Subtle flaw: session length is always the same (real humans have variety)
        session_length = 24  # Always 24 chars - this is a subtle pattern
        session_id = ''.join(random.choices(session_chars, k=session_length))
        
        # Base human-like cookies
        cookies = {
            'session_id': session_id,
            'user_id': f"u_{random.randint(100000, 999999)}",
            'timezone': random.choice(['EST', 'PST', 'GMT', 'CET']),
            'last_visit': str(int(time.time() - random.randint(3600, 86400))),
        }
        
        # Add realistic analytics cookies with subtle flaws
        if attack_type in ['scraping', 'parameter_tampering']:
            # Subtle flaw: _ga always has same format pattern
            cookies['_ga'] = f"GA1.2.{random.randint(111111111, 222222222)}.{int(time.time())}"  # Limited range
            cookies['_gid'] = f"GA1.2.{random.randint(111111111, 222222222)}"  # Same limited range
            # Subtle flaw: _gat is always present (real users have variation)
            cookies['_gat'] = '1'
        
        # Add realistic personalization cookies
        cookies.update({
            'prefs': json.dumps({
                'theme': random.choice(['dark', 'light', 'auto']),
                'lang': 'en-US',
                'notifications': random.choice([True, False])
            }),
            'region': random.choice(['US', 'EU', 'APAC']),
        })
        
        # Add CSRF token with subtle flaw
        # Subtle flaw: CSRF token length is always 32 (real apps vary)
        csrf_length = 32  # Always same length
        cookies['csrf_token'] = ''.join(random.choices(session_chars, k=csrf_length))
        
        # Add shopping/ecommerce cookies occasionally
        if random.random() < 0.4:
            # Subtle flaw: cart_id has predictable pattern
            cookies['cart_id'] = f"cart_{random.randint(100000, 199999)}"  # Limited range
            cookies['wishlist'] = f"wl_{random.randint(1000, 9999)}"
        
        # Attack-specific subtle flaws
        if attack_type == 'scraping':
            # Subtle flaw: too many product views for session time
            cookies['viewed_products'] = ','.join([f"p{random.randint(100, 999)}" for _ in range(random.randint(5, 15))])  # Too many
            # Subtle flaw: session duration vs pages viewed doesn't match human behavior
            cookies['pages_viewed'] = str(random.randint(50, 200))  # Too many for typical session
            
        elif attack_type == 'credential_stuffing':
            # Subtle flaw: login attempt counter (humans don't usually have this)
            cookies['login_attempts'] = str(random.randint(1, 5))
            # Subtle flaw: password_reset_token present without user action
            cookies['password_reset_token'] = ''.join(random.choices(session_chars, k=20))
            
        elif attack_type == 'ddos':
            # Subtle flaw: performance metrics that are too consistent
            cookies['page_load_time'] = '0.123'  # Too consistent timing
            cookies['bandwidth_test'] = 'complete'  # Unusual cookie
            
        # Add marketing cookies with flaws
        if random.random() < 0.6:
            # Subtle flaw: utm parameters in cookies that don't match typical user flow
            cookies.update({
                'utm_source': random.choice(['google', 'bing', 'direct']),
                'utm_medium': 'organic',
                'utm_campaign': f"camp_{random.randint(1000, 9999)}",
                # Subtle flaw: source and referrer don't always align
                'referrer': random.choice(['https://google.com', 'https://bing.com', 'direct'])  # May not match utm_source
            })
        
        return cookies
    
    def _header_anomaly_attack(self) -> Dict:
        """Simulate attacks with unusual headers"""
        endpoint = random.choice(['/', '/api/data'])
        

        suspicious_headers = {
            'X-Forwarded-For': '127.0.0.1, 10.0.0.1, 192.168.1.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '192.168.1.100',
            'X-Attack-Tool': 'CustomBot/1.0',
            'X-Automated-Request': 'true',
            'X-Scanner': 'VulnScanner',
            'Referer': 'http://malicious-site.com/attack',
            'Accept-Encoding': '',
            'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0'
        }
        

        original_headers = self.session.headers.copy()
        self.session.headers.update(suspicious_headers)
        
        cookies = {
            'header_attack': 'true',
            'injection_type': 'header_manipulation'
        }
        
        return {
            'endpoint': endpoint,
            'params': {},
            'cookies': cookies,
            'method': 'GET',
            '_reset_headers': original_headers
        }
    
    def make_attack_request(self) -> bool:
        """Make a single attack request"""
        try:
            attack_method = self.attack_patterns.get(self.config.attack_type, self._scraping_attack)
            attack_data = attack_method()
            
            url = f"{self.config.target_url.rstrip('/')}{attack_data['endpoint']}"
            
            # Add realistic Referer header with subtle flaws
            referer_headers = {}
            if random.random() < 0.7:  # 70% chance of having referer
                # Subtle flaw: referer patterns don't always make sense for the endpoint
                possible_referers = [
                    f"{self.config.target_url}/",  # From homepage
                    f"{self.config.target_url}/search",  # From search page
                    "https://www.google.com/",  # From Google
                    "https://www.bing.com/",  # From Bing
                    f"{self.config.target_url}/login.html",  # From login
                ]
                # Subtle flaw: sometimes referer doesn't match the navigation flow
                referer_headers['Referer'] = random.choice(possible_referers)

            request_kwargs = {
                'params': attack_data['params'],
                'cookies': attack_data['cookies'],
                'timeout': 10,
                'headers': {
                    'X-Forwarded-For': self.bot_ip,
                    **referer_headers
                }
            }
            

            if attack_data['method'] == 'POST' and 'data' in attack_data:
                response = self.session.post(url, data=attack_data['data'], **request_kwargs)
            else:
                response = self.session.get(url, **request_kwargs)
            

            if '_reset_headers' in attack_data:
                self.session.headers = attack_data['_reset_headers']
            
            self.requests_made += 1
            
            logger.info(f"Attack request {self.requests_made}: {response.status_code} "
                       f"{attack_data['endpoint']} ({self.config.attack_type})")
            
            return response.status_code < 500
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Attack request failed: {e}")
            return True
    
    def run_attack(self):
        """Run the attack for the specified duration with human-like timing"""
        logger.info(f"Starting {self.config.attack_type} attack from IP {self.config.attack_ip}")
        logger.info(f"Target: {self.config.target_url}")
        logger.info(f"Rate: {self.config.request_rate} req/s for {self.config.attack_duration}s")
        
        while time.time() - self.attack_start < self.config.attack_duration:
            success = self.make_attack_request()
            
            if not success:
                logger.warning("Attack request failed, continuing...")
            
            # Human-like timing with subtle flaws
            delay = self._get_human_like_delay_with_flaws()
            
            # Occasional longer breaks (like humans do)
            if random.random() < 0.05:  # 5% chance
                break_time = random.uniform(5, 30)  # 5-30 second break
                logger.info(f"Taking a {break_time:.1f}s break")
                time.sleep(break_time)
            
            time.sleep(delay)
        
        logger.info(f"Attack completed. Total requests made: {self.requests_made}")
    
    def _get_human_like_delay_with_flaws(self) -> float:
        """Generate human-like delays with subtle detectable patterns"""
        base_delay = 1.0 / self.config.request_rate
        
        # Subtle flaw: timing distribution is slightly off from true human behavior
        if self.config.attack_type == 'scraping':
            # Subtle flaw: too consistent in the "human" range
            delay = random.uniform(2.0, 8.0)  # Always in this range (too predictable)
        elif self.config.attack_type == 'credential_stuffing':
            # Subtle flaw: slightly too fast for manual login attempts
            delay = random.uniform(0.8, 3.0)  # Faster than human typing
        elif self.config.attack_type == 'ddos':
            # ADD: Sometimes go very fast to trigger rate limiting (30% of time)
            if random.random() < 0.3:
                delay = random.uniform(0.1, 0.5)  # Very fast to trigger WAF rate limit (30 req/5min)
            else:
                delay = base_delay + random.gauss(0, 0.5)  # Gaussian but centered on target rate
        else:
            # Subtle flaw: normal distribution instead of human-like long tail
            delay = random.gauss(4.0, 1.0)  # Too perfect normal distribution
        
        # Ensure minimum delay (but allow very fast for rate limiting)
        return max(0.1, delay)

@click.command()
@click.option('--target-url', required=True, help='Target URL for attack')
@click.option('--attack-type', 
              type=click.Choice(['scraping', 'credential_stuffing', 'ddos', 'parameter_tampering', 
                               'cookie_manipulation', 'header_anomaly']),
              default='scraping', help='Type of attack to simulate')
@click.option('--attack-ip', default='192.168.1.100', help='Source IP for attack (spoofed in headers)')
@click.option('--rate', default=5.0, help='Requests per second')
@click.option('--duration', default=600, help='Attack duration in seconds')
def main(target_url, attack_type, attack_ip, rate, duration):
    """Simulate various bot attack patterns"""
    config = AttackConfig(
        target_url=target_url,
        attack_ip=attack_ip,
        attack_duration=duration,
        request_rate=rate,
        attack_type=attack_type
    )
    
    attacker = BotAttacker(config)
    
    try:
        attacker.run_attack()
    except KeyboardInterrupt:
        logger.info("Attack interrupted by user")

if __name__ == '__main__':
    main()
