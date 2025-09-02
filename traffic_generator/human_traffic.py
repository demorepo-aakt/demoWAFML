#!/usr/bin/env python3
"""
Human Traffic Generator
Simulates realistic human web traffic using sine wave patterns
"""

import requests
import time
import numpy as np
import random
from faker import Faker
from datetime import datetime
import json
import threading
from typing import Dict, List
import logging
from dataclasses import dataclass
import click

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

fake = Faker()

@dataclass
class TrafficConfig:
    target_url: str
    base_frequency: float = 0.5
    amplitude: float = 0.3
    period: float = 300.0
    session_duration: int = 1800
    num_users: int = 10
    
class HumanUser:
    """Simulates a realistic human user session"""
    
    def __init__(self, user_id: int, config: TrafficConfig):
        self.user_id = user_id
        self.config = config
        self.session = requests.Session()
        self.profile = self._generate_user_profile()
        self.session_start = time.time()
        self.pages_visited = 0
        self.current_session_id = self._generate_realistic_session_id()
        

        self.session.headers.update({
            'User-Agent': self.profile['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': self.profile['accept_language'],
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Add X-Forwarded-For header occasionally (proxy/CDN simulation)
        if random.random() < 0.3:
            self.session.headers['X-Forwarded-For'] = self.profile['ip']
        
        # Add DNT header occasionally  
        if random.random() < 0.4:
            self.session.headers['DNT'] = '1'
        
    def _generate_user_profile(self) -> Dict:
        """Generate a realistic user profile with diverse characteristics"""
        browsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
        ]
        
        # Diverse languages and locales
        languages = [
            'en-US,en;q=0.9',
            'en-GB,en;q=0.9',
            'es-ES,es;q=0.9,en;q=0.8',
            'fr-FR,fr;q=0.9,en;q=0.8',
            'de-DE,de;q=0.9,en;q=0.8',
            'it-IT,it;q=0.9,en;q=0.8',
            'pt-BR,pt;q=0.9,en;q=0.8',
            'ja-JP,ja;q=0.9,en;q=0.8',
            'ko-KR,ko;q=0.9,en;q=0.8',
            'zh-CN,zh;q=0.9,en;q=0.8'
        ]
        
        # Extensive residential/proxy IP ranges by region and type
        ip_pools = {
            'us_residential': [
                '73.158.',      # Comcast residential East Coast
                '24.21.',       # Charter/Spectrum nationwide  
                '98.234.',      # AT&T residential
                '75.56.',       # Verizon FiOS
                '67.161.',      # Time Warner Cable
                '76.115.',      # Cox Communications
                '108.48.',      # Comcast business/residential
                '199.87.',      # Cable ISPs
                '72.182.',      # Road Runner/TWC
                '70.56.',       # CenturyLink/Qwest
                '68.173.',      # Various cable providers
                '174.109.',     # Regional ISPs
                '96.230.',      # Residential broadband
                '50.137.'       # Various residential
            ],
            'us_mobile': [
                '173.79.',      # T-Mobile
                '166.137.',     # Verizon Wireless
                '172.56.',      # AT&T Mobile
                '107.77.',      # Sprint/T-Mobile merged
                '198.228.',     # Various mobile carriers
                '162.177.',     # Mobile virtual operators
                '100.36.',      # T-Mobile network
                '155.138.'      # Mobile data
            ],
            'proxy_residential': [
                '185.92.',      # European residential proxies
                '45.134.',      # Various proxy providers
                '91.205.',      # European ISPs
                '31.173.',      # Netherlands residential
                '81.149.',      # UK residential
                '78.46.',       # German residential
                '151.80.',      # Italian residential
                '95.174.',      # Various European
                '88.99.',       # French residential
                '37.120.',      # European proxy services
                '46.161.',      # Scandinavian residential
                '89.38.'        # Eastern European
            ],
            'international': [
                '203.189.',     # Australia/Asia Pacific
                '210.140.',     # Japan/Korea
                '115.85.',      # China (legitimate)
                '122.162.',     # Various Asian countries
                '14.139.',      # India residential
                '180.76.',      # Various Asian ISPs
                '189.45.',      # Brazil
                '177.129.',     # South America
                '200.98.',      # Latin America
                '41.208.',      # Africa
                '102.130.',     # African ISPs
                '197.255.'      # More African ranges
            ]
        }
        
        # Select IP pool based on realistic distribution
        pool_choice = random.choices(
            ['us_residential', 'us_mobile', 'proxy_residential', 'international'],
            weights=[55, 25, 15, 5],  # Most traffic from US residential
            k=1
        )[0]
        
        selected_pool = ip_pools[pool_choice]
        ip_prefix = random.choice(selected_pool)
        
        # Generate full IP with two more octets
        ip = ip_prefix + f"{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        return {
            'name': fake.name(),
            'email': fake.email(),
            'ip': ip,
            'user_agent': random.choice(browsers),
            'accept_language': random.choice(languages),
            'interests': random.sample(['tech', 'news', 'shopping', 'entertainment', 'education'], 
                                     random.randint(1, 3)),
            'session_length_preference': random.uniform(5, 30),  # minutes
            'page_view_speed': random.uniform(3, 15),  # seconds between pages
            'ip_type': pool_choice,
            'cookie_preferences': {
                'analytics_enabled': random.choice([True, False]),
                'personalization': random.choice([True, False]),
                'session_length': random.choice([12, 16, 20, 24, 28, 32, 36, 40]),  # Wide variety
                'session_entropy': random.choice(['high', 'medium', 'low']),
                'tracking_protection': random.choice([True, False]),
                'cookie_complexity': random.choice(['simple', 'standard', 'complex']),
                'browser_fingerprint': random.choice(['chrome', 'firefox', 'safari', 'edge', 'mobile']),
                'privacy_level': random.choice(['high', 'medium', 'low'])
            }
        }
    
    def _get_sine_wave_frequency(self) -> float:
        """Calculate current request frequency based on sine wave"""
        current_time = time.time()
        elapsed = current_time - self.session_start
        

        frequency = (self.config.base_frequency + 
                    self.config.amplitude * np.sin(2 * np.pi * elapsed / self.config.period))
        

        return max(0.1, frequency)
    
    def _get_realistic_endpoint(self) -> str:
        """Get a realistic endpoint based on user behavior"""
        endpoints = [
            '/',
            '/api/data',
            '/search?q=' + fake.word(),
            '/login.html',
            '/api/stats',
            '/health',
        ]
        

        weights = [0.3, 0.2, 0.2, 0.1, 0.1, 0.1]
        return random.choices(endpoints, weights=weights)[0]
    
    def _add_realistic_params(self) -> Dict:
        """Add realistic request parameters"""
        params = {}
        

        if random.random() < 0.3:
            params['utm_source'] = random.choice(['google', 'facebook', 'twitter', 'direct'])
            params['utm_medium'] = random.choice(['organic', 'cpc', 'social', 'email'])
        

        if random.random() < 0.8:
            params['session_id'] = self.current_session_id
            
        return params
    
    def _generate_realistic_session_id(self) -> str:
        """Generate realistic human session ID with diverse patterns"""
        # Real browsers generate session IDs with high entropy and specific length patterns
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        
        # Use profile preference for session length
        if hasattr(self, 'profile') and 'cookie_preferences' in self.profile:
            length = self.profile['cookie_preferences']['session_length']
        else:
            length = random.choice([16, 20, 24, 32])  # Fallback
            
        return ''.join(random.choices(chars, k=length))
    
    def _get_realistic_cookies(self) -> Dict:
        """Generate sophisticated browser cookies based on user profile"""
        prefs = self.profile['cookie_preferences']
        cookies = {
            'session_id': self.current_session_id,
            'user_id': f"u_{random.randint(100000, 999999)}",
            'timezone': random.choice(['EST', 'PST', 'GMT', 'CET', 'JST', 'IST', 'CST', 'MST']),
            'last_visit': str(int(time.time() - random.randint(3600, 86400))),
        }
        
        # Browser-specific fingerprint cookies
        if prefs['browser_fingerprint'] == 'chrome':
            cookies['__cfduid'] = f"{random.randint(10**15, 10**16-1)}"
            cookies['_chrome_ver'] = random.choice(['120.0.0.0', '119.0.0.0', '118.0.0.0'])
        elif prefs['browser_fingerprint'] == 'firefox':
            cookies['__ff_session'] = f"ff_{random.randint(10**10, 10**11-1)}"
            cookies['_ff_ver'] = random.choice(['120.0', '119.0', '118.0'])
        elif prefs['browser_fingerprint'] == 'safari':
            cookies['__webkit_id'] = f"wk_{random.randint(10**8, 10**9-1)}"
            cookies['_safari_ver'] = random.choice(['17.1', '16.6', '16.5'])
        
        # Analytics cookies based on privacy level
        if prefs['analytics_enabled'] and prefs['privacy_level'] != 'high':
            if prefs['privacy_level'] == 'low':
                # Full tracking
                cookies.update({
                    '_ga': f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}",
                    '_gid': f"GA1.2.{random.randint(100000000, 999999999)}",
                    '_gat': '1',
                    '_fbp': f"fb.1.{int(time.time())}.{random.randint(100000000, 999999999)}",
                    '_gclid': f"Cj0KCQjw{random.choice(['A', 'B', 'C'])}{random.randint(1000, 9999)}"
                })
            else:  # medium privacy
                # Limited tracking
                cookies.update({
                    '_ga': f"GA1.2.{random.randint(100000000, 999999999)}.{int(time.time())}",
                    '_gid': f"GA1.2.{random.randint(100000000, 999999999)}"
                })
        
        # Personalization cookies based on complexity
        if prefs['personalization']:
            if prefs['cookie_complexity'] == 'complex':
                cookies.update({
                    'prefs': json.dumps({
                        'theme': random.choice(['dark', 'light', 'auto']),
                        'layout': random.choice(['grid', 'list', 'compact']),
                        'notifications': random.choice([True, False]),
                        'auto_play': random.choice([True, False])
                    }),
                    'lang': self.profile['accept_language'][:2],
                    'region': random.choice(['US', 'EU', 'APAC', 'CA', 'UK', 'AU']),
                    'currency': random.choice(['USD', 'EUR', 'GBP', 'CAD', 'AUD']),
                    'interests': ','.join(self.profile['interests'])
                })
            elif prefs['cookie_complexity'] == 'standard':
                cookies.update({
                    'prefs': random.choice(['dark', 'light', 'auto']),
                    'lang': self.profile['accept_language'][:2],
                    'region': random.choice(['US', 'EU', 'APAC', 'CA'])
                })
            else:  # simple
                cookies['theme'] = random.choice(['dark', 'light'])
        
        # Marketing cookies (affected by tracking protection)
        if not prefs['tracking_protection'] and random.random() < 0.7:
            cookies.update({
                'campaign': f"camp_{random.randint(1000, 9999)}",
                'source': random.choice(['google', 'facebook', 'twitter', 'direct', 'youtube', 'linkedin']),
                'medium': random.choice(['cpc', 'organic', 'social', 'email', 'referral']),
                'utm_term': random.choice(['bot-detection', 'security', 'waf', 'ml', 'ai'])
            })
        
        # CSRF and security tokens (more realistic)
        csrf_length = random.choice([32, 40, 64])
        cookies['csrf_token'] = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=csrf_length))
        
        # Shopping/e-commerce cookies (sometimes)
        if random.random() < 0.4:
            cookies.update({
                'cart_id': f"cart_{random.randint(10**6, 10**7-1)}",
                'wishlist': f"wl_{random.randint(1000, 9999)}",
                'viewed_products': ','.join([f"p{random.randint(100, 999)}" for _ in range(random.randint(1, 5))])
            })
        
        # A/B testing cookies
        if random.random() < 0.5:
            cookies.update({
                'ab_test_group': random.choice(['A', 'B', 'C', 'control']),
                'feature_flags': f"flag_{random.randint(1, 100)}"
            })
        
        return cookies
    
    def make_request(self) -> bool:
        """Make a single realistic HTTP request"""
        try:
            endpoint = self._get_realistic_endpoint()
            url = f"{self.config.target_url.rstrip('/')}{endpoint}"
            
            params = self._add_realistic_params()
            cookies = self._get_realistic_cookies()
            

            if endpoint.startswith('/api/'):
                headers = {'Accept': 'application/json'}
                if endpoint == '/api/data' and random.random() < 0.3:
                    response = self.session.post(url, 
                                               json={'query': fake.sentence()},
                                               params=params,
                                               cookies=cookies,
                                               headers=headers,
                                               timeout=10)
                else:
                    response = self.session.get(url, 
                                              params=params,
                                              cookies=cookies,
                                              headers=headers,
                                              timeout=10)
            else:
                response = self.session.get(url, 
                                          params=params,
                                          cookies=cookies,
                                          timeout=10)
            
            self.pages_visited += 1
            
            logger.info(f"User {self.user_id}: {response.status_code} {endpoint} "
                       f"({response.elapsed.total_seconds():.2f}s)")
            
            return response.status_code < 400
            
        except requests.exceptions.RequestException as e:
            logger.error(f"User {self.user_id} request failed: {e}")
            return False
    
    def run_session(self):
        """Run a complete user session"""
        logger.info(f"User {self.user_id} ({self.profile['name']}) starting session")
        
        while time.time() - self.session_start < self.config.session_duration:

            frequency = self._get_sine_wave_frequency()
            delay = 1.0 / frequency + random.uniform(-0.5, 0.5)
            delay = max(0.1, delay)
            

            self.make_request()
            

            time.sleep(delay)
            

            if random.random() < 0.1:
                break_time = random.uniform(10, 60)
                logger.info(f"User {self.user_id} taking a {break_time:.1f}s break")
                time.sleep(break_time)
        
        logger.info(f"User {self.user_id} session ended. Pages visited: {self.pages_visited}")

class TrafficGenerator:
    """Manages multiple human users generating traffic"""
    
    def __init__(self, config: TrafficConfig):
        self.config = config
        self.users = []
        self.threads = []
        self.running = False
        
    def start(self):
        """Start generating traffic with multiple concurrent users"""
        logger.info(f"Starting traffic generation with {self.config.num_users} users")
        logger.info(f"Target: {self.config.target_url}")
        logger.info(f"Base frequency: {self.config.base_frequency} req/s")
        logger.info(f"Sine wave period: {self.config.period}s ({self.config.period/60:.1f} min)")
        
        self.running = True
        

        for i in range(self.config.num_users):
            user = HumanUser(i + 1, self.config)
            self.users.append(user)
            
            thread = threading.Thread(target=user.run_session, daemon=True)
            thread.start()
            self.threads.append(thread)
            

            time.sleep(random.uniform(1, 5))
        

        for thread in self.threads:
            thread.join()
        
        logger.info("All user sessions completed")
    
    def stop(self):
        """Stop traffic generation"""
        self.running = False
        logger.info("Stopping traffic generation...")

@click.command()
@click.option('--target-url', required=True, help='Target URL for traffic generation')
@click.option('--users', default=10, help='Number of concurrent users')
@click.option('--frequency', default=0.5, help='Base requests per second')
@click.option('--amplitude', default=0.3, help='Sine wave amplitude')
@click.option('--period', default=300, help='Sine wave period in seconds')
@click.option('--duration', default=1800, help='Session duration in seconds')
def main(target_url, users, frequency, amplitude, period, duration):
    """Generate realistic human web traffic"""
    config = TrafficConfig(
        target_url=target_url,
        num_users=users,
        base_frequency=frequency,
        amplitude=amplitude,
        period=period,
        session_duration=duration
    )
    
    generator = TrafficGenerator(config)
    
    try:
        generator.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        generator.stop()

if __name__ == '__main__':
    main()
