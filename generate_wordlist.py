import os  
import random
import re
import logging
import logging.handlers
import sys
import yaml
from pathlib import Path
import pickle
from datetime import datetime
from typing import List, Optional, Dict
from faker import Faker
import secrets
import colorama
from colorama import Fore, Style
import argparse
import asyncio
import aiofiles

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError as e:
    print(f"Missing required module: {e.name}. Please install it using 'pip install {e.name}'")
    HAS_NUMPY = False

colorama.init(autoreset=True)

Path("logs").mkdir(exist_ok=True)
handlers = [
    logging.handlers.RotatingFileHandler(
        f'logs/wordlist_generator_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
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

class WordlistGenerator:
    def __init__(self, config: Dict):
        self.config = config
        self.fake = Faker()
        self.min_length = config.get('min_password_length', 8)
        self.max_length = config.get('max_password_length', 16)
        self.min_complexity = config.get('min_password_complexity', 4)
        self.wordlist_size = config.get('wordlist_size', 100000)
        self.output_file = Path(config.get('output_file', 'Password-list.txt'))
        self.cache_file = Path(f"{self.output_file}.cache")
        self.mutator_patterns = [
            lambda p: p + str(random.randint(100, 999)),
            lambda p: p.capitalize() + '!',
            lambda p: p.replace('a', '@').replace('i', '1').replace('o', '0'),
            lambda p: p + str(datetime.now().year),
            lambda p: 'P@ss' + p,
            lambda p: p.lower() + '#',
            lambda p: ''.join(c.upper() if random.random() < 0.3 else c for c in p),
            lambda p: p + random.choice(['$', '%', '^', '&']),
            lambda p: ''.join(random.sample(p, len(p))),  # Shuffle characters
            lambda p: p[::-1] + '!'  # Reverse string
        ]
        self.common_words = [
            'password', 'admin', 'user', 'root', 'test', 'login', 'secure', 'access',
            'welcome', 'letmein', 'secret', 'pass', 'qwerty', 'dragon', 'monkey',
            'shadow', 'master', 'princess', 'football', 'baseball'
        ]
        self.special_chars = '!@#$%^&*(),.?":{}|<>'
        self.wordlist = []
        self.complexity_checks = [
            lambda p: len(p) >= self.min_length,
            lambda p: re.search(r"[A-Z]", p) is not None,
            lambda p: re.search(r"[a-z]", p) is not None,
            lambda p: re.search(r"[0-9]", p) is not None,
            lambda p: re.search(r"[!@#$%^&*(),.?\":{}|<>]", p) is not None
        ]

    def _is_strong_password(self, password: str) -> bool:
        score = sum(1 for check in self.complexity_checks if check(password))
        return score >= self.min_complexity and self.min_length <= len(password) <= self.max_length

    def _mutate_password(self, password: str) -> List[str]:
        mutants = [password]
        for mutator in self.mutator_patterns:
            try:
                mutated = mutator(password)
                if self.min_length <= len(mutated) <= self.max_length:
                    mutants.append(mutated)
            except Exception as e:
                logger.debug(f"Mutation failed for {password}: {e}")
        return list(set(mutants))

    async def _generate_base_passwords(self, count: int) -> List[str]:
        passwords = set()
        sources = [
            lambda: self.fake.password(length=random.randint(self.min_length, self.max_length)),
            lambda: self.fake.word().capitalize() + str(random.randint(100, 9999)),
            lambda: f"{self.fake.first_name()}{random.randint(100, 999)}",
            lambda: f"{self.fake.last_name().lower()}{random.choice(self.special_chars)}",
            lambda: random.choice(self.common_words) + str(random.randint(10, 99)),
            lambda: ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyz0123456789' + self.special_chars)
                           for _ in range(random.randint(self.min_length, self.max_length)))
        ]

        for _ in range(count):
            source = random.choice(sources)
            password = source()
            if self._is_strong_password(password):
                passwords.add(password)
        return list(passwords)

    async def generate_wordlist(self) -> List[str]:
        if self.cache_file.exists():
            try:
                async with aiofiles.open(self.cache_file, 'rb') as f:
                    content = await f.read()
                    self.wordlist = pickle.loads(content)
                    logger.info(f"Loaded {len(self.wordlist)} passwords from cache")
                    if len(self.wordlist) >= self.wordlist_size:
                        return self.wordlist[:self.wordlist_size]
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")

        base_count = max(1000, self.wordlist_size // 10)
        logger.info(f"Generating {base_count} base passwords...")
        base_passwords = await self._generate_base_passwords(base_count)

        logger.info("Applying mutations to base passwords...")
        for password in base_passwords:
            mutants = self._mutate_password(password)
            self.wordlist.extend([m for m in mutants if self._is_strong_password(m)])

        for _ in range(self.wordlist_size - len(self.wordlist)):
            base = random.choice(base_passwords)
            mutant = random.choice(self._mutate_password(base))
            if self._is_strong_password(mutant):
                self.wordlist.append(mutant)

        self.wordlist = list(set(self.wordlist))[:self.wordlist_size]

        try:
            async with aiofiles.open(self.cache_file, 'wb') as f:
                await f.write(pickle.dumps(self.wordlist))
            logger.info(f"Saved wordlist cache to {self.cache_file}")
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

        return self.wordlist

    async def export_wordlist(self):
        try:
            async with aiofiles.open(self.output_file, 'w', encoding='utf-8') as f:
                for password in self.wordlist:
                    await f.write(password + '\n')
            logger.info(f"Wordlist exported to {self.output_file} with {len(self.wordlist)} entries")
        except Exception as e:
            logger.error(f"Failed to export wordlist: {e}")

    def print_stats(self):
        lengths = [len(p) for p in self.wordlist]
        complexity_scores = [sum(1 for check in self.complexity_checks if check(p)) for p in self.wordlist]
        
        logger.info("\n" + "="*80)
        logger.info("WORDLIST GENERATION SUMMARY")
        logger.info("="*80)
        logger.info(f"Total passwords: {len(self.wordlist)}")
        
        avg_length = sum(lengths) / len(lengths) if lengths else 0
        avg_complexity = sum(complexity_scores) / len(complexity_scores) if complexity_scores else 0
        
        logger.info(f"Average password length: {avg_length:.2f} (min: {min(lengths) if lengths else 0}, max: {max(lengths) if lengths else 0})")
        logger.info(f"Average complexity score: {avg_complexity:.2f}")
        logger.info(f"Unique passwords: {len(set(self.wordlist))}")
        logger.info(f"Output file: {self.output_file}")

def load_config(config_file: str = "wordlist_config.yaml") -> Dict:
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning(f"Error reading config file: {e}, using defaults")
        config = {}

    defaults = {
        'min_password_length': 8,
        'max_password_length': 16,
        'min_password_complexity': 4,
        'wordlist_size': 100000,
        'output_file': 'Password-list.txt',
        'log_level': 'INFO'
    }
    config = {**defaults, **config}
    logging.getLogger().setLevel(config['log_level'])
    return config

def print_banner():
    print(f"""
{Fore.RED}[x] {Fore.WHITE}OPERATOR: {Fore.LIGHTBLACK_EX}[NoneR00tk1t]
{Fore.RED}[x] {Fore.WHITE}TEAM: {Fore.LIGHTBLACK_EX}[Valhala]
{Fore.LIGHTBLACK_EX}-------------------------------------
{Fore.RED}  ****           *   *   Wordlist Generator
{Fore.RED} *  *************  **   for SSH Brute Force
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

async def main():
    print_banner()
    config = load_config()

    parser = argparse.ArgumentParser(description="Advanced Wordlist Generator for SSH Brute Force")
    parser.add_argument("--min-length", type=int, default=config['min_password_length'],
                        help=f"Minimum password length (default: {config['min_password_length']})")
    parser.add_argument("--max-length", type=int, default=config['max_password_length'],
                        help=f"Maximum password length (default: {config['max_password_length']})")
    parser.add_argument("--size", type=int, default=config['wordlist_size'],
                        help=f"Number of passwords to generate (default: {config['wordlist_size']})")
    parser.add_argument("--output", default=config['output_file'],
                        help=f"Output file for wordlist (default: {config['output_file']})")
    parser.add_argument("--complexity", type=int, default=config['min_password_complexity'],
                        help=f"Minimum password complexity score (default: {config['min_password_complexity']})")
    
    args = parser.parse_args()
    
    config.update({
        'min_password_length': args.min_length,
        'max_password_length': args.max_length,
        'wordlist_size': args.size,
        'output_file': args.output,
        'min_password_complexity': args.complexity
    })

    generator = WordlistGenerator(config)
    
    try:
        logger.info("Starting wordlist generation...")
        await generator.generate_wordlist()
        await generator.export_wordlist()
        generator.print_stats()
    except KeyboardInterrupt:
        logger.info("Wordlist generation interrupted by user")
    except Exception as e:
        logger.error(f"Critical error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())