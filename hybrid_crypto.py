"""Hybrid cryptosystem helpers.

The Feistel network uses a 16-bit symmetric key.  In order to exchange this
key securely between two parties we employ a tiny RSA implementation.  The
implementation here is purely educational and intentionally compact; it
generates reasonably sized primes and uses the well known ``65537`` value as
the public exponent.
"""

from __future__ import annotations

import json
import math
import secrets
from dataclasses import dataclass
from typing import Tuple


SECRET_KEY_BITS = 16
RSA_DEFAULT_SIZE = 256  # Number of bits in each RSA prime (overall modulus ~512 bits)
PUBLIC_EXPONENT = 65537


def generate_secret_key() -> int:
    """Create a random 16-bit key for the Feistel cipher."""

    # ``secrets`` provides cryptographically strong randomness.
    return secrets.randbelow(1 << SECRET_KEY_BITS)


@dataclass
class RSAPublicKey:
    """Minimal representation of an RSA public key."""

    modulus: int
    exponent: int = PUBLIC_EXPONENT


@dataclass
class RSAPrivateKey:
    """Minimal representation of an RSA private key."""

    modulus: int
    exponent: int


@dataclass
class RSAKeyPair:
    """Container that keeps both the public and private RSA key."""

    public: RSAPublicKey
    private: RSAPrivateKey


def export_rsa_public_key(key: RSAPublicKey) -> str:
    """Вернуть публичный ключ RSA в виде JSON-строки."""

    # Используем строки для модуля, чтобы избежать переполнения при обмене.
    payload = {"modulus": str(key.modulus), "exponent": str(key.exponent)}
    return json.dumps(payload, ensure_ascii=False)


def export_rsa_private_key(key: RSAPrivateKey) -> str:
    """Вернуть приватный ключ RSA в виде JSON-строки."""

    payload = {"modulus": str(key.modulus), "exponent": str(key.exponent)}
    return json.dumps(payload, ensure_ascii=False)


def import_rsa_public_key(data: str) -> RSAPublicKey:
    """Восстановить публичный ключ RSA из текстового представления."""

    try:
        payload = json.loads(data)
    except json.JSONDecodeError as error:
        raise ValueError("Не удалось прочитать публичный ключ.") from error

    try:
        modulus = int(payload["modulus"])
        exponent = int(payload.get("exponent", PUBLIC_EXPONENT))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Некорректный формат публичного ключа.") from error

    return RSAPublicKey(modulus=modulus, exponent=exponent)


def import_rsa_private_key(data: str) -> RSAPrivateKey:
    """Восстановить приватный ключ RSA из текстового представления."""

    try:
        payload = json.loads(data)
    except json.JSONDecodeError as error:
        raise ValueError("Не удалось прочитать приватный ключ.") from error

    try:
        modulus = int(payload["modulus"])
        exponent = int(payload["exponent"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Некорректный формат приватного ключа.") from error

    return RSAPrivateKey(modulus=modulus, exponent=exponent)


def generate_rsa_keypair(prime_bits: int = RSA_DEFAULT_SIZE) -> RSAKeyPair:
    """Generate an RSA key pair with primes of approximately ``prime_bits`` bits."""

    p = _generate_prime(prime_bits)
    q = _generate_prime(prime_bits)
    while p == q:
        q = _generate_prime(prime_bits)

    modulus = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(PUBLIC_EXPONENT, phi) != 1:
        # Extremely rare, but if it happens start over.
        return generate_rsa_keypair(prime_bits)

    private_exponent = _mod_inverse(PUBLIC_EXPONENT, phi)
    return RSAKeyPair(
        public=RSAPublicKey(modulus=modulus),
        private=RSAPrivateKey(modulus=modulus, exponent=private_exponent),
    )


def rsa_encrypt(value: int, key: RSAPublicKey) -> int:
    """Encrypt ``value`` with the RSA public key."""

    if not 0 <= value < key.modulus:
        raise ValueError("Значение выходит за пределы модуля RSA.")
    return pow(value, key.exponent, key.modulus)


def rsa_decrypt(value: int, key: RSAPrivateKey) -> int:
    """Decrypt ``value`` with the RSA private key."""

    if not 0 <= value < key.modulus:
        raise ValueError("Значение выходит за пределы модуля RSA.")
    return pow(value, key.exponent, key.modulus)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_prime(bits: int) -> int:
    """Return a probable prime number with the requested number of bits."""

    while True:
        candidate = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if _is_probable_prime(candidate):
            return candidate


def _is_probable_prime(n: int, rounds: int = 10) -> bool:
    """Perform a Miller–Rabin probabilistic primality test."""

    if n in (2, 3):
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Represent n - 1 as 2^s * d where d is odd.
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # 2 <= a <= n - 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _mod_inverse(value: int, modulus: int) -> int:
    """Compute modular inverse using the extended Euclidean algorithm."""

    g, x, _ = _extended_gcd(value, modulus)
    if g != 1:
        raise ValueError("Взаимно обратного элемента не существует.")
    return x % modulus


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm."""

    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = _extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

