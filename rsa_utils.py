"""Утилиты для работы с полноценной RSA-криптосистемой.

Модуль использует библиотеку :mod:`cryptography` для генерации ключей RSA
стандартного размера (по умолчанию 2048 бит), сериализации ключей в формате
PEM и шифрования/расшифрования симметричного 16-битного ключа с помощью OAEP.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)


@dataclass
class RSAKeyPair:
    """Пара RSA-ключей в формате объектов ``cryptography``."""

    public_key: RSAPublicKey
    private_key: RSAPrivateKey


def generate_key_pair(key_size: int = 2048) -> RSAKeyPair:
    """Генерирует пару RSA-ключей стандартного размера."""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return RSAKeyPair(public_key=public_key, private_key=private_key)


def serialize_public_key(key: RSAPublicKey) -> str:
    """Возвращает PEM-представление открытого ключа."""

    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def serialize_private_key(key: RSAPrivateKey) -> str:
    """Возвращает PEM-представление закрытого ключа (без пароля)."""

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def load_public_key(pem_text: str) -> RSAPublicKey:
    """Восстанавливает объект открытого ключа из PEM-строки."""

    return serialization.load_pem_public_key(pem_text.encode("utf-8"))


def load_private_key(pem_text: str) -> RSAPrivateKey:
    """Восстанавливает объект закрытого ключа из PEM-строки."""

    return serialization.load_pem_private_key(pem_text.encode("utf-8"), password=None)


def encrypt(data: bytes, public_key: RSAPublicKey) -> str:
    """Шифрует данные с помощью RSA-OAEP и возвращает результат в base64."""

    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64encode(ciphertext).decode("ascii")


def decrypt(token: str, private_key: RSAPrivateKey) -> bytes:
    """Расшифровывает base64-представление данных RSA-OAEP."""

    ciphertext = b64decode(token.encode("ascii"))
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def get_modulus(key: Union[RSAPublicKey, RSAPrivateKey]) -> int:
    """Возвращает модуль ``n`` из открытого или закрытого ключа."""

    if isinstance(key, RSAPrivateKey):
        return key.private_numbers().public_numbers.n
    return key.public_numbers().n

