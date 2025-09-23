"""Утилиты для работы с простейшей RSA-криптосистемой.

Модуль содержит функции генерации ключей, шифрования и расшифрования
коротких сообщений (в нашем случае — 16-битных симметричных ключей).
"""

from __future__ import annotations

import json
import math
import secrets
from dataclasses import dataclass
from typing import Dict


@dataclass
class RSAKeyPair:
    """Пара ключей RSA.

    Attributes:
        public_key: Словарь с полями ``n`` и ``e``.
        private_key: Словарь с полями ``n`` и ``d``.
    """

    public_key: Dict[str, int]
    private_key: Dict[str, int]


def _is_prime(candidate: int) -> bool:
    """Проверяет число на простоту методом перебора делителей."""

    if candidate < 2:
        return False
    if candidate in (2, 3):
        return True
    if candidate % 2 == 0:
        return False

    limit = int(math.sqrt(candidate)) + 1
    for divisor in range(3, limit, 2):
        if candidate % divisor == 0:
            return False
    return True


def _generate_prime(min_value: int = 2 ** 10, max_value: int = 2 ** 12) -> int:
    """Генерирует простое число в заданном диапазоне."""

    while True:
        candidate = secrets.randbelow(max_value - min_value) + min_value
        if _is_prime(candidate):
            return candidate


def _egcd(a: int, b: int):
    """Расширенный алгоритм Евклида для поиска НОД."""

    if a == 0:
        return b, 0, 1
    gcd_value, x1, y1 = _egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_value, x, y


def _mod_inverse(value: int, modulo: int) -> int:
    """Вычисляет мультипликативную обратную величину по модулю."""

    gcd_value, x, _ = _egcd(value, modulo)
    if gcd_value != 1:
        raise ValueError("Обратного элемента не существует.")
    return x % modulo


def generate_key_pair() -> RSAKeyPair:
    """Генерирует пару ключей RSA.

    Возвращаются сравнительно небольшие числа, достаточные для демонстрации
    гибридной криптосистемы, поскольку шифруется только 16-битный ключ.
    """

    p = _generate_prime()
    q = _generate_prime()
    while q == p:
        q = _generate_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    # Выбираем экспоненту e, взаимно простую с phi.
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    d = _mod_inverse(e, phi)

    public_key = {"n": n, "e": e}
    private_key = {"n": n, "d": d}
    return RSAKeyPair(public_key=public_key, private_key=private_key)


def encrypt(value: int, public_key: Dict[str, int]) -> int:
    """Шифрует целое число с помощью открытого ключа RSA."""

    n = public_key["n"]
    e = public_key["e"]
    if value >= n:
        raise ValueError(
            "Значение превышает модуль RSA. Используйте ключ большей длины."
        )
    return pow(value, e, n)


def decrypt(value: int, private_key: Dict[str, int]) -> int:
    """Расшифровывает целое число с помощью закрытого ключа RSA."""

    n = private_key["n"]
    d = private_key["d"]
    return pow(value, d, n)


def serialize_key(key: Dict[str, int]) -> str:
    """Сериализует ключ в JSON-строку."""

    return json.dumps(key, ensure_ascii=False, indent=2)


def serialize_key_pair(key_pair: RSAKeyPair) -> str:
    """Возвращает JSON-представление пары ключей."""

    return json.dumps(
        {
            "public_key": key_pair.public_key,
            "private_key": key_pair.private_key,
        },
        ensure_ascii=False,
        indent=2,
    )


def deserialize_key(json_text: str) -> Dict[str, int]:
    """Преобразует JSON-строку обратно в словарь с ключом."""

    data = json.loads(json_text)
    if not {"n"}.issubset(data.keys()):
        raise ValueError("Некорректный формат ключа: отсутствует модуль n.")
    return {key: int(value) for key, value in data.items()}


def deserialize_key_pair(json_text: str) -> RSAKeyPair:
    """Преобразует JSON-представление пары ключей в структуру RSAKeyPair."""

    data = json.loads(json_text)
    if "public_key" not in data or "private_key" not in data:
        raise ValueError("JSON должен содержать поля public_key и private_key.")
    public_key = deserialize_key(json.dumps(data["public_key"]))
    private_key = deserialize_key(json.dumps(data["private_key"]))
    return RSAKeyPair(public_key=public_key, private_key=private_key)

