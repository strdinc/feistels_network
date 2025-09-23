"""Функции экспорта и импорта данных гибридной криптосистемы."""

from __future__ import annotations

import io
import json
from typing import Dict, List


PACKAGE_VERSION = 1


def create_package(
    cipher_blocks: List[str],
    encrypted_key: int,
    rsa_modulus: int,
    original_length: int,
    metadata: Dict[str, str],
) -> Dict[str, object]:
    """Формирует словарь с данными для экспорта."""

    package = {
        "version": PACKAGE_VERSION,
        "cipher_blocks": cipher_blocks,
        "encrypted_key": str(encrypted_key),
        "rsa_modulus": str(rsa_modulus),
        "original_length": original_length,
        "metadata": metadata,
    }
    return package


def package_to_bytes(package: Dict[str, object]) -> bytes:
    """Сериализует пакет в байтовое представление JSON."""

    return json.dumps(package, ensure_ascii=False, indent=2).encode("utf-8")


def package_from_bytes(data: bytes) -> Dict[str, object]:
    """Читает пакет из JSON-представления."""

    package = json.loads(data.decode("utf-8"))
    required_keys = {
        "version",
        "cipher_blocks",
        "encrypted_key",
        "rsa_modulus",
        "original_length",
        "metadata",
    }
    if not required_keys.issubset(package.keys()):
        raise ValueError("Файл не похож на пакет гибридной системы.")
    package["cipher_blocks"] = [str(block) for block in package["cipher_blocks"]]
    package["encrypted_key"] = int(package["encrypted_key"])
    package["rsa_modulus"] = int(package["rsa_modulus"])
    package["original_length"] = int(package["original_length"])
    return package


def package_to_filelike(package: Dict[str, object]) -> io.BytesIO:
    """Создаёт объект BytesIO для скачивания пакета в браузере."""

    buffer = io.BytesIO()
    buffer.write(package_to_bytes(package))
    buffer.seek(0)
    return buffer

