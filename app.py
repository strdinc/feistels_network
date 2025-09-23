"""Веб-приложение Flask для демонстрации сети Фейстеля."""

from __future__ import annotations

import io
import json
import secrets

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from data_io import create_package, package_from_bytes
from feistel import (
    ENCODING,
    PADDING_BYTE,
    decrypt_blocks_with_trace,
    encrypt_blocks_with_trace,
    format_blocks,
    prepare_plaintext_with_trace,
    restore_plaintext_with_trace,
)
from rsa_utils import (
    decrypt as rsa_decrypt,
    encrypt as rsa_encrypt,
    generate_key_pair,
    get_modulus,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
)


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


def _log_to_lines(log: str) -> list[str]:
    """Преобразует многострочный журнал в список непустых строк."""

    return [line.strip() for line in log.splitlines() if line.strip()]


def _normalize_section(lines: list[str]) -> dict[str, list[str]]:
    """Формирует словарь с заголовком и списком строк для группы журнала."""

    clean = [line.strip() for line in lines if line.strip()]
    if not clean:
        return {"title": "", "lines": []}

    if set(clean[0]) == {"="}:
        title = ""
        body = []
        for line in clean:
            if set(line) == {"="}:
                continue
            if not title:
                title = line
            else:
                body.append(line)
        return {"title": title, "lines": body}

    title, *body = clean
    return {"title": title, "lines": body}


def _log_to_sections(log: str) -> list[dict[str, list[str]]]:
    """Разбивает журнал на логические группы по пустым строкам."""

    sections = []
    buffer = []

    for line in log.splitlines():
        if line.strip():
            buffer.append(line)
            continue
        if buffer:
            sections.append(_normalize_section(buffer))
            buffer = []

    if buffer:
        sections.append(_normalize_section(buffer))

    return [section for section in sections if section["title"] or section["lines"]]


def _render_index(**context):
    """Выводит главную страницу с учётом переданного контекста."""

    return render_template("index.html", **context)


@app.route("/", methods=["GET", "POST"])
def index() -> Response:
    """Главная страница приложения.

    В зависимости от значения скрытого поля ``action`` выполняется одно из
    действий: генерация ключей, шифрование, расшифрование или экспорт данных.
    """

    if request.method == "GET":
        return _render_index()

    action = request.form.get("action")

    try:
        if action == "generate_keys":
            return _handle_generate_keys()
        if action == "download_public_key":
            return _handle_download_public_key()
        if action == "download_private_key":
            return _handle_download_private_key()
        if action == "encrypt":
            return _handle_encrypt()
        if action == "download_package":
            return _handle_download_package()
        if action == "decrypt":
            return _handle_decrypt()
        if action == "download_plaintext":
            return _handle_download_plaintext()
    except Exception as error:  # noqa: BLE001 - выводим пользователю текст ошибки
        flash(str(error), "error")
        return redirect(url_for("index"))

    flash("Неизвестное действие.", "error")
    return redirect(url_for("index"))


def _handle_generate_keys() -> Response:
    """Создаёт пару RSA-ключей и отображает их пользователю."""

    key_pair = generate_key_pair()
    context = {
        "generated_keys": {
            "public": serialize_public_key(key_pair.public_key),
            "private": serialize_private_key(key_pair.private_key),
            "modulus": str(get_modulus(key_pair.public_key)),
        }
    }
    flash("Пара RSA-ключей успешно сгенерирована.", "success")
    return _render_index(**context)


def _handle_download_public_key() -> Response:
    """Скачивание файла с открытым ключом."""

    public_pem = request.form.get("public_key_pem")
    if not public_pem:
        raise ValueError("Нет данных открытого ключа для скачивания.")

    buffer = io.BytesIO(public_pem.encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name="rsa_public_key.pem",
    )


def _handle_download_private_key() -> Response:
    """Скачивание файла с закрытым ключом."""

    private_pem = request.form.get("private_key_pem")
    if not private_pem:
        raise ValueError("Нет данных закрытого ключа для скачивания.")

    buffer = io.BytesIO(private_pem.encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name="rsa_private_key.pem",
    )


def _extract_public_key() -> RSAPublicKey:
    """Извлекает открытый ключ из формы (файл или текстовое поле)."""

    if "public_key_file" in request.files:
        uploaded_file = request.files.get("public_key_file")
        if uploaded_file and uploaded_file.filename:
            data = uploaded_file.read().decode("utf-8")
            return load_public_key(data)

    public_key_text = request.form.get("public_key_text", "").strip()
    if public_key_text:
        return load_public_key(public_key_text)

    raise ValueError(
        "Необходимо предоставить открытый ключ RSA (файл или текстовое поле)."
    )


def _build_rsa_encryption_log(
    *,
    public_key: RSAPublicKey,
    symmetric_key_binary: str,
    symmetric_key_bytes: bytes,
    encrypted_key: str,
) -> str:
    """Формирует журнал RSA-шифрования симметричного ключа."""

    lines = [
        "RSA-ШИФРОВАНИЕ СИММЕТРИЧНОГО КЛЮЧА",
        f"Модуль n: {get_modulus(public_key)}",
        f"Симметричный ключ (16 бит): {symmetric_key_binary}",
        f"Симметричный ключ (hex): 0x{symmetric_key_bytes.hex().upper()}",
        "Используется схема OAEP с SHA-256.",
        f"Зашифрованный ключ (base64): {encrypted_key}",
    ]
    return "\n".join(lines)


def _build_rsa_decryption_log(
    *,
    private_key: RSAPrivateKey,
    encrypted_key: str,
    symmetric_key_bytes: bytes,
    symmetric_key_binary: str,
) -> str:
    """Формирует журнал RSA-расшифрования симметричного ключа."""

    lines = [
        "RSA-РАСШИФРОВАНИЕ СИММЕТРИЧНОГО КЛЮЧА",
        f"Модуль n: {get_modulus(private_key)}",
        f"Входные данные (base64): {encrypted_key}",
        "Используется схема OAEP с SHA-256.",
        f"Результат в hex: 0x{symmetric_key_bytes.hex().upper()}",
        f"Результат в двоичном виде: {symmetric_key_binary}",
    ]
    return "\n".join(lines)


def _handle_encrypt() -> Response:
    """Шифрует текст с помощью сети Фейстеля и RSA."""

    plaintext = request.form.get("plaintext", "")
    if not plaintext:
        raise ValueError("Введите текст для шифрования.")

    public_key = _extract_public_key()

    prepared, preparation_log = prepare_plaintext_with_trace(plaintext)
    symmetric_key_int = secrets.randbits(16)
    symmetric_key_binary = format(symmetric_key_int, "016b")
    symmetric_key_bytes = symmetric_key_int.to_bytes(2, "big")

    cipher_blocks, encryption_log = encrypt_blocks_with_trace(
        prepared.binary_blocks, symmetric_key_binary
    )

    encrypted_key = rsa_encrypt(symmetric_key_bytes, public_key)
    rsa_log = _build_rsa_encryption_log(
        public_key=public_key,
        symmetric_key_binary=symmetric_key_binary,
        symmetric_key_bytes=symmetric_key_bytes,
        encrypted_key=encrypted_key,
    )

    metadata = {
        "encoding": ENCODING,
        "padding_byte": f"0x{PADDING_BYTE:02X}",
        "feedback_mode": "XOR с предыдущим шифроблоком",
        "rounds": "8",
        "rsa": "RSA-OAEP (SHA-256)",
    }

    package = create_package(
        cipher_blocks=cipher_blocks,
        encrypted_key=encrypted_key,
        rsa_modulus=get_modulus(public_key),
        original_byte_length=prepared.original_byte_length,
        metadata=metadata,
    )
    package_json = json.dumps(package, ensure_ascii=False, indent=2)

    context = {
        "encryption_result": {
            "cipher_blocks": cipher_blocks,
            "cipher_blocks_text": format_blocks(cipher_blocks),
            "package_json": package_json,
            "encrypted_key": str(encrypted_key),
            "symmetric_key_binary": symmetric_key_binary,
            "original_byte_length": prepared.original_byte_length,
            "preparation_log": preparation_log,
            "encryption_log": encryption_log,
            "rsa_log": rsa_log,
            "preparation_steps": _log_to_lines(preparation_log),
            "encryption_sections": _log_to_sections(encryption_log),
            "rsa_steps": _log_to_lines(rsa_log),
        }
    }

    flash("Сообщение зашифровано. Скачайте пакет для передачи.", "success")
    return _render_index(**context)


def _handle_download_package() -> Response:
    """Отдаёт пользователю файл с зашифрованным пакетом."""

    package_json = request.form.get("package_json")
    if not package_json:
        raise ValueError("Нет данных пакета для скачивания.")

    buffer = io.BytesIO(package_json.encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/json",
        as_attachment=True,
        download_name="feistel_package.json",
    )


def _handle_decrypt() -> Response:
    """Расшифровывает полученный пакет с использованием закрытого ключа."""

    package_file = request.files.get("package_file")
    private_key_file = request.files.get("private_key_file")

    if not package_file or not package_file.filename:
        raise ValueError("Необходимо выбрать файл зашифрованного пакета.")
    if not private_key_file or not private_key_file.filename:
        raise ValueError("Необходимо выбрать файл закрытого ключа.")

    package = package_from_bytes(package_file.read())
    private_key = load_private_key(private_key_file.read().decode("utf-8"))

    if package["rsa_modulus"] != get_modulus(private_key):
        raise ValueError("Модуль RSA в пакете не совпадает с модулем ключа.")

    symmetric_key_bytes = rsa_decrypt(package["encrypted_key"], private_key)
    symmetric_key_int = int.from_bytes(symmetric_key_bytes, "big")
    symmetric_key_binary = format(symmetric_key_int, "016b")

    plaintext_blocks, decryption_log = decrypt_blocks_with_trace(
        package["cipher_blocks"], symmetric_key_binary
    )
    plaintext, restoration_log = restore_plaintext_with_trace(
        plaintext_blocks, package["original_byte_length"]
    )
    rsa_log = _build_rsa_decryption_log(
        private_key=private_key,
        encrypted_key=package["encrypted_key"],
        symmetric_key_bytes=symmetric_key_bytes,
        symmetric_key_binary=symmetric_key_binary,
    )

    context = {
        "decryption_result": {
            "plaintext": plaintext,
            "symmetric_key_binary": symmetric_key_binary,
            "cipher_blocks": format_blocks(package["cipher_blocks"]),
            "cipher_blocks_list": package["cipher_blocks"],
            "decryption_log": decryption_log,
            "restoration_log": restoration_log,
            "rsa_log": rsa_log,
            "decryption_sections": _log_to_sections(decryption_log),
            "restoration_steps": _log_to_lines(restoration_log),
            "rsa_steps": _log_to_lines(rsa_log),
        }
    }

    flash("Пакет успешно расшифрован.", "success")
    return _render_index(**context)


def _handle_download_plaintext() -> Response:
    """Позволяет сохранить расшифрованный текст в виде файла."""

    plaintext = request.form.get("plaintext_data")
    if plaintext is None:
        raise ValueError("Нет текста для сохранения.")

    buffer = io.BytesIO(plaintext.encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="text/plain",
        as_attachment=True,
        download_name="feistel_plaintext.txt",
    )


if __name__ == "__main__":
    app.run(debug=True)

