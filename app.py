"""Веб-приложение Flask для демонстрации сети Фейстеля."""

from __future__ import annotations

import io
import json
import secrets
from typing import Dict

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
    ALPHABET,
    PADDING_SYMBOL,
    format_blocks,
    prepare_plaintext,
    restore_plaintext,
    encrypt_blocks,
    decrypt_blocks,
)
from rsa_utils import (
    decrypt as rsa_decrypt,
    deserialize_key,
    generate_key_pair,
    serialize_key,
    serialize_key_pair,
    encrypt as rsa_encrypt,
)


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


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
        if action == "download_keypair":
            return _handle_download_keypair()
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
            "public": serialize_key(key_pair.public_key),
            "private": serialize_key(key_pair.private_key),
            "pair": serialize_key_pair(key_pair),
        }
    }
    flash("Пара RSA-ключей успешно сгенерирована.", "success")
    return _render_index(**context)


def _handle_download_keypair() -> Response:
    """Возвращает файл с сохранённой парой ключей."""

    keypair_json = request.form.get("keypair_json")
    if not keypair_json:
        raise ValueError("Нет данных для выгрузки пары ключей.")

    buffer = io.BytesIO(keypair_json.encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/json",
        as_attachment=True,
        download_name="rsa_keypair.json",
    )


def _extract_public_key() -> Dict[str, int]:
    """Извлекает открытый ключ из формы (файл или текстовое поле)."""

    if "public_key_file" in request.files:
        uploaded_file = request.files.get("public_key_file")
        if uploaded_file and uploaded_file.filename:
            data = uploaded_file.read().decode("utf-8")
            return deserialize_key(data)

    public_key_text = request.form.get("public_key_text", "").strip()
    if public_key_text:
        return deserialize_key(public_key_text)

    raise ValueError(
        "Необходимо предоставить открытый ключ RSA (файл или текстовое поле)."
    )


def _handle_encrypt() -> Response:
    """Шифрует текст с помощью сети Фейстеля и RSA."""

    plaintext = request.form.get("plaintext", "")
    if not plaintext:
        raise ValueError("Введите текст для шифрования.")

    public_key = _extract_public_key()

    prepared = prepare_plaintext(plaintext)
    symmetric_key_int = secrets.randbits(16)
    symmetric_key_binary = format(symmetric_key_int, "016b")

    cipher_blocks = encrypt_blocks(prepared.binary_blocks, symmetric_key_binary)

    encrypted_key = rsa_encrypt(symmetric_key_int, public_key)

    metadata = {
        "alphabet": ALPHABET,
        "padding_symbol": PADDING_SYMBOL,
        "feedback_mode": "XOR с предыдущим шифроблоком",
        "rounds": "8",
    }

    package = create_package(
        cipher_blocks=cipher_blocks,
        encrypted_key=encrypted_key,
        rsa_modulus=public_key["n"],
        original_length=prepared.original_length,
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
            "original_length": prepared.original_length,
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
    private_key = deserialize_key(private_key_file.read().decode("utf-8"))

    if package["rsa_modulus"] != private_key["n"]:
        raise ValueError("Модуль RSA в пакете не совпадает с модулем ключа.")

    symmetric_key_int = rsa_decrypt(package["encrypted_key"], private_key)
    symmetric_key_binary = format(symmetric_key_int, "016b")

    plaintext_blocks = decrypt_blocks(package["cipher_blocks"], symmetric_key_binary)
    plaintext = restore_plaintext(plaintext_blocks, package["original_length"])

    context = {
        "decryption_result": {
            "plaintext": plaintext,
            "symmetric_key_binary": symmetric_key_binary,
            "cipher_blocks": format_blocks(package["cipher_blocks"]),
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

