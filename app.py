"""Graphical user interface for the Feistel network demo application."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from feistel_cipher import FeedbackMode, decrypt_text, encrypt_text
from hybrid_crypto import (
    RSAKeyPair,
    generate_rsa_keypair,
    generate_secret_key,
    rsa_decrypt,
    rsa_encrypt,
)


class FeistelApp(tk.Tk):
    """Tkinter based GUI that exposes all features in a single window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Feistel Network Demo")
        self.resizable(False, False)

        self.secret_key_var = tk.StringVar()
        self.feedback_mode_var = tk.StringVar(value=FeedbackMode.NONE)
        self.plaintext_var = tk.StringVar()
        self.ciphertext_var = tk.StringVar()
        self.binary_output_var = tk.StringVar()
        self.rsa_modulus_var = tk.StringVar()
        self.rsa_public_var = tk.StringVar()
        self.rsa_private_var = tk.StringVar()
        self.rsa_cipher_var = tk.StringVar()

        self.rsa_keypair: RSAKeyPair | None = None

        self._build_widgets()
        self._generate_initial_key()

    # ------------------------------------------------------------------
    # GUI construction
    # ------------------------------------------------------------------

    def _build_widgets(self) -> None:
        """Create all frames and widgets."""

        padding = {"padx": 10, "pady": 5}

        key_frame = ttk.LabelFrame(self, text="Секретный ключ")
        key_frame.grid(row=0, column=0, sticky="ew", **padding)

        ttk.Label(key_frame, text="16-битный ключ:").grid(row=0, column=0, sticky="w")
        key_entry = ttk.Entry(key_frame, textvariable=self.secret_key_var, width=10)
        key_entry.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Button(key_frame, text="Сгенерировать", command=self._generate_secret_key).grid(
            row=0, column=2, padx=5
        )

        feedback_frame = ttk.LabelFrame(self, text="Режим обратной связи")
        feedback_frame.grid(row=1, column=0, sticky="ew", **padding)

        ttk.Radiobutton(
            feedback_frame,
            text="Без обратной связи",
            value=FeedbackMode.NONE,
            variable=self.feedback_mode_var,
        ).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            feedback_frame,
            text="XOR с предыдущим открытым блоком",
            value=FeedbackMode.PREVIOUS_PLAINTEXT,
            variable=self.feedback_mode_var,
        ).grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(
            feedback_frame,
            text="XOR с предыдущим шифроблоком",
            value=FeedbackMode.PREVIOUS_CIPHERTEXT,
            variable=self.feedback_mode_var,
        ).grid(row=2, column=0, sticky="w")

        crypto_frame = ttk.LabelFrame(self, text="Шифрование / Расшифровка")
        crypto_frame.grid(row=2, column=0, sticky="ew", **padding)

        ttk.Label(crypto_frame, text="Открытый текст:").grid(row=0, column=0, sticky="w")
        ttk.Entry(crypto_frame, textvariable=self.plaintext_var, width=60).grid(
            row=0, column=1, sticky="w"
        )

        ttk.Button(crypto_frame, text="Зашифровать", command=self._encrypt).grid(
            row=0, column=2, padx=5
        )

        ttk.Label(crypto_frame, text="Шифртекст (через пробел):").grid(row=1, column=0, sticky="w")
        ttk.Entry(crypto_frame, textvariable=self.ciphertext_var, width=60).grid(
            row=1, column=1, sticky="w"
        )

        ttk.Button(crypto_frame, text="Расшифровать", command=self._decrypt).grid(
            row=1, column=2, padx=5
        )

        ttk.Label(crypto_frame, text="Блоки в бинарном виде:").grid(row=2, column=0, sticky="w")
        ttk.Label(crypto_frame, textvariable=self.binary_output_var, wraplength=450).grid(
            row=2, column=1, columnspan=2, sticky="w"
        )

        rsa_frame = ttk.LabelFrame(self, text="Гибридная криптосистема (RSA)")
        rsa_frame.grid(row=3, column=0, sticky="ew", **padding)

        ttk.Button(rsa_frame, text="Сгенерировать RSA ключи", command=self._generate_rsa_keys).grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )

        ttk.Label(rsa_frame, text="Модуль n:").grid(row=1, column=0, sticky="w")
        ttk.Entry(rsa_frame, textvariable=self.rsa_modulus_var, width=70, state="readonly").grid(
            row=1, column=1, sticky="w"
        )

        ttk.Label(rsa_frame, text="Публичная экспонента e:").grid(row=2, column=0, sticky="w")
        ttk.Entry(rsa_frame, textvariable=self.rsa_public_var, width=30, state="readonly").grid(
            row=2, column=1, sticky="w"
        )

        ttk.Label(rsa_frame, text="Приватная экспонента d:").grid(row=3, column=0, sticky="w")
        ttk.Entry(rsa_frame, textvariable=self.rsa_private_var, width=30, state="readonly").grid(
            row=3, column=1, sticky="w"
        )

        ttk.Label(rsa_frame, text="Зашифрованный ключ:").grid(row=4, column=0, sticky="w")
        ttk.Entry(rsa_frame, textvariable=self.rsa_cipher_var, width=70).grid(
            row=4, column=1, sticky="w"
        )

        actions_frame = ttk.Frame(rsa_frame)
        actions_frame.grid(row=5, column=0, columnspan=2, sticky="w", pady=5)

        ttk.Button(actions_frame, text="Шифровать ключ", command=self._encrypt_secret_key).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(actions_frame, text="Расшифровать ключ", command=self._decrypt_secret_key).grid(
            row=0, column=1, padx=5
        )

    # ------------------------------------------------------------------
    # Secret key and RSA helpers
    # ------------------------------------------------------------------

    def _generate_initial_key(self) -> None:
        """Populate the key field when the application starts."""

        self._set_secret_key(generate_secret_key())

    def _generate_secret_key(self) -> None:
        """Generate and display a new random 16-bit key."""

        self._set_secret_key(generate_secret_key())
        messagebox.showinfo("Ключ обновлён", "Создан новый 16-битный ключ.")

    def _set_secret_key(self, value: int) -> None:
        """Display a key value as a decimal number."""

        self.secret_key_var.set(str(value))

    def _get_secret_key(self) -> int:
        """Read and validate the user supplied secret key."""

        raw = self.secret_key_var.get().strip()
        try:
            value = int(raw)
        except ValueError:
            raise ValueError("Ключ должен быть целым числом.")
        if not 0 <= value <= 0xFFFF:
            raise ValueError("Ключ обязан быть 16-битным (0..65535).")
        return value

    def _generate_rsa_keys(self) -> None:
        """Create a new RSA key pair and show its parameters."""

        self.rsa_keypair = generate_rsa_keypair()
        self.rsa_modulus_var.set(str(self.rsa_keypair.public.modulus))
        self.rsa_public_var.set(str(self.rsa_keypair.public.exponent))
        self.rsa_private_var.set(str(self.rsa_keypair.private.exponent))
        messagebox.showinfo("RSA", "Создана новая пара RSA ключей.")

    def _encrypt_secret_key(self) -> None:
        """Encrypt the Feistel secret key with the RSA public key."""

        if self.rsa_keypair is None:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте RSA ключи.")
            return

        try:
            secret_key = self._get_secret_key()
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        cipher_value = rsa_encrypt(secret_key, self.rsa_keypair.public)
        self.rsa_cipher_var.set(str(cipher_value))
        messagebox.showinfo("Готово", "Ключ зашифрован и готов к передаче.")

    def _decrypt_secret_key(self) -> None:
        """Decrypt the RSA encrypted secret key and load it into the field."""

        if self.rsa_keypair is None:
            messagebox.showerror("Ошибка", "Нет приватного ключа для расшифровки.")
            return

        raw = self.rsa_cipher_var.get().strip()
        if not raw:
            messagebox.showerror("Ошибка", "Введите шифртекст ключа.")
            return

        try:
            cipher_value = int(raw)
        except ValueError:
            messagebox.showerror("Ошибка", "Шифртекст ключа должен быть числом.")
            return

        try:
            secret_key = rsa_decrypt(cipher_value, self.rsa_keypair.private)
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        self._set_secret_key(secret_key)
        messagebox.showinfo("Готово", "Секретный ключ восстановлен.")

    # ------------------------------------------------------------------
    # Encryption / decryption logic
    # ------------------------------------------------------------------

    def _encrypt(self) -> None:
        """Encrypt the text and display all representations."""

        try:
            secret_key = self._get_secret_key()
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        text = self.plaintext_var.get()
        if not text:
            messagebox.showerror("Ошибка", "Введите открытый текст.")
            return

        result = encrypt_text(text, secret_key, self.feedback_mode_var.get())
        self.ciphertext_var.set(result.text)
        self.binary_output_var.set(
            " | ".join(result.binary_blocks)
            if result.binary_blocks
            else ""
        )
        messagebox.showinfo("Готово", "Текст зашифрован.")

    def _decrypt(self) -> None:
        """Decrypt the numeric cipher text back to plain text."""

        try:
            secret_key = self._get_secret_key()
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        cipher_text = self.ciphertext_var.get().strip()
        if not cipher_text:
            messagebox.showerror("Ошибка", "Введите шифртекст для расшифровки.")
            return

        try:
            result = decrypt_text(cipher_text, secret_key, self.feedback_mode_var.get())
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        self.plaintext_var.set(result.text)
        self.binary_output_var.set(
            " | ".join(result.binary_blocks)
            if result.binary_blocks
            else ""
        )
        messagebox.showinfo("Готово", "Шифртекст расшифрован.")


def main() -> None:
    """Entry point used by ``python app.py``."""

    app = FeistelApp()
    app.mainloop()


if __name__ == "__main__":  # pragma: no cover - manual testing helper
    main()

