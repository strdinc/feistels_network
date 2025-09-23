"""Graphical user interface for the Feistel network demo application."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from feistel_cipher import FeedbackMode, decrypt_text, encrypt_text
from hybrid_crypto import (
    RSAPrivateKey,
    RSAPublicKey,
    export_rsa_private_key,
    export_rsa_public_key,
    generate_rsa_keypair,
    generate_secret_key,
    import_rsa_private_key,
    import_rsa_public_key,
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

        self.rsa_public_key: RSAPublicKey | None = None
        self.rsa_private_key: RSAPrivateKey | None = None

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

        cipher_file_frame = ttk.Frame(crypto_frame)
        cipher_file_frame.grid(row=3, column=0, columnspan=3, sticky="w", pady=5)

        ttk.Button(cipher_file_frame, text="Импорт шифртекста", command=self._import_ciphertext).grid(
            row=0, column=0, padx=5
        )
        ttk.Button(cipher_file_frame, text="Экспорт шифртекста", command=self._export_ciphertext).grid(
            row=0, column=1, padx=5
        )

        rsa_frame = ttk.LabelFrame(self, text="Гибридная криптосистема (RSA)")
        rsa_frame.grid(row=3, column=0, sticky="ew", **padding)

        rsa_buttons = ttk.Frame(rsa_frame)
        rsa_buttons.grid(row=0, column=0, columnspan=2, sticky="w", pady=5)

        ttk.Button(rsa_buttons, text="Сгенерировать RSA ключи", command=self._generate_rsa_keys).grid(
            row=0, column=0, padx=5, pady=2, sticky="w"
        )
        ttk.Button(rsa_buttons, text="Импорт публичного ключа", command=self._import_public_key).grid(
            row=0, column=1, padx=5, pady=2, sticky="w"
        )
        ttk.Button(rsa_buttons, text="Импорт приватного ключа", command=self._import_private_key).grid(
            row=0, column=2, padx=5, pady=2, sticky="w"
        )
        ttk.Button(rsa_buttons, text="Экспорт публичного ключа", command=self._export_public_key).grid(
            row=1, column=0, padx=5, pady=2, sticky="w"
        )
        ttk.Button(rsa_buttons, text="Экспорт приватного ключа", command=self._export_private_key).grid(
            row=1, column=1, padx=5, pady=2, sticky="w"
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
        ttk.Button(actions_frame, text="Импорт шифртекста ключа", command=self._import_rsa_cipher).grid(
            row=1, column=0, padx=5, pady=(5, 0)
        )
        ttk.Button(actions_frame, text="Экспорт шифртекста ключа", command=self._export_rsa_cipher).grid(
            row=1, column=1, padx=5, pady=(5, 0)
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

    def _update_rsa_modulus_display(self) -> None:
        """Обновить поле с модулем RSA."""

        modulus: int | None = None
        if self.rsa_public_key is not None:
            modulus = self.rsa_public_key.modulus
        elif self.rsa_private_key is not None:
            modulus = self.rsa_private_key.modulus
        self.rsa_modulus_var.set(str(modulus) if modulus is not None else "")

    def _set_public_key(self, key: RSAPublicKey | None) -> None:
        """Сохранить публичный ключ и обновить интерфейс."""

        self.rsa_public_key = key
        self.rsa_public_var.set(str(key.exponent) if key else "")
        self._update_rsa_modulus_display()

    def _set_private_key(self, key: RSAPrivateKey | None) -> None:
        """Сохранить приватный ключ и обновить интерфейс."""

        self.rsa_private_key = key
        self.rsa_private_var.set(str(key.exponent) if key else "")
        self._update_rsa_modulus_display()

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

        keypair = generate_rsa_keypair()
        self._set_public_key(keypair.public)
        self._set_private_key(keypair.private)
        self.rsa_cipher_var.set("")
        messagebox.showinfo("RSA", "Создана новая пара RSA ключей.")

    def _import_public_key(self) -> None:
        """Загрузить публичный RSA ключ из файла."""

        path = filedialog.askopenfilename(
            title="Импорт публичного ключа",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = handle.read()
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {error}")
            return

        try:
            public_key = import_rsa_public_key(data)
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        if (
            self.rsa_private_key is not None
            and self.rsa_private_key.modulus != public_key.modulus
        ):
            messagebox.showerror(
                "Ошибка",
                "Модули публичного и приватного ключей не совпадают.",
            )
            return

        self._set_public_key(public_key)
        messagebox.showinfo("Готово", "Публичный ключ импортирован.")

    def _export_public_key(self) -> None:
        """Сохранить публичный RSA ключ в файл."""

        if self.rsa_public_key is None:
            messagebox.showerror("Ошибка", "Нет публичного ключа для экспорта.")
            return

        path = filedialog.asksaveasfilename(
            title="Экспорт публичного ключа",
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(export_rsa_public_key(self.rsa_public_key))
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {error}")
            return

        messagebox.showinfo("Готово", "Публичный ключ сохранён.")

    def _import_private_key(self) -> None:
        """Загрузить приватный RSA ключ из файла."""

        path = filedialog.askopenfilename(
            title="Импорт приватного ключа",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = handle.read()
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {error}")
            return

        try:
            private_key = import_rsa_private_key(data)
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        if (
            self.rsa_public_key is not None
            and self.rsa_public_key.modulus != private_key.modulus
        ):
            messagebox.showerror(
                "Ошибка",
                "Модули публичного и приватного ключей не совпадают.",
            )
            return

        self._set_private_key(private_key)
        self.rsa_cipher_var.set("")
        messagebox.showinfo("Готово", "Приватный ключ импортирован.")

    def _export_private_key(self) -> None:
        """Сохранить приватный RSA ключ в файл."""

        if self.rsa_private_key is None:
            messagebox.showerror("Ошибка", "Нет приватного ключа для экспорта.")
            return

        path = filedialog.asksaveasfilename(
            title="Экспорт приватного ключа",
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(export_rsa_private_key(self.rsa_private_key))
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {error}")
            return

        messagebox.showinfo("Готово", "Приватный ключ сохранён.")

    def _encrypt_secret_key(self) -> None:
        """Encrypt the Feistel secret key with the RSA public key."""

        if self.rsa_public_key is None:
            messagebox.showerror("Ошибка", "Нет публичного ключа для шифрования.")
            return

        try:
            secret_key = self._get_secret_key()
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        cipher_value = rsa_encrypt(secret_key, self.rsa_public_key)
        self.rsa_cipher_var.set(str(cipher_value))
        messagebox.showinfo("Готово", "Ключ зашифрован и готов к передаче.")

    def _decrypt_secret_key(self) -> None:
        """Decrypt the RSA encrypted secret key and load it into the field."""

        if self.rsa_private_key is None:
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
            secret_key = rsa_decrypt(cipher_value, self.rsa_private_key)
        except ValueError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        self._set_secret_key(secret_key)
        messagebox.showinfo("Готово", "Секретный ключ восстановлен.")

    # ------------------------------------------------------------------
    # Импорт/экспорт данных
    # ------------------------------------------------------------------

    def _import_rsa_cipher(self) -> None:
        """Загрузить шифртекст секретного ключа из файла."""

        path = filedialog.askopenfilename(
            title="Импорт шифртекста ключа",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {error}")
            return

        if not raw:
            messagebox.showerror("Ошибка", "Файл не содержит шифртекст.")
            return

        try:
            int(raw)
        except ValueError:
            messagebox.showerror("Ошибка", "В файле должен быть числовой шифртекст.")
            return

        self.rsa_cipher_var.set(raw)
        messagebox.showinfo("Готово", "Шифртекст ключа импортирован.")

    def _export_rsa_cipher(self) -> None:
        """Сохранить шифртекст секретного ключа в файл."""

        raw = self.rsa_cipher_var.get().strip()
        if not raw:
            messagebox.showerror("Ошибка", "Нет шифртекста для экспорта.")
            return

        try:
            int(raw)
        except ValueError:
            messagebox.showerror("Ошибка", "Шифртекст ключа должен быть числом.")
            return

        path = filedialog.asksaveasfilename(
            title="Экспорт шифртекста ключа",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(raw)
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {error}")
            return

        messagebox.showinfo("Готово", "Шифртекст ключа сохранён.")

    def _import_ciphertext(self) -> None:
        """Загрузить шифртекст сети Фейстеля из файла."""

        path = filedialog.askopenfilename(
            title="Импорт шифртекста",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = handle.read().strip()
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось прочитать файл: {error}")
            return

        if not data:
            messagebox.showerror("Ошибка", "Файл не содержит данных для импорта.")
            return

        self.ciphertext_var.set(data)
        messagebox.showinfo("Готово", "Шифртекст загружен.")

    def _export_ciphertext(self) -> None:
        """Сохранить шифртекст сети Фейстеля в файл."""

        data = self.ciphertext_var.get().strip()
        if not data:
            messagebox.showerror("Ошибка", "Нет шифртекста для экспорта.")
            return

        path = filedialog.asksaveasfilename(
            title="Экспорт шифртекста",
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(data)
        except OSError as error:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {error}")
            return

        messagebox.showinfo("Готово", "Шифртекст сохранён.")

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

