"""Модуль с реализацией сети Фейстеля и вспомогательных операций.

Все функции снабжены подробными комментариями на русском языке, так как
требуется максимально прозрачное описание алгоритмов.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


# Алфавит, поддерживающий русский язык, цифры и базовые знаки препинания.
# Алфавит задаёт порядок символов для построения биграмм и их перевод в
# десятичную, а затем и двоичную системы счисления.
ALPHABET: str = (
    "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " .,!?-:\"'()"
)

# Символ, применяемый для дополнения текста до чётной длины при построении
# биграмм. Выбран пробел, чтобы при восстановлении сообщения дополняющий
# символ не выглядел подозрительно.
PADDING_SYMBOL: str = " "


@dataclass
class PreparedText:
    """Структура с результатами подготовки текста.

    Attributes:
        binary_blocks: Список 16-битных двоичных строк, соответствующих
            биграммам исходного текста.
        original_length: Количество символов в исходном тексте до
            возможного добавления символа дополнения.
    """

    binary_blocks: List[str]
    original_length: int


def _validate_symbol(symbol: str) -> None:
    """Проверяет, что символ присутствует в алфавите.

    Args:
        symbol: Символ, который нужно проверить.

    Raises:
        ValueError: Если символ отсутствует в алфавите и, следовательно,
            не может быть корректно закодирован.
    """

    if symbol not in ALPHABET:
        raise ValueError(
            f"Символ '{symbol}' отсутствует в поддерживаемом алфавите. "
            "Допустимые символы: "
            f"{ALPHABET}"
        )


def prepare_plaintext(plaintext: str) -> PreparedText:
    """Преобразует открытый текст в последовательность 16-битных блоков.

    Подготовка выполняется в несколько шагов: все символы проверяются на
    принадлежность алфавиту, далее текст делится на биграммы (по два
    символа). Каждая биграмма преобразуется в десятичное число, а затем в
    16-битное двоичное представление.

    Args:
        plaintext: Строка открытого текста.

    Returns:
        PreparedText: Список 16-битных двоичных строк и длина исходного
        текста (без учёта добавленного символа дополнения).
    """

    sanitized_text = plaintext.upper()
    processed_symbols: List[str] = []

    for symbol in sanitized_text:
        if symbol == "\n":
            # Перевод строки не всегда удобен при кодировании, поэтому
            # заменяем его на пробел, который есть в алфавите.
            symbol = " "
        _validate_symbol(symbol)
        processed_symbols.append(symbol)

    original_length = len(processed_symbols)

    # Если количество символов нечётное, добавляем символ дополнения,
    # чтобы биграммы образовывались корректно.
    if len(processed_symbols) % 2 != 0:
        processed_symbols.append(PADDING_SYMBOL)

    alphabet_size = len(ALPHABET)
    binary_blocks: List[str] = []

    for index in range(0, len(processed_symbols), 2):
        first = processed_symbols[index]
        second = processed_symbols[index + 1]
        first_position = ALPHABET.index(first)
        second_position = ALPHABET.index(second)

        # Значение биграммы в десятичной системе.
        decimal_value = first_position * alphabet_size + second_position
        # Преобразуем в 16-битное двоичное представление с ведущими нулями.
        binary_value = format(decimal_value, "016b")
        binary_blocks.append(binary_value)

    return PreparedText(binary_blocks=binary_blocks, original_length=original_length)


def restore_plaintext(blocks: List[str], original_length: int) -> str:
    """Преобразует список 16-битных блоков обратно в строку.

    Args:
        blocks: Список 16-битных строк, представляющих биграммы.
        original_length: Число символов в исходном тексте (без дополнения).

    Returns:
        str: Восстановленная строка открытого текста.
    """

    alphabet_size = len(ALPHABET)
    symbols: List[str] = []

    for block in blocks:
        decimal_value = int(block, 2)
        first_position, second_position = divmod(decimal_value, alphabet_size)
        symbols.extend([ALPHABET[first_position], ALPHABET[second_position]])

    # Обрезаем список до исходной длины, чтобы удалить возможное дополнение.
    trimmed_symbols = symbols[:original_length]
    return "".join(trimmed_symbols)


def left_rotate_bits(value: str, shift: int) -> str:
    """Выполняет циклический сдвиг двоичной строки влево.

    Args:
        value: Двоичная строка для сдвига.
        shift: Количество позиций сдвига.

    Returns:
        str: Результат циклического сдвига.
    """

    shift %= len(value)
    return value[shift:] + value[:shift]


def round_function(right_half: str, round_key: str) -> str:
    """Раундовая функция F для сети Фейстеля.

    Функция использует обе половины раундового ключа: первая половина
    участвует в операции XOR, вторая половина прибавляется по модулю 256.

    Args:
        right_half: Правая половина блока (8 бит).
        round_key: Раундовый ключ (16 бит).

    Returns:
        str: 8-битный результат функции F.
    """

    # Разделяем ключ на две части по 8 бит.
    left_key = round_key[:8]
    right_key = round_key[8:]

    right_value = int(right_half, 2)
    left_key_value = int(left_key, 2)
    right_key_value = int(right_key, 2)

    # Первый этап — XOR с левой частью ключа.
    mixed = right_value ^ left_key_value
    # Второй этап — сложение с правой частью ключа по модулю 256.
    transformed = (mixed + right_key_value) % 256

    return format(transformed, "08b")


def feistel_rounds(block: str, key: str) -> str:
    """Выполняет 8 раундов сети Фейстеля для одного блока.

    Args:
        block: 16-битный двоичный блок.
        key: 16-битный секретный ключ.

    Returns:
        str: Зашифрованный 16-битный блок.
    """

    left = block[:8]
    right = block[8:]

    for round_number in range(1, 9):
        round_key = left_rotate_bits(key, round_number)
        f_output = round_function(right, round_key)
        new_left = right
        new_right_value = int(left, 2) ^ int(f_output, 2)
        new_right = format(new_right_value, "08b")
        left, right = new_left, new_right

    # После восьмого раунда половины меняются местами, поэтому возвращаем
    # объединение последних значений left и right.
    return left + right


def feistel_inverse_rounds(block: str, key: str) -> str:
    """Выполняет обратные раунды сети Фейстеля для одного блока.

    Args:
        block: 16-битный зашифрованный блок.
        key: 16-битный секретный ключ.

    Returns:
        str: Расшифрованный 16-битный блок.
    """

    left = block[:8]
    right = block[8:]

    for round_number in range(8, 0, -1):
        round_key = left_rotate_bits(key, round_number)
        f_output = round_function(left, round_key)
        new_right = left
        new_left_value = int(right, 2) ^ int(f_output, 2)
        new_left = format(new_left_value, "08b")
        left, right = new_left, new_right

    return left + right


def xor_blocks(first: str, second: str) -> str:
    """Выполняет побитовое XOR двух 16-битных строк.

    Args:
        first: Первая 16-битная строка.
        second: Вторая 16-битная строка.

    Returns:
        str: Результат операции XOR.
    """

    value = int(first, 2) ^ int(second, 2)
    return format(value, "016b")


def encrypt_blocks(blocks: List[str], key: str) -> List[str]:
    """Шифрует список блоков с режимом обратной связи по шифртексту.

    Args:
        blocks: Список 16-битных блоков открытого текста.
        key: 16-битный секретный ключ в двоичном виде.

    Returns:
        List[str]: Список зашифрованных блоков.
    """

    encrypted: List[str] = []
    previous_cipher = "0" * 16

    for index, block in enumerate(blocks):
        block_to_encrypt = block
        if index > 0:
            block_to_encrypt = xor_blocks(block, previous_cipher)

        cipher_block = feistel_rounds(block_to_encrypt, key)
        encrypted.append(cipher_block)
        previous_cipher = cipher_block

    return encrypted


def decrypt_blocks(blocks: List[str], key: str) -> List[str]:
    """Расшифровывает список блоков с режимом обратной связи по шифртексту.

    Args:
        blocks: Список 16-битных блоков шифртекста.
        key: 16-битный секретный ключ в двоичном виде.

    Returns:
        List[str]: Список 16-битных блоков открытого текста.
    """

    decrypted: List[str] = []
    previous_cipher = "0" * 16

    for index, block in enumerate(blocks):
        decrypted_block = feistel_inverse_rounds(block, key)
        if index > 0:
            decrypted_block = xor_blocks(decrypted_block, previous_cipher)

        decrypted.append(decrypted_block)
        previous_cipher = block

    return decrypted


def ensure_16bit_key(key: str) -> str:
    """Проверяет и приводит ключ к 16-битной форме.

    Args:
        key: Строка, которая должна быть двоичным ключом.

    Returns:
        str: Нормализованный 16-битный ключ.

    Raises:
        ValueError: Если ключ не состоит из 0 и 1 или имеет неподходящую
            длину.
    """

    if not set(key) <= {"0", "1"}:
        raise ValueError("Ключ должен состоять только из символов '0' и '1'.")
    if len(key) != 16:
        raise ValueError("Ключ сети Фейстеля обязан быть длиной ровно 16 бит.")
    return key


def format_blocks(blocks: List[str]) -> str:
    """Возвращает удобочитаемое представление списка блоков.

    Args:
        blocks: Список 16-битных блоков.

    Returns:
        str: Строка, где блоки разделены пробелами.
    """

    return " ".join(blocks)


def parse_blocks(blocks_text: str) -> List[str]:
    """Разбирает строковое представление блоков в список.

    Args:
        blocks_text: Строка, содержащая блоки, разделённые пробелами или
            переводами строк.

    Returns:
        List[str]: Список 16-битных строк.
    """

    candidates = blocks_text.replace("\n", " ").split()
    blocks: List[str] = []
    for candidate in candidates:
        ensure_16bit_key(candidate)
        blocks.append(candidate)
    return blocks

