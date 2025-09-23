"""Feistel cipher implementation with optional feedback modes.

This module contains the cryptographic core that is used by the GUI
application.  The implementation follows the requirements from the task:

* block size: 16 bits;
* number of rounds: 8 with numbering starting from 1;
* round keys are produced from the 16-bit master key using a circular
  left shift by the number of the round;
* right-hand XOR Feistel structure;
* processing is performed on binary data that is produced from the
  Unicode text by grouping characters into bigrams;
* additional feedback modes that mix in data from previous blocks.

The module exposes high level helpers that operate on text values so that
the GUI code stays compact and easier to read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


BIT_MASK_16 = 0xFFFF
BIT_MASK_8 = 0xFF
ROUNDS = 8


def rotate_left(value: int, shift: int, bit_width: int = 16) -> int:
    """Rotate ``value`` to the left by ``shift`` positions.

    Args:
        value: Integer value to rotate.
        shift: Number of positions to shift.  The shift may be greater than
            the bit width; in that case it wraps around automatically.
        bit_width: The amount of bits that are kept after the rotation.

    Returns:
        Rotated integer that still fits within ``bit_width`` bits.
    """

    shift %= bit_width
    mask = (1 << bit_width) - 1
    return ((value << shift) & mask) | (value >> (bit_width - shift))


def round_function(right_half: int, round_key: int) -> int:
    """Round function *F* used inside the Feistel network.

    The function intentionally mixes in the round key twice and performs a
    couple of inexpensive operations (XOR and bit rotations).  The result is
    constrained to 8 bits so that it can be XORed with the 8-bit left half.

    Args:
        right_half: Eight lower bits of the current Feistel state.
        round_key: Sixteen bit round key value.

    Returns:
        Eight bit integer that is combined with the left half of the block.
    """

    key_low = round_key & BIT_MASK_8
    key_high = (round_key >> 8) & BIT_MASK_8
    mix = right_half ^ key_low
    rotated = rotate_left(key_high | key_low, 3, 8)
    return (mix + rotated) & BIT_MASK_8


def generate_round_keys(master_key: int) -> List[int]:
    """Produce the sequence of round keys for the Feistel network.

    Args:
        master_key: 16-bit master key provided by the user.

    Returns:
        List with eight integers that correspond to the round keys.
    """

    keys = []
    for round_index in range(1, ROUNDS + 1):
        keys.append(rotate_left(master_key, round_index, 16))
    return keys


def _feistel_core(block: int, round_keys: Iterable[int], reverse: bool = False) -> int:
    """Shared part for encryption and decryption of a single block.

    Args:
        block: 16-bit block to transform.
        round_keys: Iterable with round keys in the order they should be
            consumed.
        reverse: When ``True`` the round sequence is reversed which is
            required for decryption.

    Returns:
        Transformed block (encrypted or decrypted depending on ``reverse``).
    """

    left = (block >> 8) & BIT_MASK_8
    right = block & BIT_MASK_8

    keys = list(round_keys)
    if reverse:
        keys = list(reversed(keys))

    for round_key in keys:
        f_value = round_function(right, round_key)
        new_left = right
        new_right = left ^ f_value
        left, right = new_left, new_right

    return ((left & BIT_MASK_8) << 8) | (right & BIT_MASK_8)


def encrypt_block(block: int, master_key: int) -> int:
    """Encrypt a 16-bit ``block`` using the provided ``master_key``."""

    return _feistel_core(block & BIT_MASK_16, generate_round_keys(master_key))


def decrypt_block(block: int, master_key: int) -> int:
    """Decrypt a 16-bit ``block`` using the provided ``master_key``."""

    return _feistel_core(block & BIT_MASK_16, generate_round_keys(master_key), reverse=True)


def _ensure_even_length(data: bytes) -> bytes:
    """Pad the byte string with a zero byte if the length is odd."""

    if len(data) % 2:
        return data + b"\x00"
    return data


def text_to_blocks(text: str) -> List[int]:
    """Convert text to 16-bit blocks using bigrams.

    The text is encoded to UTF-8 which supports the whole Unicode alphabet.
    After that the bytes are grouped into pairs (bigrams).  Each pair forms a
    single 16-bit block.  A zero byte is added if the input has an odd number
    of bytes.

    Args:
        text: Plain text value entered by the user.

    Returns:
        List of integers where each integer represents a 16-bit block.
    """

    encoded = _ensure_even_length(text.encode("utf-8"))
    blocks = []
    for index in range(0, len(encoded), 2):
        block = (encoded[index] << 8) | encoded[index + 1]
        blocks.append(block)
    return blocks


def blocks_to_text(blocks: Iterable[int]) -> str:
    """Assemble text from 16-bit ``blocks`` produced by :func:`text_to_blocks`."""

    raw = bytearray()
    for block in blocks:
        raw.append((block >> 8) & BIT_MASK_8)
        raw.append(block & BIT_MASK_8)
    try:
        return raw.rstrip(b"\x00").decode("utf-8")
    except UnicodeDecodeError:
        # As a fallback keep undecodable data visible.
        return raw.rstrip(b"\x00").decode("utf-8", errors="replace")


def blocks_to_binary_strings(blocks: Iterable[int]) -> List[str]:
    """Return blocks formatted as 16-bit binary strings."""

    return [format(block & BIT_MASK_16, "016b") for block in blocks]


class FeedbackMode:
    """Enumeration-like container with available feedback modes."""

    NONE = "none"
    PREVIOUS_PLAINTEXT = "plaintext"
    PREVIOUS_CIPHERTEXT = "ciphertext"


@dataclass
class CipherResult:
    """Container that keeps both numeric and textual representations."""

    blocks: List[int]
    binary_blocks: List[str]
    text: str


def encrypt_text(text: str, master_key: int, feedback_mode: str = FeedbackMode.NONE) -> CipherResult:
    """Encrypt ``text`` and return numeric as well as textual output.

    Args:
        text: Plain text message that will be encrypted.
        master_key: 16-bit key used as the input for the Feistel network.
        feedback_mode: Specifies how blocks are additionally combined.  Use
            values from :class:`FeedbackMode`.

    Returns:
        :class:`CipherResult` containing encrypted blocks.
    """

    plain_blocks = text_to_blocks(text)
    cipher_blocks = _process_blocks(plain_blocks, master_key, feedback_mode, encrypt=True)
    return CipherResult(
        blocks=cipher_blocks,
        binary_blocks=blocks_to_binary_strings(cipher_blocks),
        text=" ".join(map(str, cipher_blocks)),
    )


def decrypt_text(cipher_text: str, master_key: int, feedback_mode: str = FeedbackMode.NONE) -> CipherResult:
    """Decrypt numeric ``cipher_text`` produced by :func:`encrypt_text`.

    Args:
        cipher_text: Space separated string with encrypted 16-bit blocks.
        master_key: 16-bit master key used during encryption.
        feedback_mode: Feedback mode that was active during encryption.

    Returns:
        :class:`CipherResult` with restored plain text message.
    """

    cipher_blocks = _parse_blocks(cipher_text)
    plain_blocks = _process_blocks(cipher_blocks, master_key, feedback_mode, encrypt=False)
    return CipherResult(
        blocks=plain_blocks,
        binary_blocks=blocks_to_binary_strings(plain_blocks),
        text=blocks_to_text(plain_blocks),
    )


def _process_blocks(blocks: List[int], master_key: int, feedback_mode: str, encrypt: bool) -> List[int]:
    """Apply feedback mode and run Feistel transformations over the blocks."""

    processed: List[int] = []
    previous_plain: int | None = None
    previous_cipher: int | None = None

    for block in blocks:
        current = block
        if encrypt:
            if feedback_mode == FeedbackMode.PREVIOUS_PLAINTEXT and previous_plain is not None:
                current ^= previous_plain
            elif feedback_mode == FeedbackMode.PREVIOUS_CIPHERTEXT and previous_cipher is not None:
                current ^= previous_cipher
            result = encrypt_block(current, master_key)
            previous_plain = block
            previous_cipher = result
        else:
            result = decrypt_block(current, master_key)
            if feedback_mode == FeedbackMode.PREVIOUS_PLAINTEXT and previous_plain is not None:
                result ^= previous_plain
            elif feedback_mode == FeedbackMode.PREVIOUS_CIPHERTEXT and previous_cipher is not None:
                result ^= previous_cipher
            previous_plain = result
            previous_cipher = block

        processed.append(result & BIT_MASK_16)

    return processed


def _parse_blocks(raw: str) -> List[int]:
    """Parse a user provided string with numeric block values."""

    values: List[int] = []
    for item in raw.replace(",", " ").split():
        try:
            value = int(item)
        except ValueError as error:  # pragma: no cover - validation code for GUI
            raise ValueError(f"Не удалось разобрать блок '{item}'.") from error
        if not 0 <= value <= BIT_MASK_16:
            raise ValueError(f"Блок '{item}' выходит за границы 16-битного значения.")
        values.append(value)
    return values

