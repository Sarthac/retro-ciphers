from abc import ABC, abstractmethod
import string
from typing import override, Sequence


class Substitution(ABC):
    @abstractmethod
    def cipher(self, text: str) -> str:
        pass

    @abstractmethod
    def decipher(self, text: str) -> str:
        pass

    def __call__(self, text: str) -> str:
        """Allows the cipher object to be called directly to encrypt text."""
        return self.cipher(text)


class MonoalphabeticSubstitution(Substitution):
    """
    A base class for creating monoalphabetic substitution ciphers.
    """

    def __init__(self, cipher_alphabet: Sequence[str]):
        """
        Takes a 26-character sequence and automatically builds
        a dual-case mapping dictionary to preserve original formatting.
        """
        # 1. Build the lowercase mapping
        lower_base = string.ascii_lowercase
        lower_cipher = [char.lower() for char in cipher_alphabet]
        lower_map = dict(zip(lower_base, lower_cipher))

        # 2. Build the uppercase mapping
        upper_base = string.ascii_uppercase
        upper_cipher = [char.upper() for char in cipher_alphabet]
        upper_map = dict(zip(upper_base, upper_cipher))

        # 3. Merge them into a single 52-pair dictionary!
        self.mapping: dict = lower_map | upper_map
        self.reverse_mapping: dict = {v: k for k, v in self.mapping.items()}

    @override
    def cipher(self, text: str) -> str:
        return "".join(self.mapping.get(char, char) for char in text)

    @override
    def decipher(self, text: str) -> str:
        return "".join(self.reverse_mapping.get(char, char) for char in text)

    @override
    def __str__(self) -> str:
        base = string.ascii_letters
        cipher = "".join(self.mapping.values())

        return (
            f"--- {self.__class__.__name__} Cipher ---\n"
            f"Plain:  {base}\n"
            f"Cipher: {cipher}\n"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MonoalphabeticSubstitution):
            return NotImplemented
        # Two ciphers are equal if their cipher_alphabet dictionaries are exactly the same
        return self.mapping == other.mapping
