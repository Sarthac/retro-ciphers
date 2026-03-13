from abc import ABC, abstractmethod
import string
from typing import override, Sequence
from itertools import cycle


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
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        result: str = ""

        for char in text:
            if char.isalpha():
                result += self.mapping[char]
            elif not omit_non_alpha or (char in string.whitespace):
                result += char

        return result

    @override
    def decipher(self, text: str) -> str:
        return "".join(self.reverse_mapping.get(char, char) for char in text)

    def __str__(self) -> str:
        base = string.ascii_letters
        cipher_mapping = "".join(self.mapping.values())

        return (
            f"--- {self.__class__.__name__} Cipher ---\n"
            f"Plain:  {base}\n"
            f"Cipher: {cipher_mapping}\n"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MonoalphabeticSubstitution):
            return NotImplemented
        # Two ciphers are equal if their cipher_alphabet dictionaries are exactly the same
        return self.mapping == other.mapping


class PolyalphabeticSubstitution(Substitution):
    def __init__(self, key: str):
        # Call the generation method as a standard function
        self.tabula_recta = self._generate_table()
        if not key:
            raise ValueError("Key must not be empty.")
        self.key = key.upper()
        if not any(char.isalpha() for char in self.key):
            raise ValueError("Key must contain at least one letter.")

    def _generate_table(self) -> list[list[str]]:
        """Create a square table of alphabets (Vigenère by default)."""
        tabula_recta: list[list[str]] = []
        for i in range(26):
            tabula_recta.append(
                list(string.ascii_uppercase[i:] + string.ascii_uppercase[:i])
            )
        return tabula_recta

    def _get_key_sequence(self) -> list[int]:
        """Maps the keyword to a sequence of shifts."""
        clean_key = [char.upper() for char in self.key if char.isalpha()]
        if not clean_key:
            raise ValueError("Key must contain at least one letter.")
        return [ord(char) - 65 for char in clean_key]

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        result: str = ""
        key_cycle = cycle(self._get_key_sequence())

        for char in text.upper():
            if char.isalpha():
                key_char = next(key_cycle)
                row = key_char
                # convert text_char to int then -65 as the ascii upper letters start at 65, to get the index of the column.
                column = ord(char) - 65
                result += self.tabula_recta[row][column]

            elif not omit_non_alpha or (char in string.whitespace):
                result += char

        return result

    @override
    def decipher(self, text: str) -> str:
        result: str = ""
        key_cycle = cycle(self._get_key_sequence())

        for char in text.upper():
            if char.isalpha():
                key_char = next(key_cycle)
                column = self.tabula_recta[key_char].index(char)
                result += self.tabula_recta[0][column]
            else:
                result += char
        return result

    def __str__(self) -> str:
        key = self.key

        return f"--- {self.__class__.__name__} Cipher ---\n" f"Key:  {key!r}\n"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(key={self.key!r})"
