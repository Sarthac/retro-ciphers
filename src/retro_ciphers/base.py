"""Base classes to unify monoalphabetic and polyalphabetic operations.

This module contains the abstract Substitution class, which serves as the
foundation for monoalphabetic and polyalphabetic substitutions. These two
substitution cipher classes implement the cipher and decipher methods used
by most cipher algorithms without requiring overrides.
"""

import string
from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from itertools import cycle
from typing import override


class Substitution(ABC):
    """A base class for different substitution cipher implementations."""

    @abstractmethod
    def cipher(self, text: str) -> str:
        """Converts plaintext into ciphertext.

        Args:
            text (str): The plaintext string to encrypt.

        Returns:
            str: The resulting ciphertext string.
        """
        pass

    @abstractmethod
    def decipher(self, text: str) -> str:
        """Converts ciphertext into plaintext.

        Args:
            text (str): The ciphertext string to decrypt.

        Returns:
            str: The resulting plaintext string.
        """
        pass

    def __call__(self, text: str) -> str:
        """Allows the cipher object to be called directly.

        Args:
            text (str): The plaintext string to encrypt.

        Returns:
            str: The resulting ciphertext string.
        """
        return self.cipher(text)


class MonoalphabeticSubstitution(Substitution):
    """A base class for creating monoalphabetic substitution ciphers."""

    def __init__(self, cipher_alphabet: Sequence[str]) -> None:
        """Initializes a MonoalphabeticSubstitution object and builds a map.

        Takes a unique 26-character lowercase alphabet sequence provided by a
        subclass algorithm and builds a mapping with the standard 'a-z'
        alphabet. For uppercase characters, it converts the sequence and maps
        it to 'A-Z'.

        Args:
            cipher_alphabet (Sequence[str]): A unique 26-character lowercase
                sequence.
        """
        # 1. Build the lowercase mapping
        lower_base: str = string.ascii_lowercase
        lower_cipher: list[str] = [char.lower() for char in cipher_alphabet]
        lower_map: dict[str, str] = dict(zip(lower_base, lower_cipher))

        # 2. Build the uppercase mapping
        upper_base: str = string.ascii_uppercase
        upper_cipher: list[str] = [char.upper() for char in cipher_alphabet]
        upper_map: dict[str, str] = dict(zip(upper_base, upper_cipher))

        # 3. Merge them into a single 52-pair dictionary!
        self.mapping: dict = lower_map | upper_map
        self.reverse_mapping: dict = {v: k for k, v in self.mapping.items()}

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        """Converts plaintext into ciphertext.

        Iterates through the plaintext characters, retrieves the mapped value,
        and appends it to the result. Non-alphabetic characters are either
        preserved or stripped based on the provided flag.

        Args:
            text (str): The plaintext string to encrypt.
            omit_non_alpha (bool): If True, non-alphabetic characters are
                removed. Defaults to False.

        Returns:
            str: The resulting ciphertext string.
        """
        result: str = ""

        for char in text:
            if char.isalpha():
                # add char's value to result with respect to key-value pair
                result += self.mapping[char]
            # adds whitespace into results, and symbols if omit_non_alpha
            # is False; removes it otherwise
            elif not omit_non_alpha or (char in string.whitespace):
                result += char

        return result

    @override
    def decipher(self, text: str) -> str:
        """Converts ciphertext into plaintext.

        Iterates through the ciphertext characters, retrieves the mapped value
        from the reverse map, and appends it to the result.

        Args:
            text (str): The ciphertext string to decrypt.

        Returns:
            str: The resulting plaintext string.
        """
        return "".join(self.reverse_mapping.get(char, char) for char in text)

    def __str__(self) -> str:
        """Returns the plaintext alphabet and its corresponding cipher alphabet.

        Returns:
            str: A string showing the plaintext and cipher alphabet mappings.
        """
        base: str = string.ascii_letters
        cipher_mapping: str = "".join(self.mapping.values())

        return (f"--- {self.__class__.__name__} Cipher ---"
                f"\nPlain:  {base}\nCipher: {cipher_mapping}\n")

    def __eq__(self, other: object) -> bool:
        """Compares two cipher objects based on their cipher alphabets.

        This is useful for algorithms like MixedAlphabet, SimpleSubstitution,
        and Shift, where the cipher alphabet depends on parameters like
        keywords or shift values. If both objects have the same cipher
        alphabet, they are considered equal.

        Note:
            This is less useful for algorithms with fixed mappings like
            Caesar, Atbash, Rot13, Baconian, and PolybiusSquare, as their
            mappings are always identical.

        Args:
            other (object): The object to compare with.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        # checking if 'other' is the instance of this class
        if not isinstance(other, MonoalphabeticSubstitution):
            return NotImplemented
        # Two ciphers are equal if their cipher_alphabet dictionaries are
        # exactly the same
        return self.mapping == other.mapping


class PolyalphabeticSubstitution(Substitution):
    """A base class for creating polyalphabetic substitution ciphers."""

    def __init__(self, key: str):
        """Initializes the cipher with a key for multiple shifts.

        Args:
            key (str): The key used to build the cipher table (tabula recta).
        """
        # Call the generation method as a standard function
        self.tabula_recta: list[list[str]] = self._generate_table()
        if not key:
            raise ValueError("Key must not be empty.")
        self.key: str = key.upper()
        if not any(char.isalpha() for char in self.key):
            raise ValueError("Key must contain at least one letter.")

    def _generate_table(self) -> list[list[str]]:
        """Creates a square table of alphabets (Vigenère by default).

        Returns:
            list[list[str]]: A 26x26 square table of alphabets.
        """
        tabula_recta: list[list[str]] = []
        for i in range(26):
            tabula_recta.append(
                list(string.ascii_uppercase[i:] + string.ascii_uppercase[:i])
            )
        return tabula_recta

    def _get_key_sequence(self) -> list[int]:
        """Maps the keyword to a sequence of integer shifts.

        Extracts all alphabetic characters from the key, converts them to
        uppercase, and maps them to a 0-25 integer range.

        Returns:
            list[int]: A list of shift values to be used by the cipher.

        Raises:
            ValueError: If the key contains no alphabetic characters.
        """
        clean_key: list[str] = [
            char.upper() for char in self.key if char.isalpha()
        ]
        if not clean_key:
            raise ValueError("Key must contain at least one letter.")
        # convert chr into int, 0-25
        return [ord(char) - 65 for char in clean_key]

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        """Encrypts text using a Vigenère table.

        The tabula recta is a 26x26 table where each row is shifted by one
        position. Encryption is performed by finding the intersection of the
        plaintext character's column and the key character's row.

        Args:
            text (str): The plaintext string to encrypt.
            omit_non_alpha (bool): If True, non-alphabetic characters are
                removed. Defaults to False.

        Returns:
            str: The resulting ciphertext string.
        """
        result: str = ""
        key_cycle: Iterator[int] = cycle(self._get_key_sequence())

        for char in text.upper():
            if char.isalpha():
                key_char: int = next(key_cycle)
                row: int = key_char
                # convert text_char to int then -65 as the ascii upper letters
                # start at 65,
                # to get the index of the column.
                column: int = ord(char) - 65
                result += self.tabula_recta[row][column]

            elif not omit_non_alpha or (char in string.whitespace):
                result += char

        return result

    @override
    def decipher(self, text: str) -> str:
        """Decrypts text using a Vigenère table.

        Decryption is performed by locating the key character's row in the
        tabula recta, finding the ciphertext character in that row, and
        retrieving the corresponding plaintext character from the first row.

        Example:
            Key = LEMON, Ciphertext = CIFFB
            Row 'L', find 'C' -> Column 'R'. Result: RETRO.

        Args:
            text (str): The ciphertext string to decrypt.

        Returns:
            str: The resulting plaintext string.
        """
        result: str = ""
        key_cycle: Iterator[int] = cycle(self._get_key_sequence())

        for char in text.upper():
            if char.isalpha():
                key_char: int = next(key_cycle)
                # get the char position in tabula_recta row
                column: int = self.tabula_recta[key_char].index(char)
                result += self.tabula_recta[0][column]
            else:
                result += char
        return result

    def __str__(self) -> str:
        """Returns the cipher class name and its associated key.

        Returns:
            str: A formatted string with the class name and key.
        """
        key: str = self.key

        return f"--- {self.__class__.__name__} Cipher ---\nKey:  {key!r}\n"

    def __repr__(self) -> str:
        """Returns a string representation to recreate the cipher object.

        Returns:
            str: A string that can be used to recreate the instance.
        """
        return f"{self.__class__.__name__}(key={self.key!r})"
