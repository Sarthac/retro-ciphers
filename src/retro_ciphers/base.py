"""Base classes for uniform the operations of Monoalphabetic substitution and  Polyalphabetic substitution.

This module contains abstract Substitution class that is a foundation of Monoalphabetic substitution and
Polyalphabetic substitution. These two substitutions cipher class implemented cipher and decipher method that
is used by most of ciphers algorithms without overriding it.
"""


import string
from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from itertools import cycle
from typing import override


class Substitution(ABC):
    """A foundation class for different substitution classes."""
    @abstractmethod
    def cipher(self, text: str) -> str:
        """Converts plaintext into ciphertext.

        Args:
            text (str): A plaintext string.

        Returns:
            str: A ciphertext string.
        """
        pass

    @abstractmethod
    def decipher(self, text: str) -> str:
        """Converts ciphertext into plaintext.

        Args:
            text (str): A ciphertext string.

        Returns:
            str: A plaintext / decipher string.
        """
        pass

    def __call__(self, text: str) -> str:
        """Allows the cipher object to call cipher method.

        Args:
            text (str): A plaintext string.

        Returns:
            str: A ciphertext string.
        """
        return self.cipher(text)


class MonoalphabeticSubstitution(Substitution):
    """A base class for creating Monoalphabetic substitution ciphers."""

    def __init__(self, cipher_alphabet: Sequence[str]) -> None:
        """Initializes a MonoalphabeticSubstitution object. and builds a map.

        Takes a unique lower-case-26-character alphabet sequence that must be produce and provide by each of
        the child class cipher algorithm then builds a map with provided unique alphabet with a-z 26-character.
        for upper-case, converts provided unique lower-case-26-character alphabet into upper-case and maps with
        A-Z 26-character.

        Args:
            cipher_alphabet (Sequence): A unique lower-case-26-character sequence.
        """
        # 1. Build the lowercase mapping
        lower_base : str = string.ascii_lowercase
        lower_cipher : list[str] = [char.lower() for char in cipher_alphabet]
        lower_map : dict[str, str] = dict(zip(lower_base, lower_cipher))

        # 2. Build the uppercase mapping
        upper_base : str = string.ascii_uppercase
        upper_cipher : list[str] = [char.upper() for char in cipher_alphabet]
        upper_map: dict[str, str] = dict(zip(upper_base, upper_cipher))

        # 3. Merge them into a single 52-pair dictionary!
        self.mapping: dict = lower_map | upper_map
        self.reverse_mapping: dict = {v: k for k, v in self.mapping.items()}

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        """Converts plaintext into ciphertext.

        Iterates through the plaintext character and get the appropriate value from map then append to result.
        Non-alphabetic characters are either preserved or stripped based on the provided flag.

        Args:
            text (str): A plaintext string.
            omit_non_alpha (bool, optional): Defaults to False, removes non-alphabet characters if set to True.

        Returns:
            str: A ciphertext string.
        """
        result: str = ""

        for char in text:
            if char.isalpha():
                # add char's value to result with respect to key-value pair
                result += self.mapping[char]
            # adds whitespace into results, and symbols if omit_non_alpha is False; removes it otherwise
            elif not omit_non_alpha or (char in string.whitespace):
                result += char

        return result

    @override
    def decipher(self, text: str) -> str:
        """Converts ciphertext into plaintext.

        Iterates through the ciphertext character and get the appropriate value from map then append to result.

        Args:
            text (str): A ciphertext string.

        Returns:
            str: A plaintext / decipher string.
                """
        return "".join(self.reverse_mapping.get(char, char) for char in text)

    def __str__(self) -> str:
        """Prints plain_alphabet and its respected cipher_alphabet.

        Returns:
            str: A plain_alphabet and its respected cipher_alphabet.
        """
        base: str = string.ascii_letters
        cipher_mapping: str = "".join(self.mapping.values())

        return (
            f"--- {self.__class__.__name__} Cipher ---\n"
            f"Plain:  {base}\n"
            f"Cipher: {cipher_mapping}\n"
        )

    def __eq__(self, other: object) -> bool:
        """Compares two objects with their cipher_alphabets.

        Useful in cipher algorithm such as MixedAlphabet, SimpleSubstitution, and Shift as their cipher_alphabet
        changes depending on parameter it passes that used in MixedAlphabet, Number(shift) provided in shift etc.

        If both of object's cipher_alphabet are same which means their Keyword, Number(Shift) are same.

        Not useful in cipher algorithms such as Caesar, Atbash, Rot13, Baconian, and PolybiusSquare as
        their ciphertext will be exact same because of their fixed mapping.

        Args:
            other (object): The other object.

        Returns:
            bool: True if the two objects are equal, False otherwise.
        """
        # checking if 'other' is the instance of this class
        if not isinstance(other, MonoalphabeticSubstitution):
            return NotImplemented
        # Two ciphers are equal if their cipher_alphabet dictionaries are exactly the same
        return self.mapping == other.mapping


class PolyalphabeticSubstitution(Substitution):
    """A base class for creating Polyalphabetic substitution ciphers."""

    def __init__(self, key: str):
        """Uses more than One shift to cipher each char.

        Args:
            key (str): The key use to build cipher table(tabula_recta).
        """
        # Call the generation method as a standard function
        self.tabula_recta : list[list[str]] = self._generate_table()
        if not key:
            raise ValueError("Key must not be empty.")
        self.key : str = key.upper()
        if not any(char.isalpha() for char in self.key):
            raise ValueError("Key must contain at least one letter.")

    def _generate_table(self) -> list[list[str]]:
        """Create a square table of alphabets (Vigenère by default).

        Returns:
            list[list[str]]: A two-dimensional square table of alphabet.
        """
        tabula_recta: list[list[str]] = []
        for i in range(26):
            tabula_recta.append(
                list(string.ascii_uppercase[i:] + string.ascii_uppercase[:i])
            )
        return tabula_recta

    def _get_key_sequence(self) -> list[int]:
        """Maps the keyword to a sequence of integer shifts.

        Extracts all alphabetic characters from the underlying key, converts
        them to uppercase, and maps them to a 0-25 integer range.

        Returns:
            list[int]: A list of shift values to be used by the cipher.

        Raises:
            ValueError: If the key contains no alphabetic characters.
        """
        clean_key : list[str] = [char.upper() for char in self.key if char.isalpha()]
        if not clean_key:
            raise ValueError("Key must contain at least one letter.")
        # convert chr into int, 0-25
        return [ord(char) - 65 for char in clean_key]

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        result: str = ""
        key_cycle : Iterator[int] = cycle(self._get_key_sequence())

        for char in text.upper():
            if char.isalpha():
                key_char : int = next(key_cycle)
                row : int = key_char
                # convert text_char to int then -65 as the ascii upper letters start at 65,
                # to get the index of the column.
                column : int = ord(char) - 65
                result += self.tabula_recta[row][column]

            elif not omit_non_alpha or (char in string.whitespace):
                result += char

        return result

    @override
    def decipher(self, text: str) -> str:
        result: str = ""
        key_cycle : Iterator[int] = cycle(self._get_key_sequence())

        for char in text.upper():
            if char.isalpha():
                key_char : int = next(key_cycle)
                column : int = self.tabula_recta[key_char].index(char)
                result += self.tabula_recta[0][column]
            else:
                result += char
        return result

    def __str__(self) -> str:
        """Prints cipher class name with key associated with it.

        Returns:
            str: Cipher class name and key.
        """
        key : str = self.key

        return f"--- {self.__class__.__name__} Cipher ---\n" f"Key:  {key!r}\n"

    def __repr__(self) -> str:
        """Use to recreate instance of cipher class.

        Returns:
            str: Class name with key associated with it.
        """
        return f"{self.__class__.__name__}(key={self.key!r})"
