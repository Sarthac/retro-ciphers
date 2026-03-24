"""Implemented different Monoalphabetic substitution ciphers.

This module contains Monoalphabetic cipher algorithms, every cipher algorithm produce different cipher_alphabets
that makes them unique from rest of them.
"""

__all__: list[str] = [
    "Atbash",
    "Shift",
    "Caesar",
    "Rot13",
    "MixedAlphabet",
    "SimpleSubstitution",
    "Baconian",
    "PolybiusSquare",
]

import random
import string
from typing import override

from .base import MonoalphabeticSubstitution


class Atbash(MonoalphabeticSubstitution):
    """cipher_alphabet is reverse of alphabet (z-a)."""

    def __init__(self):
        """Initialize super class and passes cipher_alphabet."""
        super().__init__(string.ascii_lowercase[::-1])


class Shift(MonoalphabeticSubstitution):
    """Produce cipher_alphabet based on user given shift."""

    def __init__(self, shift: int):
        """Initialize super class and passes cipher_alphabet by producing it with user-defined shift.

        Args:
            shift (int): User given shift in integer.
        """
        base: str = string.ascii_lowercase
        # The modulo ensures shifts larger than 26 wrap around safely
        self.shift: int = shift % len(base)
        # creating reverse alphabet (z-a)
        cipher_alphabet: str = base[self.shift :] + base[: self.shift]
        super().__init__(cipher_alphabet)

    def __repr__(self) -> str:
        """Use to recreate object.

        Returns:
            str: Prints class with user defined shift.
        """
        return f"{self.__class__.__name__}(shift={self.shift})"


class Caesar(Shift):
    """Simplest Monoalphabetic substitution cipher, uses fixed shift of 3."""

    def __init__(self):
        """Initialize super class and passes cipher_alphabet by producing it with fixed shift of 3."""
        super().__init__(shift=3)


class Rot13(Shift):
    """Uses fixed shift of 13."""

    def __init__(self):
        """Initialize super class and passes cipher_alphabet by producing it with fixed shift of 13."""
        super().__init__(shift=13)


class MixedAlphabet(MonoalphabeticSubstitution):
    """Generate a unique cipher_alphabet each time with different keyword."""

    def __init__(self, keyword: str) -> None:
        """Initialize super class and passes cipher_alphabet by producing it with user-defined keyword.

        The cipher alphabet is created by taking the unique letters(removing recurring letters) of the keyword,
        followed by the remaining letters of the alphabet in their ascending order.
        """
        # removing duplicate letter in the keyword to make the cipher_alphanet 26 chars
        self.keyword: str = "".join(filter(str.isalpha, keyword.lower()))
        # make keyword unique so the cipher alphanet does not include duplicates, and it should 26 exact
        clean_keyword: list[str] = list(dict.fromkeys(self.keyword))
        cipher_alphabet: list[str] = clean_keyword
        # append remaining characters in cipher_alphabet
        for letter in string.ascii_lowercase:
            if letter not in cipher_alphabet:
                cipher_alphabet.append(letter)

        super().__init__(cipher_alphabet)

    def __repr__(self) -> str:
        """Use to recreate object.

        Returns:
            str: Prints class with user defined keyword.
        """
        return f"{self.__class__.__name__}(keyword={self.keyword!r})"


class SimpleSubstitution(MonoalphabeticSubstitution):
    """One of the simplest substitution cipher.

    Sender and Receiver need to agree on exact mapping of plain_alphabet with cipher_alphabet. there is no algorithm or
    tool to generate cipher_alphabet on the parameter such a shift or key; both must memories the cipher_alphabet
    or write down.
    """

    # user need to know the cipher_alphabet as it is a key to cipher and decipher.
    # user provide one or generate one using a static method.
    def __init__(self, cipher_alphabet: str) -> None:
        """Uses provided cipher_alphabet to map with plain_alphabet.

        Args:
            cipher_alphabet (str): cipher_alphabet to use.
        """
        # removing duplicate character in cipher_alphabet and making sure it is exactly 26 OR check if the length is 26
        if (
            len(dict.fromkeys(c.lower() for c in cipher_alphabet)) != 26
            or len(cipher_alphabet) != 26
        ):
            raise ValueError(
                "cipher_alphabets must be unique and 26 char long OR generate one by "
                "executing 'SimpleSubstitution.generate_cipher_alphabet()'"
            )
        self.cipher_alphabet: str = cipher_alphabet
        super().__init__(self.cipher_alphabet)

    @staticmethod
    def generate_cipher_alphabet() -> str:
        """Generates a random cipher_alphabet.

        Returns:
            A string representing the random cipher alphabet.
        """
        return "".join(random.sample(string.ascii_lowercase, k=26))

    def __repr__(self) -> str:
        """Use to recreate object.

        Returns:
            str: Prints class with given cipher_alphabet.
        """
        return f"{self.__class__.__name__}(cipher_alphabet={self.cipher_alphabet!r})"


class Baconian(MonoalphabeticSubstitution):
    """A substitution cipher that uses a 5-character binary representation for each letter."""

    modern_baconian_cipher: list[str] = [
        "aaaaa",  # a
        "aaaab",  # b
        "aaaba",  # c
        "aaabb",  # d
        "aabaa",  # e
        "aabab",  # f
        "aabba",  # g
        "aabbb",  # h
        "abaaa",  # i
        "abaab",  # j
        "ababa",  # k
        "ababb",  # l
        "abbaa",  # m
        "abbab",  # n
        "abbba",  # o
        "abbbb",  # p
        "baaaa",  # q
        "baaab",  # r
        "baaba",  # s
        "baabb",  # t
        "babaa",  # u
        "babab",  # v
        "babba",  # w
        "babbb",  # x
        "bbaaa",  # y
        "bbaab",  # z
    ]

    classic_baconian_cipher: list[str] = [
        "aaaaa",  # A
        "aaaab",  # B
        "aaaba",  # C
        "aaabb",  # D
        "aabaa",  # E
        "aabab",  # F
        "aabba",  # G
        "aabbb",  # H
        "abaaa",  # I / J
        "abaaa",  # I / J
        "abaab",  # K
        "ababa",  # L
        "ababb",  # M
        "abbaa",  # N
        "abbab",  # O
        "abbba",  # P
        "abbbb",  # Q
        "baaaa",  # R
        "baaab",  # S
        "baaba",  # T
        "baabb",  # U / V
        "baabb",  # U / V
        "babaa",  # W
        "babab",  # X
        "babba",  # Y
        "babbb",  # Z
    ]

    def __init__(self, modern_implementation=True) -> None:
        """Initializes the Baconian cipher.

        Args:
            modern_implementation: Whether to use the modern or old implementation of the cipher.
        """
        self.modern_implementation: bool = modern_implementation
        self.cipher_alphabet: list[str] = (
            self.modern_baconian_cipher
            if self.modern_implementation
            else self.classic_baconian_cipher
        )
        super().__init__(self.cipher_alphabet)

    @override
    def decipher(self, text: str) -> str:
        """Decipher the given text.

        Make a bach of 5-characters, gather the value of it from map and append it in result.

        Args:
            text (str): text to decipher.

        Returns:
            str: plaintext / deciphered text.
        """
        plain_text = ""
        i = 0
        # setting up the cipher word length
        word_length = 5
        while i < len(text):
            if not text[i].isalpha():
                plain_text += text[i]
                i += 1
            else:
                # grabbing next five chars
                block: str = text[i : i + word_length]
                # look into dictionary to decipher to single char
                plain_text += self.reverse_mapping.get(block, block)
                # switch index to next five chars
                i += word_length
        return plain_text

    def __repr__(self) -> str:
        """Use to recreate object.

        Returns:
            str: Prints class with boolean value of modern_implementation.
        """
        return f"{self.__class__.__name__}(modern_implementation={self.modern_implementation})"


class PolybiusSquare(MonoalphabeticSubstitution):
    """A substitution cipher that uses a 5x5 grid to represent each letter.

    A Polybius Square is a 5x5 grid. 5 x 5 = 25 total coordinates (from "11" to "55").
    However, base_alphabet (the standard English alphabet) has 26 letters. Ancient Greeks and classic cryptographers
    solved this by making two letters share the exact same cell in the grid. Usually, 'I' and 'J' share a
    spot (though sometimes 'C' and 'K' share one).To fix this, we pass 26-item list where the coordinates
    for 'i' and 'j' are identical.
    """

    cipher_alphabets = [
        "11",
        "12",
        "13",
        "14",
        "15",
        "21",
        "22",
        "23",
        "24",
        "24",
        "25",
        "31",
        "32",
        "33",
        "34",
        "35",
        "41",
        "42",
        "43",
        "44",
        "45",
        "51",
        "52",
        "53",
        "54",
        "55",
    ]

    def __init__(self) -> None:
        """Initialize super class and passes cipher_alphabet."""
        super().__init__(self.cipher_alphabets)

    @override
    def decipher(self, text: str) -> str:
        """Decipher the given text.

        Make a bach of 2-characters, gather the value of it from map and append it in result.

        Args:
            text (str): text to decipher.

        Returns:
            str: plaintext / deciphered text.
        """
        plain_text = ""
        i = 0
        # setting up the cipher word length
        word_length = 2
        while i < len(text):
            if not text[i].isnumeric():
                plain_text += text[i]
                i += 1
            else:
                # grabbing next two chars
                block = text[i : i + word_length]
                # look into dictionary to decipher to single char
                plain_text += self.reverse_mapping.get(block, block)
                # switch index to next two chars
                i += word_length
        return plain_text
