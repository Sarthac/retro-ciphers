from .base import MonoalphabeticSubstitution
import string
from typing import override
import random


"""
The following ciphers are implemented:
- MixedAlphabet: A substitution cipher with a mixed alphabet generated from a keyword.
- Atbash: A simple substitution cipher where the alphabet is reversed.
- SimpleSubstitution: A substitution cipher with a randomly generated or user-defined cipher alphabet.
- Rotate: A substitution cipher that rotates the alphabet by a given shift.
- Caesar: A specific instance of the Rotate cipher with a shift of 3.
- Rot13: A specific instance of the Rotate cipher with a shift of 13.
- Baconian: A substitution cipher that uses a 5-character binary representation for each letter.
- PolybiusSquare: A substitution cipher that uses a 5x5 grid to represent each letter.
"""


class Atbash(MonoalphabeticSubstitution):
    def __init__(self):
        super().__init__(string.ascii_lowercase[::-1])


class Shift(MonoalphabeticSubstitution):
    def __init__(self, shift: int):
        # The modulo ensures shifts larger than 26 wrap around safely
        base = string.ascii_lowercase
        self.shift = shift % len(base)
        cipher_alphabet: str = base[self.shift :] + base[: self.shift]
        super().__init__(cipher_alphabet)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(shift={self.shift})"


class Caesar(Shift):
    def __init__(self):
        super().__init__(shift=3)


class Rot13(Shift):
    def __init__(self):
        super().__init__(shift=13)


class MixedAlphabet(MonoalphabeticSubstitution):
    """
    A substitution cipher with a mixed alphabet generated from a keyword.

    The cipher alphabet is created by taking the unique letters of the keyword,
    followed by the remaining letters of the alphabet in their normal order.
    """

    def __init__(self, keyword: str) -> None:
        # removing duplicate letter in the keyword to make the cipher_alphanet 26 chars
        self.keyword = "".join(filter(str.isalpha, keyword.lower()))
        # make keyword unique so the cipher alphanet does not include dublicates and it should 26 exact
        clean_keyword = list(dict.fromkeys(self.keyword))
        cipher_alphabet = clean_keyword
        for letter in string.ascii_lowercase:
            if letter not in cipher_alphabet:
                cipher_alphabet.append(letter)

        super().__init__(cipher_alphabet)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(keyword={self.keyword!r})"


class SimpleSubstitution(MonoalphabeticSubstitution):
    """
    A substitution cipher with a randomly generated or user-defined cipher alphabet.
    """

    # user need to know the cipher_alphabet as it is a key to cipher and decipher.
    # user provide one or generate one using a static method.
    def __init__(self, cipher_alphabet: str) -> None:
        if (
            len(dict.fromkeys(c.lower() for c in cipher_alphabet)) != 26
            or len(cipher_alphabet) != 26
        ):
            raise ValueError(
                "cipher_alphabets must be unqiue and 26 char long OR generate one by executing 'SimpleSubstitution.generate_cipher_alphabet()'"
            )
        self.cipher_alphabet = cipher_alphabet
        super().__init__(self.cipher_alphabet)

    @staticmethod
    def generate_cipher_alphabet() -> str:
        """
        Generates a random cipher alphabet.

        Returns:
            A string representing the random cipher alphabet.
        """
        return "".join(random.sample(string.ascii_lowercase, k=26))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(cipher_alphabet={self.cipher_alphabet!r})"


class Baconian(MonoalphabeticSubstitution):
    """
    A substitution cipher that uses a 5-character binary representation for each letter.
    """

    modern_baconian_cipher = [
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

    classic_baconian_cipher = [
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
        """
        Initializes the Baconian cipher.

        Args:
            modern_implementation: Whether to use the modern or old implementation of the cipher.
        """
        self.modern_implementation = modern_implementation
        self.cipher_alphabet = (
            self.modern_baconian_cipher
            if self.modern_implementation
            else self.classic_baconian_cipher
        )
        super().__init__(self.cipher_alphabet)

    @override
    def decipher(self, text: str) -> str:
        plain_text = ""
        i = 0
        # setting up the cipher word lenth
        word_length = 5
        while i < len(text):
            if not text[i].isalpha():
                plain_text += text[i]
                i += 1
            else:
                # grabing next five chars
                block = text[i : i + word_length]
                # look into dictionary to decipher to single char
                plain_text += self.reverse_mapping.get(block, block)
                # switch index to next five chars
                i += word_length
        return plain_text

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(modern_implementation={self.modern_implementation})"


class PolybiusSquare(MonoalphabeticSubstitution):
    """
    A substitution cipher that uses a 5x5 grid to represent each letter.

    A Polybius Square is a 5x5 grid. 5 x 5 = 25 total coordinates (from "11" to "55").
    However, your self.base_alphabet (the standard English alphabet) has 26 letters.

    Ancient Greeks and classic cryptographers solved this by making two letters share the exact same cell in the grid. Usually, 'I' and 'J' share a spot (though sometimes 'C' and 'K' share one).

    To fix this in your code without having to rewrite your beautiful parent class, you just need to pass a 26-item list where the coordinates for 'i' and 'j' are identical.
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
        super().__init__(self.cipher_alphabets)

    @override
    def decipher(self, text: str) -> str:
        plain_text = ""
        i = 0
        # setting up the cipher word lenth
        word_length = 2
        while i < len(text):
            if not text[i].isnumeric():
                plain_text += text[i]
                i += 1
            else:
                # grabing next two chars
                block = text[i : i + word_length]
                # look into dictionary to decipher to single char
                plain_text += self.reverse_mapping.get(block, block)
                # switch index to next two chars
                i += word_length
        return plain_text
