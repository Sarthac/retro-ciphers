"""Polyalphabetic substitution ciphers uses multiple shift to produce cipher text.

Each cipher has different mechanism to utilize multiple shift.

The history of the Polyalphabetic substitution ciphers

        Alberti cipher
            ↓
        Trithemius cipher
            ↓
        Vigenere cipher
            ↓
        Beaufort cipher
            ↓
        Autokey cipher
"""

import random
import string
from collections.abc import Iterator
from itertools import cycle
from typing import override

from .base import PolyalphabeticSubstitution, Substitution


class Alberti(Substitution):
    """Uses a disk that has two disk, stack on each other to form one disk, that use to cipher text.

    1. Outer disk is Capital letters, not moveable
    2. Inner disk is small letters, moveable (possible to rotate)

    To cipher or decipher a text, both parties—the sender and receiver agree on the key that is respect to inner disk(smaller letter),

    In Alberti's original design, the Outer Disk is the Plaintext and the Inner Disk is the Ciphertext.


    1). How to Encrypt (Outer -> Inner)

    Because the outer disk represents your readable English, you always start looking there when encrypting.

    1.  Align: Map the inner 'g' to the outer 'D'.(here 'g' is the key, both sender and receiver need to know, 'D' is
        the outer disk only specify that the 'g' map to 'D', if receiver stumble upon next new capital letter, it is
        time to map the 'g' with new capital letter)
    2.  Signal: Write down 'D' in your ciphertext so the receiver knows the starting position.
    3.  Cipher: Look for your Plaintext letter on the Outer Disk. Find the letter directly below it on the Inner
        Disk and write that down.
    4.  Switch: Decide to change the key. Map inner 'g' to outer 'M'.
    5.  Signal & Cipher: Write down 'M' in your ciphertext, and then continue looking at the Outer Disk and writing
        down the new matching letters from the Inner Disk.

    2). How to Decrypt (Inner -> Outer)

    When you receive the scrambled message, you are looking at the ciphertext, so you have to read it in reverse.

    1.  Read the Signal: You see the first letter is 'D'.
    2.  Align: You map your inner 'g' to the outer 'D'.
    3.  Decipher: Look for the scrambled Ciphertext letter on the Inner Disk. Find the letter directly above it
        on the Outer Disk and write that down to reveal the plain English.
    4.  Read the Next Signal: You hit the letter 'M' in the ciphertext.
    5.  Switch & Decipher: You rotate your inner 'g' to the outer 'M', and continue finding the ciphertext on the
        Inner Disk and translating it to the Outer Disk.
    """

    def __init__(
        self, key: str, frequency: int = 50, modern_implementation: bool = True
    ):
        """Creates disk.

        Args:
            key (str): Initial key that must be a single character.
            frequency (int, optional): How often rotate a key, Defaults to 50; which mean every after 50 characters.
            modern_implementation (bool): Two implementation; takes boolean value, set to True to use modern; and
                False to use old implementation.
                1. modern: which include current English alphabet a-z.
                2. old : which includes old alphabets that includes 20 latin characters + 4 numbers (1-4).
                is for the historical purposes.

        Returns:
            str: A ciphertext string.
        """
        self.key: str = key
        self.frequency: int = frequency
        self.disk: dict[str, str] = {}
        self.modern_implementation: bool = modern_implementation

        if self.modern_implementation:
            # The Modern 26-Letter English Tool
            self.outer_disk_alphabets: str = string.ascii_uppercase
            self.inner_disk_alphabets: str = "qwertyuiopasdfghjklzxcvbnm"
        else:
            # The Historical 1467 Latin Replica
            self.outer_disk_alphabets: str = "ABCDEFGILMNOPQRSTVXZ1234"
            self.inner_disk_alphabets: str = "gklnprtuz&xysomqihfdbace"

        if self.key not in self.inner_disk_alphabets:
            raise ValueError(f"Key '{self.key}' must be in the inner disk alphabets")

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        """Cipher text by mapping outer disk with inner disk.

        Args:
            text (str): plaintext to be ciphered.
            omit_non_alpha (bool, optional): Whether to omit non-alphabet characters. Defaults to False.

        Returns:
            str: A ciphertext string.
        """
        result: str = ""

        # generate initial disk
        gen = self.generate()
        self.disk = gen["disk"]
        # outer_key assigned by sender
        outer_key = gen["outer_key"]

        result += outer_key
        for i, char in enumerate(text.upper()):
            if char in self.disk:
                result += self.disk[char]
            elif not omit_non_alpha or (char in string.whitespace):
                result += char

            # time to produce new mapping, to make it harder for cryptanalysis
            if i > 0 and i % self.frequency == 0:
                gen = self.generate()
                self.disk = gen["disk"]
                outer_key = gen["outer_key"]
                result += outer_key

        return result

    @override
    def decipher(self, text: str) -> str:
        """Cipher text by mapping inner disk with outer disk.

        Args:
            text (str): plaintext to be ciphered.

        Returns:
            str: decipher text / plaintext string.
        """
        result: str = ""
        for char in text:
            # Checks if the Capital char found, if found create a disk
            if char in self.outer_disk_alphabets:
                self.disk = self.create_disk(outer_key=char)

            # If char is small letter, it means use the existing disk to decipher it.
            elif char in self.inner_disk_alphabets:
                if not self.disk:
                    raise KeyError(
                        "Disk not initialized because ciphertext does not start with an outer key."
                    )
                result += self.disk[char]

            # Dont omit non-alphabet chars
            else:
                result += char

        return result

    def generate(self):
        """Generate a disk, change the outer_key to produce new disk to make the cipher harder for cryptanalysis.

        Returns:
            Dict[str, dict[str,str]]: outer key and a disk.
        """
        # Safely pick a random outer key without IndexErrors
        outer_key = random.choice(self.outer_disk_alphabets)
        disk = self.create_disk(outer_key=outer_key)

        return {
            "outer_key": outer_key,
            "disk": disk,
        }

    def create_disk(self, outer_key: str):
        """Utility method to produce disk based on the outer_key and inner_key that is self.key.

        Args:
            outer_key (str): outer_key to produce disk.

        Returns:
            Dict[str, str]: A disk that can use to cipher and decipher text.
        """
        inner_index = self.inner_disk_alphabets.index(self.key)
        inner_disk_alphabets = (
            self.inner_disk_alphabets[inner_index:]
            + self.inner_disk_alphabets[:inner_index]
        )

        outer_key_index = self.outer_disk_alphabets.index(outer_key)
        outer_disk_alphabets = (
            self.outer_disk_alphabets[outer_key_index:]
            + self.outer_disk_alphabets[:outer_key_index]
        )

        disk = dict(zip(outer_disk_alphabets, inner_disk_alphabets)) | dict(
            zip(inner_disk_alphabets, outer_disk_alphabets)
        )

        return disk

    def __str__(self) -> str:
        """Information of object that includes: key, frequency and modern_implementation.

        Returns:
            str : Prints information of object that includes: key, frequency and modern_implementation.
        """
        mode: str = "Modern A-Z" if self.modern_implementation else "Historical 1467"
        return (
            f"--- {self.__class__.__name__} Cipher ---\n"
            f"Key: {self.key!r}\n"
            f"Spin Freq: {self.frequency}\n"
            f"Mode: {mode}\n"
        )

    def __repr__(self) -> str:
        """Recreate object.

        Returns:
            str : class name with object parameters.
        """
        return f"AlbertiCipher(key={self.key!r}, frequency={self.frequency}, modern_implementation={self.modern_implementation})"


class Trithemius(PolyalphabeticSubstitution):
    """Inspired from the Alberti ciper but uses it own table, that make it unique.

    It creates it own key by the sequence of the input text letters, first letter will be A,
    Second letter wil be B and so on, after the end of Z; it will start with A again.

    WIKI - https://en.wikipedia.org/wiki/Tabula_recta#Trithemius%20cipher
    """

    def __init__(self):
        """Passes key in the super class."""
        super().__init__(key=string.ascii_uppercase)

    @override
    def decipher(self, text: str) -> str:
        """Lookup row index 0 with column index.

        Only column index need to be calculated in order to decipher the text.

        Args:
            text (str): text to decipher.

        Returns:
            str: deciphered / Plain text.
        """
        result: str = ""
        key_cycle: Iterator[int] = cycle(self._get_key_sequence())

        for char in text.upper():
            if char.isalpha():
                key_char: int = next(key_cycle)
                # converts char into int (0-25), -key_char to find the original plain char.
                column: int = (ord(char) - 65) - key_char
                result += self.tabula_recta[0][column]
            else:
                result += char
        return result

    @override
    def __str__(self) -> str:
        """Print class names.

        Print only class name as it does calculate it own key, it does not need to provide a key.

        Returns:
            str: class name.
        """
        return f"{self.__class__.__name__}\n"

    @override
    def __repr__(self) -> str:
        # __repr__ only exist to override its parent implementation, as parent implementation shows key,
        # and Trithemius does need a key.
        return f"{self.__class__.__name__}()"


class Vigenere(PolyalphabeticSubstitution):
    """An extension to Trithemius, uses a continuous Key till it map with each plaintext character; example: LEMONLEMONLEMON.

    WIKI - https://en.wikipedia.org/wiki/Tabula_recta#Improvements and https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
    """

    def __init__(self, key: str):  # noqa : D107
        super().__init__(key)


class Beaufort(PolyalphabeticSubstitution):
    """Similar to Vigenere but uses modified table.

    Similar table size, two-dimensional 26*26 but reverse order starting with the letter Z-A in
    the first row and Column. The letter shifted to left one and goes on as we proceed to next row and column.
    As we visit to 26th row and column it starts with A, Z, Y ... D, C, B.

    WIKI - https://en.wikipedia.org/wiki/Beaufort_cipher
    """

    def __init__(self, key: str):  # noqa : D107
        super().__init__(key)

    @override
    def _generate_table(self) -> list[list[str]]:
        """Create a square table of alphabets for beaufort cipher, as it uses it own table implementation.

        Returns:
            list[list[str]] : Two dimensional square table of alphabets for beaufort cipher.
        """
        tabula_recta: list[list[str]] = []
        for i in range(26):
            tabula_recta.append(
                list(string.ascii_uppercase[i::-1] + string.ascii_uppercase[:i:-1])
            )
        return tabula_recta

    @override
    def decipher(self, text: str) -> str:
        # self-reciprocal
        return self.cipher(text)


class Autokey(PolyalphabeticSubstitution):
    """Similar to Vigenere but uses different key mechanism.

    Starts with a relatively-short keyword, the primer, and appends the message to it.
    For example, if the keyword is QUEENLY and the message is 'attack at dawn', then the key would be
    QUEENLYATTAC

    WIKI - https://en.wikipedia.org/wiki/Autokey_cipher
    """

    def __init__(self, key: str):  # noqa : D107
        super().__init__(key)

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        result: str = ""
        # We start with our primer (e.g., the shifts for 'LEMON')
        key_sequence: list[int] = self._get_key_sequence()
        key_index = 0

        for char in text.upper():
            if char.isalpha():
                # 1. Grab the current shift from our growing list
                current_key_shift: int = key_sequence[key_index]

                # 2. Encrypt the letter using the base class table
                column: int = ord(char) - 65
                result += self.tabula_recta[current_key_shift][column]

                # 3. Append the PLAINTEXT letter to our key sequence!
                key_sequence.append(column)
                key_index += 1

            elif not omit_non_alpha or (char in string.whitespace):
                result += char

        return result

    @override
    def decipher(self, text: str) -> str:
        """Uses Vigenere table.

        Take a first character from the key, find that character into Vigenere table's row.
        Now take first character from cipher text and look into that row's column.

        for example:
        Key = QUEENLYATTAC
        Ciphertext = QNXEPVYTWTWP

        Key first letter = Q
        Ciphertext first letter = Q

        Use the Vigenere table, Q in row and find Q in that row, intersect with column, you will get : A,
        continue this and plaintext will be ATTACKATDAWN.

        Args:
            text (str): The text to be ciphered.

        Returns:
            str: A plaintext / decipher string.
        """
        result: str = ""
        # The receiver only starts with the primer ('LEMON')
        key_sequence: list[int] = self._get_key_sequence()
        key_index = 0

        for text_char in text.upper():
            if text_char.isalpha():
                # 1. Grab the current shift
                current_key_shift: int = key_sequence[key_index]

                # 2. Decrypt the ciphertext back to the original letter
                column: int = self.tabula_recta[current_key_shift].index(text_char)
                decrypted_char: str = self.tabula_recta[0][column]
                result += decrypted_char

                # 3. Append the DECRYPTED letter to our key sequence
                # so we can use it to decrypt future letters!
                key_sequence.append(column)
                key_index += 1
            else:
                result += text_char

        return result
