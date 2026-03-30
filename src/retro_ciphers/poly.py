"""Polyalphabetic substitution ciphers using multiple shifts.

Each cipher in this module employs a different mechanism to utilize
multiple shifts.

Evolution of polyalphabetic substitution ciphers:
    Alberti -> Trithemius -> Vigenère -> Beaufort -> Autokey
"""

import random
import string
from collections.abc import Iterator
from itertools import cycle
from typing import override

from .base import PolyalphabeticSubstitution, Substitution


class Alberti(Substitution):
    """A cipher using two stacked disks for encryption and decryption.

    The outer disk contains uppercase letters and is fixed, while the inner
    disk contains lowercase letters and can rotate. Both parties agree on a
    key character on the inner disk.

    Encryption (Outer to Inner):
        1. Align the inner key letter with a signal character on the outer
           disk.
        2. Record the signal character in the ciphertext.
        3. Find the plaintext letter on the outer disk and its corresponding
           letter on the inner disk.
        4. Periodically change the alignment and record a new signal character.

    Decryption (Inner to Outer):
        1. Read the signal character from the ciphertext.
        2. Align the inner key letter with this signal character.
        3. Translate inner disk characters back to outer disk characters.
        4. Update alignment when a new signal character (uppercase) is
           encountered.
    """

    def __init__(
        self, key: str, frequency: int = 50, modern_implementation: bool = True
    ):
        """Initializes the Alberti cipher disks.

        Args:
            key (str): The inner disk key character.
            frequency (int): How often to rotate the disk (every N characters).
                Defaults to 50.
            modern_implementation (bool): If True, uses the modern 'a-z'
                alphabet. If False, uses the historical 1467 Latin replica.
                Defaults to True.

        Raises:
            ValueError: If the key is not in the inner disk alphabet.
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
            raise ValueError(f"Key '{self.key}'"
                             f"must be in the inner disk alphabets")

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        """Encrypts text by mapping outer disk characters to the inner disk.

        Args:
            text (str): The plaintext string to encrypt.
            omit_non_alpha (bool): If True, non-alphabetic characters are
                removed. Defaults to False.

        Returns:
            str: The resulting ciphertext string.
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
        """Decrypts text by mapping inner disk characters to the outer disk.

        Args:
            text (str): The ciphertext string to decrypt.

        Returns:
            str: The resulting plaintext string.
        """
        result: str = ""
        for char in text:
            # Checks if the Capital char found, if found create a disk
            if char in self.outer_disk_alphabets:
                self.disk = self.create_disk(outer_key=char)

            # If char is small letter, it means use the existing disk
            # to decipher it.
            elif char in self.inner_disk_alphabets:
                if not self.disk:
                    raise KeyError(
                        "Disk not initialized because ciphertext does not"
                        " start with an outer key."
                    )
                result += self.disk[char]

            # Dont omit non-alphabet chars
            else:
                result += char

        return result

    def generate(self):
        """Generates a new disk alignment with a random outer key.

        Returns:
            dict: A dictionary containing the 'outer_key' and the 'disk'
                mapping.
        """
        # Safely pick a random outer key without IndexErrors
        outer_key = random.choice(self.outer_disk_alphabets)
        disk = self.create_disk(outer_key=outer_key)

        return {
            "outer_key": outer_key,
            "disk": disk,
        }

    def create_disk(self, outer_key: str):
        """Creates a disk mapping based on the outer key and the inner key.

        Args:
            outer_key (str): The outer disk character to align with the inner
                key.

        Returns:
            dict[str, str]: A dictionary representing the disk mapping.
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

        disk = (dict(zip(outer_disk_alphabets, inner_disk_alphabets)) |
                dict(zip(inner_disk_alphabets, outer_disk_alphabets)
        ))

        return disk

    def __str__(self) -> str:
        """Returns the cipher settings, including key, frequency, and mode.

        Returns:
            str: A formatted string with the cipher information.
        """
        mode: str = "Modern A-Z" if self.modern_implementation else "Historical 1467"
        return (
            f"--- {self.__class__.__name__} Cipher ---\n"
            f"Key: {self.key!r}\n"
            f"Spin Freq: {self.frequency}\n"
            f"Mode: {mode}\n"
        )

    def __repr__(self) -> str:
        """Returns a string representation to recreate the object.

        Returns:
            str: A string that can be used to recreate the instance.
        """
        return (f"AlbertiCipher(key={self.key!r}, frequency={self.frequency},"
                f" modern_implementation={self.modern_implementation})")


class Trithemius(PolyalphabeticSubstitution):
    """A polyalphabetic cipher that uses a progressive shift.

    Each character is shifted by its position in the text (0 for the first
    character, 1 for the second, etc.), effectively using the alphabet as
    a sequence of keys.

    See: https://en.wikipedia.org/wiki/Tabula_recta#Trithemius_cipher
    """

    def __init__(self):
        """Initializes the Trithemius cipher with the standard alphabet key."""
        super().__init__(key=string.ascii_uppercase)

    @override
    def decipher(self, text: str) -> str:
        """Decrypts the text using progressive shifts.

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
                # converts char into int (0-25), -key_char to find the
                # original plain char.
                column: int = (ord(char) - 65) - key_char
                result += self.tabula_recta[0][column]
            else:
                result += char
        return result

    @override
    def __str__(self) -> str:
        """Returns the class name.

        Returns:
            str: The name of the cipher class.
        """
        return f"{self.__class__.__name__}\n"

    @override
    def __repr__(self) -> str:
        """Returns a string representation to recreate the object.

        Returns:
            str: A string representing the object.
        """
        return f"{self.__class__.__name__}()"


class Vigenere(PolyalphabeticSubstitution):
    """An extension of Trithemius using a repeating keyword.

    See: https://en.wikipedia.org/wiki/Vigenere_cipher
    """

    def __init__(self, key: str):  # noqa : D107
        super().__init__(key)


class Beaufort(PolyalphabeticSubstitution):
    """A variant of the Vigenère cipher using a reversed tabula recta.

    The table starts with 'Z-A' in the first row and column, and shifts
    left progressively.

    See: https://en.wikipedia.org/wiki/Beaufort_cipher
    """

    def __init__(self, key: str):  # noqa : D107
        super().__init__(key)

    @override
    def _generate_table(self) -> list[list[str]]:
        """Creates a reversed square table of alphabets for the Beaufort.

        Returns:
            list[list[str]]: A 26x26 square table of reversed alphabets.
        """
        tabula_recta: list[list[str]] = []
        for i in range(26):
            tabula_recta.append(
                list(string.ascii_uppercase[i::-1]
                     + string.ascii_uppercase[:i:-1])
            )
        return tabula_recta

    @override
    def decipher(self, text: str) -> str:
        # self-reciprocal
        return self.cipher(text)


class Autokey(PolyalphabeticSubstitution):
    """A polyalphabetic cipher that incorporates the message into the key.

    It starts with a short keyword (the primer) and appends the plaintext
    itself to form the key.

    See: https://en.wikipedia.org/wiki/Autokey_cipher
    """

    def __init__(self, key: str):  # noqa : D107
        super().__init__(key)

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        """Encrypts text using the autokey mechanism.

        Args:
            text (str): The plaintext string to encrypt.
            omit_non_alpha (bool): If True, non-alphabetic characters are
                removed. Defaults to False.

        Returns:
            str: The resulting ciphertext string.
        """
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
        """Decrypts text using the autokey mechanism.

        Example:
            Key primer = QUEENLY, Ciphertext = QNXEPVYTWTWP
            The decrypted letters are appended to the key to decrypt
            subsequent characters.

        Args:
            text (str): The ciphertext string to decrypt.

        Returns:
            str: The resulting plaintext string.
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
                column: int = (self.tabula_recta[current_key_shift].
                               index(text_char))
                decrypted_char: str = self.tabula_recta[0][column]
                result += decrypted_char

                # 3. Append the DECRYPTED letter to our key sequence
                # so we can use it to decrypt future letters!
                key_sequence.append(column)
                key_index += 1
            else:
                result += text_char

        return result
