from .base import Substitution
import string
from typing import override
from itertools import cycle

"""
The history of the Polyalphabetci substitution cipher

Alberti cipher
	↓
Trithemius cipher
	↓
Vigenere cipher
	↓
Beaufort cipher
	↓
Autokey cipher


----------------------------------------------------------

Alberti cipher 

- was one of the first polyalphabetic ciphers.

WIKI - https://en.wikipedia.org/wiki/Alberti_cipher

----------------------------------------------------------

Trithemius cipher

- Grab the inspiration from the Alberti ciper but uses it own table, that make it uqnique. It creates it own key by the sequnce of the input text letters, first letter will be A, Second letter wil be B and so on, after the end of Z return to A.

WIKI - https://en.wikipedia.org/wiki/Tabula_recta#Trithemius%20cipher

----------------------------------------------------------

Vigenera cipher 

- an important extension to Trithemius's method, Need a key; not just a sequence of letter as a key, for example: LEMON.

WIKI - https://en.wikipedia.org/wiki/Tabula_recta#Improvements and https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

----------------------------------------------------------

Beaufort cipher

- Similar to the Vigenère cipher, with a slightly modified enciphering mechanism and tableau.
- The Beaufort cipher is based on the Beaufort square which is essentially the same as a Vigenère square but in reverse order starting with the letter "Z" in the first row,[3] where the first row and the last column serve the same purpose.

WIKI - https://en.wikipedia.org/wiki/Beaufort_cipher

----------------------------------------------------------

Autokey cipher

- starts with a relatively-short keyword, the primer, and appends the message to it. For example, if the keyword is QUEENLY and the message is attack at dawn, then the key would be QUEENLYATTACKATDAWN

WIKI - https://en.wikipedia.org/wiki/Autokey_cipher

"""


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
    def cipher(self, text: str) -> str:
        result: str = ""
        key_cycle = cycle(self._get_key_sequence())

        for text_char in text.upper():
            if text_char.isalpha():
                key_char = next(key_cycle)
                row = key_char
                # convert text_char to int then -65 as the ascii upper letters start at 65, to get the index of the column.
                column = ord(text_char) - 65
                result += self.tabula_recta[row][column]
            else:
                result += text_char
        return result

    @override
    def decipher(self, text: str) -> str:
        result: str = ""
        key_cycle = cycle(self._get_key_sequence())

        for text_char in text.upper():
            if text_char.isalpha():
                key_char = next(key_cycle)
                column = self.tabula_recta[key_char].index(text_char)
                result += self.tabula_recta[0][column]
            else:
                result += text_char
        return result


import random


class AlbertiCipher(Substitution):
    """
    modern_implementation: Whether to use the modern or old implementation of the cipher.
    if moder_imlemenation = False, you should only bring plaintext as in 15th century latin alphabets, this is for the historical purposes.
    """

    def __init__(
        self, key: str, frequency: int = 50, modern_implementation: bool = True
    ):
        self.key = key
        self.frequency = frequency
        self.disk: dict[str, str] = {}
        self.modern_implementation = modern_implementation

        if self.modern_implementation:
            # The Modern 26-Letter English Tool
            self.outer_disk_alphabets = string.ascii_uppercase
            self.inner_disk_alphabets = "qwertyuiopasdfghjklzxcvbnm"
        else:
            # The Historical 1467 Latin Replica
            self.outer_disk_alphabets = "ABCDEFGILMNOPQRSTVXZ1234"
            self.inner_disk_alphabets = "gklnprtuz&xysomqihfdbace"

        if self.key not in self.inner_disk_alphabets:
            raise ValueError(f"Key '{self.key}' must be in the inner disk alphabets")

    @override
    def cipher(self, text: str) -> str:
        result: str = ""

        # generate intial disk
        gen = self.generate()
        self.disk = gen["disk"]
        outer_key = gen["outer_key"]

        result += outer_key
        for i, char in enumerate(text.upper()):
            if char in self.disk:
                result += self.disk[char]
            else:
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
        result: str = ""
        for char in text:
            # Checks if the Capital char found, if found create a disk
            if char in self.outer_disk_alphabets:
                self.disk = self.create_disk(outer_key=char)

            # If char is small letter, it mean use the existing disk to decipher it.
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
        """
        Generate a disk, change the outer_key to produce new disk to make the cipher harder cryptanalysis.
        """
        # Safely pick a random outer key without IndexErrors
        outer_key = random.choice(self.outer_disk_alphabets)
        disk = self.create_disk(outer_key=outer_key)

        return {
            "outer_key": outer_key,
            "disk": disk,
        }

    def create_disk(self, outer_key: str):
        """
        Utility method to produce disk based on the outer_key and inner_key that is self.key
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


class TrithemiusCipher(PolyalphabeticSubstitution):
    def __init__(self):
        super().__init__(key=string.ascii_uppercase)

    @override
    def decipher(self, text: str) -> str:
        result: str = ""
        key_cycle = cycle(self._get_key_sequence())

        for text_char in text.upper():
            if text_char.isalpha():
                key_char = next(key_cycle)
                column = (ord(text_char) - 65) - key_char
                result += self.tabula_recta[0][column]
            else:
                result += text_char
        return result


class VigenereCipher(PolyalphabeticSubstitution):
    def __init__(self, key: str):
        super().__init__(key)


class BeaufortCipher(PolyalphabeticSubstitution):
    def __init__(self, key: str):
        super().__init__(key)

    @override
    def _generate_table(self) -> list[list[str]]:
        """Create a square table of alphabets for beaufort cipher, as it uses it own table implmentation."""
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


class AutokeyCipher(PolyalphabeticSubstitution):
    def __init__(self, key: str):
        super().__init__(key)

    @override
    def cipher(self, text: str) -> str:
        result: str = ""
        # We start with our primer (e.g., the shifts for 'LEMON')
        key_sequence = self._get_key_sequence()
        key_index = 0

        for text_char in text.upper():
            if text_char.isalpha():
                # 1. Grab the current shift from our growing list
                current_key_shift = key_sequence[key_index]

                # 2. Encrypt the letter using the base class table
                column = ord(text_char) - 65
                result += self.tabula_recta[current_key_shift][column]

                # 3. Append the PLAINTEXT letter to our key sequence!
                key_sequence.append(column)
                key_index += 1
            else:
                result += text_char

        return result

    @override
    def decipher(self, text: str) -> str:
        result: str = ""
        # The receiver only starts with the primer ('LEMON')
        key_sequence = self._get_key_sequence()
        key_index = 0

        for text_char in text.upper():
            if text_char.isalpha():
                # 1. Grab the current shift
                current_key_shift = key_sequence[key_index]

                # 2. Decrypt the ciphertext back to the original letter
                column = self.tabula_recta[current_key_shift].index(text_char)
                decrypted_char = self.tabula_recta[0][column]
                result += decrypted_char

                # 3. Append the DECRYPTED letter to our key sequence
                # so we can use it to decrypt future letters!
                key_sequence.append(column)
                key_index += 1
            else:
                result += text_char

        return result
