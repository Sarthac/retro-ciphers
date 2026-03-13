from .base import Substitution, PolyalphabeticSubstitution
import string
from typing import override
from itertools import cycle
import random

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


class Alberti(Substitution):
    """
    Uses a disk that has two disk stack on each other to form a disk,

    1. Outer disk is Capital lettes, not moveable
    2. Inner disk is small letters, moveable (possible to rotate)

    To cipher or decipher a text, both parties—the sender and reciver agree on the key that is respect to inner disk(smaller letter),

    In Alberti's original design, the Outer Disk is the Plaintext and the Inner Disk is the Ciphertext.


    1). How to Encrypt (Outer -> Inner)

    Because the outer disk represents your readable English, you always start looking there when encrypting.

    1.  Align: Map the inner 'g' to the outer 'D'.(here 'g' is the key, both sender and reciver need to know, 'D' is the outer disk only specify that the 'g' map to 'D', if reciver stumble upon next new capital letter, it is time to map the 'g' with new capital letter)
    2.  Signal: Write down 'D' in your ciphertext so the receiver knows the starting position.
    3.  Cipher: Look for your Plaintext letter on the Outer Disk. Find the letter directly below it on the Inner Disk and write that down.
    4.  Switch: Decide to change the key. Map inner 'g' to outer 'M'.
    5.  Signal & Cipher: Write down 'M' in your ciphertext, and then continue looking at the Outer Disk and writing down the new matching letters from the Inner Disk.

    2). How to Decrypt (Inner -> Outer)

    When you receive the scrambled message, you are looking at the ciphertext, so you have to read it in reverse.

    1.  Read the Signal: You see the first letter is 'D'.
    2.  Align: You map your inner 'g' to the outer 'D'.
    3.  Decipher: Look for the scrambled Ciphertext letter on the Inner Disk. Find the letter directly above it on the Outer Disk and write that down to reveal the plain English.
    4.  Read the Next Signal: You hit the letter 'M' in the ciphertext.
    5.  Switch & Decipher: You rotate your inner 'g' to the outer 'M', and continue finding the ciphertext on the Inner Disk and translating it to the Outer Disk.

    """

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
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        result: str = ""

        # generate intial disk
        gen = self.generate()
        self.disk = gen["disk"]
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

    def __str__(self) -> str:
        mode = "Modern A-Z" if self.modern_implementation else "Historical 1467"
        return (
            f"--- {self.__class__.__name__} Cipher ---\n"
            f"Key: {self.key!r}\n"
            f"Spin Freq: {self.frequency}\n"
            f"Mode: {mode}\n"
        )

    def __repr__(self) -> str:
        return f"AlbertiCipher(key={self.key!r}, frequency={self.frequency}, modern_implementation={self.modern_implementation})"


class Trithemius(PolyalphabeticSubstitution):
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

    @override
    def __str__(self) -> str:
        return f"{self.__class__.__name__}\n"

    @override
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class Vigenere(PolyalphabeticSubstitution):
    def __init__(self, key: str):
        super().__init__(key)


class Beaufort(PolyalphabeticSubstitution):
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


class Autokey(PolyalphabeticSubstitution):
    def __init__(self, key: str):
        super().__init__(key)

    @override
    def cipher(self, text: str, omit_non_alpha: bool = False) -> str:
        result: str = ""
        # We start with our primer (e.g., the shifts for 'LEMON')
        key_sequence = self._get_key_sequence()
        key_index = 0

        for char in text.upper():
            if char.isalpha():
                # 1. Grab the current shift from our growing list
                current_key_shift = key_sequence[key_index]

                # 2. Encrypt the letter using the base class table
                column = ord(char) - 65
                result += self.tabula_recta[current_key_shift][column]

                # 3. Append the PLAINTEXT letter to our key sequence!
                key_sequence.append(column)
                key_index += 1

            elif not omit_non_alpha or (char in string.whitespace):
                result += char

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
