import pytest

from src.retro_ciphers.poly import (
    Alberti,
    Autokey,
    Beaufort,
    PolyalphabeticSubstitution,
    Trithemius,
    Vigenere,
)


class TestPolyalphabeticSubstitution:
    def test_empty_key(self):
        with pytest.raises(ValueError, match="Key must not be empty."):
            PolyalphabeticSubstitution("")

    def test_invalid_key(self):
        with pytest.raises(ValueError, match="Key must contain at least one letter."):
            Vigenere("123")

    def test_generate_table(self):
        # We need a dummy subclass since PolyalphabeticSubstitution cannot be initialized without a concrete cipher
        # Wait, the base class can be initialized, it doesn't have abstract subclass barriers in python automatically unless ABC is used
        cipher = PolyalphabeticSubstitution("KEY")
        table = cipher._generate_table()
        assert len(table) == 26
        # Check first row is normal alphabet
        assert "".join(table[0]) == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        # Check second row is shifted by 1
        assert "".join(table[1]) == "BCDEFGHIJKLMNOPQRSTUVWXYZA"
        # Check all rows have 26 cols
        assert all(len(row) == 26 for row in table)

class TestAlbertiCipher:
    def test_invalid_key_initialization(self):
        with pytest.raises(ValueError, match="must be in the inner disk alphabets"):
            Alberti("A")  # 'A' is in outer disk, not inner disk

    def test_crashing_uninitialized_decipher(self):
        # By default, modern_implementation=True, so "a" is valid inner disk
        cipher = Alberti("a")
        # 'h' is in inner disk. Attempting to decipher without outer disk char first raises KeyError.
        with pytest.raises(KeyError, match="Disk not initialized"):
            cipher.decipher("hello")

    def test_missing_characters(self):
        cipher = Alberti("a")
        text = "HELLO WORLD ZEBRA! @#"
        enc = cipher.cipher(text)
        # H and W are not in the outer disk alphabets!
        # They get dropped silently into the output, preserving them
        dec = cipher.decipher(enc)
        assert dec == text

    def test_frequency_rotation(self):
        cipher = Alberti("a", frequency=2)
        # Text with spaces to trigger frequency rotation
        text = "A B C D E F"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text

    def test_historical_mode(self):
        # In historical mode, inner disk is "gklnprtuz&xysomqihfdbace", 'a' is valid
        cipher = Alberti("a", modern_implementation=False)
        text = "ABCDEFGHI"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text

    def test_historical_invalid_key(self):
        with pytest.raises(ValueError, match="must be in the inner disk alphabets"):
            Alberti("w", modern_implementation=False) # w is not in historical inner disk

class TestVigenereCipher:
    def test_basic_cipher(self):
        cipher = Vigenere("LEMON")
        text = "ATTACKATDAWN"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text

    def test_non_alpha_characters(self):
        cipher = Vigenere("LEMON")
        text = "ATTACK AT DAWN!"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text

    def test_long_mixed_case(self):
        cipher = Vigenere("SeCrEt")
        # Mixed cases are converted to uppercase internally by the cipher/decipher logic
        text = "This is a really long text with mixed CASES and symbols 123 !@#"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text.upper()

class TestTrithemiusCipher:
    def test_basic_cipher(self):
        cipher = Trithemius()
        text = "HELLO WORLD"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text

class TestBeaufortCipher:
    def test_basic_cipher(self):
        cipher = Beaufort("FORTIFICATION")
        text = "DEFENDTHEEASTWALLOFTHECASTLE"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text

class TestAutokeyCipher:
    def test_basic_cipher(self):
        cipher = Autokey("QUEENLY")
        text = "ATTACKATDAWN"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text

    def test_punctuation_continuity(self):
        cipher = Autokey("KEY")
        text = "HELLO, WORLD!"
        enc = cipher.cipher(text)
        dec = cipher.decipher(enc)
        assert dec == text.upper()
