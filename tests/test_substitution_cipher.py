
import pytest

from src.retro_ciphers.mono import (
    Atbash,
    Shift,
    Caesar,
    Rot13,
    MixedAlphabet,
    SimpleSubstitution,
    Baconian,
    PolybiusSquare,
)

def test_atbash():
    cipher = Atbash()
    assert cipher.cipher("A") == "Z"
    assert cipher.cipher("a") == "z"
    assert cipher.cipher("Hello World!") == "Svool Dliow!"
    assert cipher.decipher("Svool Dliow!") == "Hello World!"

def test_shift():
    cipher = Shift(1)
    assert cipher.cipher("abc") == "bcd"
    assert cipher.cipher("Z") == "A"
    assert cipher.decipher("bcd") == "abc"

    # Test shift larger than 26
    cipher_wrap = Shift(27)
    assert cipher_wrap.cipher("abc") == "bcd"

def test_caesar():
    cipher = Caesar()
    assert cipher.cipher("aBc") == "dEf"
    assert cipher.decipher("dEf") == "aBc"

def test_rot13():
    cipher = Rot13()
    assert cipher.cipher("Hello!") == "Uryyb!"
    assert cipher.decipher("Uryyb!") == "Hello!"

def test_mixed_alphabet():
    cipher = MixedAlphabet("ZEBRA")
    # ZEBRAcdfghijklmnopqstuvwxy
    # a->Z, b->E, c->B, d->R, e->A, f->c
    assert cipher.cipher("abcde") == "zebra"
    assert cipher.decipher("zebra") == "abcde"

    # Test keyword normalization (ignoring non-alpha, handling upper/lower cases)
    cipher2 = MixedAlphabet("Zz !eE bB Rr Aa!")
    assert cipher2.cipher("abcde") == "zebra"
    assert cipher2.decipher("zebra") == "abcde"

def test_simple_substitution():
    alphabet = "zyxwvutsrqponmlkjihgfedcba" # reversed
    cipher = SimpleSubstitution(alphabet)
    assert cipher.cipher("abc") == "zyx"
    assert cipher.decipher("zyx") == "abc"

    # Unique check
    with pytest.raises(ValueError):
        SimpleSubstitution("A" * 26)

    # Length check
    with pytest.raises(ValueError):
        SimpleSubstitution("abc")

    # Symbols allowed in cipher alphabet (casing might fail to preserve for decipher)
    symbol_alphabet = "!@#$%^&*()_+{}|:\"<>?-=[]\\;',./"[:26]
    cipher_sym = SimpleSubstitution(symbol_alphabet)
    assert cipher_sym.cipher("a") == "!"

    # Random generation
    random_alphabet = SimpleSubstitution.generate_cipher_alphabet()
    assert len(set(random_alphabet)) == 26
    assert len(random_alphabet) == 26

def test_baconian_modern():
    cipher = Baconian(modern_implementation=True)
    # H -> AABBB, e -> aabaa, l -> ababb, l -> ababb, o -> abbba
    assert cipher.cipher("Hello") == "AABBBaabaaababbababbabbba"
    assert cipher.decipher("AABBBaabaaababbababbabbba") == "Hello"

    assert cipher.cipher("a B") == "aaaaa AAAAB"
    assert cipher.decipher("aaaaa AAAAB") == "a B"

    # Edge cases
    assert cipher.decipher("aa!aa") == "aa!aa"     # incomplete blocks fall back
    assert cipher.decipher("aaaaab") == "ab"       # remaining "b" falls back as is

def test_baconian_classic():
    cipher = Baconian(modern_implementation=False)
    # I and J are both abaaa.
    assert cipher.cipher("I") == "ABAAA"
    assert cipher.cipher("J") == "ABAAA"
    # Decipher defaults to 'J' or 'I' because it's mapping the same token. 
    # With dictionary iteration either might be last, but it maps consistently.
    deciphered_I = cipher.decipher("ABAAA").upper()
    assert deciphered_I in ["I", "J"]

def test_polybius_square():
    cipher = PolybiusSquare()
    assert cipher.cipher("aB") == "1112"
    assert cipher.decipher("1112") == "AB" # Polybius deciphers to uppercase
    assert cipher.cipher("I") == "24"
    assert cipher.cipher("J") == "24"
    assert cipher.decipher("24").upper() in ["I", "J"]
    
    # Test non-alphabetic/non-numeric correctly falls back
    assert cipher.cipher("a1") == "111"
    
    deciphered_spaced = cipher.decipher("11 24")
    assert deciphered_spaced == "A I" or deciphered_spaced == "A J"

    # Odd length fallback
    assert cipher.decipher("111") == "A1"
