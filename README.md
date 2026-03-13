# Retro Ciphers

**Retro Ciphers** is implementations of classical and historical ciphers. It is intended for educational purposes, cryptography enthusiasts, or anyone interested in the history of hidden messages.

This package encompasses both **Monoalphabetic** and **Polyalphabetic** substitution ciphers,to include modern interpretations as well as strict, historically accurate 15th-century variants.

## Installation

You can easily install `retro-ciphers` via pip:

```bash
pip install retro-ciphers
```

*(Requires Python 3.12 or higher)*

## Features

`retro-ciphers` provides clean, object-oriented API access to the following historical ciphers:

### Monoalphabetic Ciphers
- **Atbash**: The classic Hebrew reversal cipher.
- **Caesar / Shift / ROT13**: Classical shift ciphers with custom shift lengths.
- **Mixed Alphabet**: Key-based shift mechanisms mapping the standard alphabet.
- **Simple Substitution**: Create completely custom scrambled mappings.
- **Baconian Cipher**: Francis Bacon's steganographic, binary-like cipher (supports both classic 24-letter and modern 26-letter alphabets).
- **Polybius Square**: The classical ancient Greek fractionating cipher (coordinates).

### Polyalphabetic Ciphers
- **Alberti Cipher**: The first polyalphabetic cipher! Supports both standard English 26-character modern modes AND the historically accurate 1467 Latin 24/24 Character Disks implementation seamlessly!
- **Trithemius Cipher**: Johannes Trithemius's tabula recta system.
- **Vigenère Cipher**: The famous, unbroken mathematical improvement using table offsets.
- **Beaufort Cipher**: A variant of Vigenère using a reversed tabula recta mechanism.
- **Autokey Cipher**: An extension where the plaintext itself becomes part of the key.

## Quick Start

The API is simple: initialize your chosen cipher, then use `.cipher()` to encrypt and `.decipher()` to decrypt text.

### Monoalphabetic Examples

```python
from retro_ciphers.mono import Caesar, Atbash, Baconian

# Caesar Cipher
caesar = Caesar() # Default shift of 3
encrypted = caesar.cipher("Hello World!")
# >>> "Khoor Zruog!"

# Atbash Cipher
atbash = Atbash()
print(atbash.cipher("Classical Cryptography"))
# >>> "Xozhhzxzo Xibkgltizksb"

# Baconian Cipher
bacon = Baconian(modern_implementation=True)
print(bacon.cipher("Hide"))
# >>> "AABBBABAAAAABABAABAA"
```

### Polyalphabetic Examples

```python
from retro_ciphers.poly import Vigenere, Alberti

# Vigenère Cipher
vigenere = Vigenere("LEMON")
encrypted = vigenere.cipher("ATTACK AT DAWN")
print(encrypted)
# >>> "LXFOPV EF RNHR"

decrypted = vigenere.decipher(encrypted)
print(decrypted)
# >>> "ATTACK AT DAWN"

# Alberti Cipher (Historical 1467 Mode)
# Uses the original Latin outer ("ABCDEFGILMNOPQRSTVXZ1234") and inner mappings
alberti = Alberti(key="a", modern_implementation=False)
secret = alberti.cipher("ABCDEFGHI")
print(secret)
```

## Extra arguments

- `omit_non_alpha`: Available in the `cipher()` methods across ciphers (such as `Alberti` and `Autokey`). Accepts a boolean value (default: `False`). If `True`, it removes special symbols such as punctuation from the ciphertext. If `False`, it safely passes them through so they are kept intact.
- `Alberti(key, frequency=50, modern_implementation=True)`: 
  - `modern_implementation`: By default (`True`), the cipher uses the standard modern English A-Z alphabet. If you pass `False`, it enforces the historically accurate 1467 24-character Latin disks.
  - `frequency`: By default (`50`), the Alberti cipher automatically changes its mapping disk (indicating via a new outer key) every 50 characters to improve security against cryptanalysis. You can increase or decrease this rate.
- `Baconian(modern_implementation=True)`: By default (`True`), uses the full 26-letter alphabet. If `False`, it mimics Bacon's original 24-letter alphabet where 'I' & 'J' and 'U' & 'V' map to the same sequences. 

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
