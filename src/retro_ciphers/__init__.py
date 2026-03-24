"""Classical implementation of Substitution ciphers.

This package provides implementation of Monoalphabetic substitution, Polyalphabetic substitution cipher.
Algorithms that Monoalphabetic substitution includes Atbash, Baconian, Caesar, MixedAlphabet, PolybiusSquare,
Rot13, Shift and SimpleSubstitution; Polyalphabetic substitution includes Alberti, Autokey, Beaufort, Trithemius,
and Vigenere.

Modules:
    mono: Monoalphabetic substitution that map each letter to its corresponding fixed letter.
    poly: Polyalphabetic substitution that uses multiple shift rules and then map each letter to its corresponding
    fixed letter.
"""


# compatible with older code i.e. retro_ciphers.mono and retro_ciphers.poly
from . import mono, poly
# direct access to classes
from .mono import (
    Atbash,
    Baconian,
    Caesar,
    MixedAlphabet,
    PolybiusSquare,
    Rot13,
    Shift,
    SimpleSubstitution,
)
from .poly import (
    Alberti,
    Autokey,
    Beaufort,
    Trithemius,
    Vigenere,
)

__all__ : list[str] = [
    "mono",
    "poly",
    # Monoalphabetic
    "Atbash",
    "Shift",
    "Caesar",
    "Rot13",
    "MixedAlphabet",
    "SimpleSubstitution",
    "Baconian",
    "PolybiusSquare",

    # Polyalphabetic
    "Alberti",
    "Trithemius",
    "Vigenere",
    "Beaufort",
    "Autokey",
]
