"""Classical implementations of substitution ciphers.

This package provides implementations of monoalphabetic and polyalphabetic
substitution ciphers. Monoalphabetic algorithms include Atbash, Baconian,
Caesar, MixedAlphabet, PolybiusSquare, Rot13, Shift, and SimpleSubstitution.
Polyalphabetic algorithms include Alberti, Autokey, Beaufort, Trithemius,
and Vigenere.

Modules:
    mono: Monoalphabetic substitution that maps each letter to a fixed letter.
    poly: Polyalphabetic substitution that uses multiple shift rules.
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

__all__: list[str] = [
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
