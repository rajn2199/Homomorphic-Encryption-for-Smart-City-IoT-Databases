"""BFV arithmetic for bounded integer sensor readings."""

from fractions import Fraction

import tenseal as ts

MAX_VALUE = 100
MAX_ROWS = 1000
WEIGHTS = list(range(MAX_VALUE + 1))


def create_contexts():
    owner = ts.context(ts.SCHEME_TYPE.BFV, 8192, 1032193, n_threads=1)
    owner.generate_galois_keys()
    public_bytes = owner.serialize(save_secret_key=False)
    return owner, ts.context_from(public_bytes, n_threads=1)


def encrypt_reading(public, value):
    if type(value) is not int or not 0 <= value <= MAX_VALUE:
        raise ValueError(f"Reading must be an integer from 0 to {MAX_VALUE}")
    bins = [0] * len(WEIGHTS)
    bins[value] = 1
    return ts.bfv_vector(public, bins).serialize()


def evaluate(public, ciphertexts):
    """Run with evaluation keys only. Return encrypted total and histogram."""
    if not 1 <= len(ciphertexts) <= MAX_ROWS:
        raise ValueError(f"Expected 1 to {MAX_ROWS} readings")
    if public.has_secret_key():
        raise ValueError("Evaluation requires a public context")

    rows = iter(ciphertexts)
    histogram = ts.bfv_vector_from(public, next(rows))
    for row in rows:
        histogram += ts.bfv_vector_from(public, row)
    return histogram.dot(WEIGHTS).serialize(), histogram.serialize()


def decrypt_results(owner, encrypted_total, encrypted_histogram, count):
    total, = ts.bfv_vector_from(owner, encrypted_total).decrypt()
    bins = ts.bfv_vector_from(owner, encrypted_histogram).decrypt()
    occupied = [value for value, frequency in enumerate(bins) if frequency > 0]
    if (len(bins) != len(WEIGHTS) or any(frequency < 0 for frequency in bins)
            or sum(bins) != count or not occupied
            or sum(value * frequency for value, frequency in enumerate(bins)) != total):
        raise ValueError("Inconsistent encrypted aggregates")
    return total, Fraction(total, count), occupied[0], occupied[-1]
