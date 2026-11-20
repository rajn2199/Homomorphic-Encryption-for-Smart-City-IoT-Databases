"""Check encrypted arithmetic without starting PostgreSQL."""

from fractions import Fraction
import unittest

from crypto import MAX_ROWS, create_contexts, decrypt_results, encrypt_reading, evaluate


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner, cls.public = create_contexts()

    def test_aggregates(self):
        for values, expected in (
            ([0], (0, Fraction(0), 0, 0)),
            ([0, 20, 20, 100], (140, Fraction(35), 0, 100)),
            ([2, 5, 6], (13, Fraction(13, 3), 2, 6)),
            ([100] * MAX_ROWS, (100 * MAX_ROWS, Fraction(100), 100, 100)),
        ):
            with self.subTest(count=len(values), first=values[0]):
                # Cache repeated readings for the boundary test to exercise
                # worst-case addition of correlated ciphertext noise.
                encrypted = {
                    value: encrypt_reading(self.public, value) for value in set(values)
                }
                rows = [encrypted[value] for value in values]
                self.assertEqual(
                    decrypt_results(self.owner, *evaluate(self.public, rows), len(values)),
                    expected,
                )

    def test_bounds_and_key_separation(self):
        for value in (-1, 101, 2.5):
            with self.assertRaises(ValueError):
                encrypt_reading(self.public, value)
        self.assertFalse(self.public.has_secret_key())
        with self.assertRaises(ValueError):
            evaluate(self.public, [])
        with self.assertRaises(ValueError):
            evaluate(self.owner, [encrypt_reading(self.public, 7)])


if __name__ == "__main__":
    unittest.main()
