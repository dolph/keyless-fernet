import datetime
import unittest

import fernet_keyless


VALID_TOKEN = (
    'gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJ'
    'obwOz7JcbmrR64jVmpU4IwqDA==')


class TestValidToken(unittest.TestCase):
    def setUp(self):
        self.token = fernet_keyless.Token(VALID_TOKEN)

    def test_version(self):
        self.assertEqual(128, self.token.version)

    def test_timestamp(self):
        expected_timestamp = datetime.datetime(1985, 10, 26, 8, 20, 0)
        self.assertEqual(expected_timestamp, self.token.timestamp)

    def test_iv(self):
        iv = '000102030405060708090a0b0c0d0e0f'
        self.assertEqual(iv, self.token.iv)

    def test_ciphertext(self):
        ciphertext = (
            '2d36d5ca46556299fde13008633804b2')
        self.assertEqual(ciphertext, self.token.ciphertext)

    def test_hmac(self):
        hmac = (
            'c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c')
        self.assertEqual(hmac, self.token.hmac)


class TestInvalidTokens(unittest.TestCase):
    def test_incorrect_padding(self):
        # this doesn't have the correct padding to be base64 encoded
        self.assertRaises(
            fernet_keyless.InvalidToken,
            fernet_keyless.Token,
            'foo')

    def test_unrecognized_version(self):
        # although this clearly isn't base64 encoded, it is padded correctly
        self.assertRaises(
            fernet_keyless.UnrecognizedVersion,
            fernet_keyless.Token,
            'asdf')

        # this token has the version manually set to 0x7F == 127
        self.assertRaises(
            fernet_keyless.UnrecognizedVersion,
            fernet_keyless.Token,
            'fwAAAABU7LJHAsotTpqP3tpAZ0zrJKiHFSJ8Z1I-S5ZCuAfBPpLKNaFHXoQeuba1n'
            'MROtB_kTDBlydZ2hj3_AqS34UE0_QXN4Q==')
