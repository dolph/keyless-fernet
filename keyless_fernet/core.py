import base64
import binascii
import datetime
import struct
import time


# component lengths in bytes
VERSION_LEN = 1
TIMESTAMP_LEN = 8
IV_LEN = 16
CIPHERTEXT_LEN_MOD = 16  # variable length, multiples of 16 bytes
HMAC_LEN = 32

# compute the start of each component
VERSION_START = 0
TIMESTAMP_START = VERSION_LEN
IV_START = TIMESTAMP_START + TIMESTAMP_LEN
CIPHERTEXT_START = IV_START + IV_LEN
HMAC_START = -HMAC_LEN

# compute the end of each segment
VERSION_END = TIMESTAMP_START
TIMESTAMP_END = IV_START
IV_END = CIPHERTEXT_START
CIPHERTEXT_END = -HMAC_LEN
HMAC_END = None


class InvalidToken(Exception):
    pass


class UnrecognizedVersion(InvalidToken):
    pass


class ExpiredToken(InvalidToken):
    pass


class Token(object):
    """Parses as much of fernet tokens as possible without an encryption key.

    Specification: https://github.com/fernet/spec/blob/master/Spec.md

    """
    def __init__(self, token, ttl=None):
        try:
            self._token = base64.urlsafe_b64decode(token)
        except Exception:
            # this will most likely occur when the base64 padding is wrong
            raise InvalidToken('Token is not base64url encoded.')

        self.validate(ttl)

    def validate(self, ttl=None):
        """Validate the token without using the encryption key."""
        if self.version != 128:
            raise UnrecognizedVersion('Token is not a recognized version.')

        if ttl is not None:
            age = time.time() - self.timestamp_int
            if age > ttl:
                raise ExpiredToken('Token expired %d seconds ago.' % (
                    age - ttl))

    @property
    def version(self):
        """Returns the token's version specification.

        Currently there is only one version defined, with the value 128 (0x80).

        """
        byte_str = self._token[VERSION_START:VERSION_END]
        return ord(byte_str)

    @property
    def timestamp_bytes(self):
        return self._token[TIMESTAMP_START:TIMESTAMP_END]

    @property
    def timestamp_int(self):
        return struct.unpack(">Q", self.timestamp_bytes)[0]

    @property
    def timestamp(self):
        """Return the token's timestamp as a datetime object.

        The timestamp is a 64-bit unsigned big-endian integer, recording the
        number of seconds elapsed between January 1, 1970 UTC and the time the
        token was created.

        """
        return datetime.datetime.fromtimestamp(self.timestamp_int)

    @property
    def iv(self):
        """Return the AES Initialization Vector used in hex."""
        return binascii.hexlify(self._token[IV_START:IV_END])

    @property
    def ciphertext(self):
        """Return the variable-length AES ciphertext in hex."""
        return binascii.hexlify(self._token[CIPHERTEXT_START:CIPHERTEXT_END])

    @property
    def hmac(self):
        """Return the token's 256-bit SHA256 HMAC, under signing-key, in hex.

        You need the signing key, which is part of the fernet key, in order to
        validate the HMAC.

        """
        return binascii.hexlify(self._token[HMAC_START:HMAC_END])
