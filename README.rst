==============
keyless-fernet
==============

A Python library to parse `Fernet tokens <https://github.com/fernet>`_ as much
as possible without using a key. This is useful for doing limited,
non-cryptographic validation or introspection of Fernet tokens.

Usage
-----

.. code:: python

    >>> token = 'gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA=='
    >>> import keyless_fernet
    >>> t = keyless_fernet.Token(token)  # tokens are validated on init
    >>> t.validate(ttl=60)  # but you can also validate a token against any TTL
    >>> t.version  # retrieve the token's version, as an integer
    128
    >>> t.timestamp  # retrieve the token's timestamp, as a datetime
    datetime.datetime(1985, 10, 26, 8, 20)
    >>> t.iv  # and see the hex representations of the other attributes
    '000102030405060708090a0b0c0d0e0f'
    >>> t.ciphertext
    '2d36d5ca46556299fde13008633804b2'
    >>> t.hmac
    'c5ff9095f5d38f9ab86e5543e02686f03b3ec971b9ab47ae23566a54e08c2a0c'

Testing
-------

.. image:: https://travis-ci.org/dolph/keyless-fernet.svg?branch=master
    :target: https://travis-ci.org/dolph/keyless-fernet

No external testing dependencies are required:

.. code:: bash

    $ python -m unittest discover
