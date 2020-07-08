import base64
import bcrypt
import os

PM_VERSION = 4


def bcrypt_b64_encode(s):  # The joy of bcrypt
    bcrypt_base64 = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    std_base64chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    s = base64.b64encode(s)
    return s.translate(bytes.maketrans(std_base64chars, bcrypt_base64))


def hash_password_3(hash_class, password, salt, modulus):
    salt = (salt + b"proton")[:16]
    salt = bcrypt_b64_encode(salt)[:22]
    hashed = bcrypt.hashpw(password, b"$2y$10$" + salt)
    return hash_class(hashed + modulus).digest()


def hash_password(hash_class, password, salt, modulus, version):
    if version == 4 or version == 3:
        return hash_password_3(hash_class, password, salt, modulus)

    raise ValueError('Unsupported auth version')


def long_length(n):
    return (n.bit_length() + 7) // 8


def bytes_to_long(s):
    return int.from_bytes(s, 'little')


def long_to_bytes(n):
    return n.to_bytes(long_length(n), 'little')


def get_random(nbytes):
    return bytes_to_long(os.urandom(nbytes))


def get_random_of_length(nbytes):
    offset = (nbytes * 8) - 1
    return get_random(nbytes) | (1 << offset)


def custom_hash(hash_class, *args, **kwargs):
    h = hash_class()
    for s in args:
        if s is not None:
            data = long_to_bytes(s) if isinstance(s, int) else s
            h.update(data)

    return bytes_to_long(h.digest())
