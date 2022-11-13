import ctypes
from typing import Tuple
from ctypes import CDLL

from . import __cdlls
from . import __params
from . import __logger

def get_base(version: str, nist_security_level: int, aes: bool) -> str:
    base = f'pqcrystals_dilithium{nist_security_level}{"aes" if aes else ""}_{version}'
    return base

def get_lib(version: str, nist_security_level: int, aes: bool) -> CDLL:
    base = get_base(version, nist_security_level, aes)
    libname = 'lib' + base
    lib = __cdlls[libname]
    return lib

def get_function_name(version: str, nist_security_level: int, aes: bool, name: str) -> str:
    base = get_base(version, nist_security_level, aes)
    symbol_name = base + '_' + name
    return symbol_name

def get_define_name(nist_security_level: int, name: str) -> str:
    return f'pqcrystals_dilithium{nist_security_level}_{name}'

def keypair(version: str = 'ref', nist_security_level: int = 3, aes=False) -> Tuple[bytes, bytes]:
    # aes -> version == 'avx2'
    lib = get_lib(version, nist_security_level, aes)
    f = lib.__getattr__(get_function_name(version, nist_security_level, aes, 'keypair'))

    # pk_buf_len = __defines[get_define_name(nist_security_level, 'PUBLICKEYBYTES')]
    # sk_buf_len = __defines[get_define_name(nist_security_level, 'SECRETKEYBYTES')]
    pk_buf_len = __params[nist_security_level]['CRYPTO_PUBLICKEYBYTES']
    sk_buf_len = __params[nist_security_level]['CRYPTO_SECRETKEYBYTES']

    pk_buf = (ctypes.c_uint8 * pk_buf_len)()
    sk_buf = (ctypes.c_uint8 * sk_buf_len)()

    f(ctypes.pointer(pk_buf), ctypes.pointer(sk_buf))

    return bytes(pk_buf), bytes(sk_buf)


def signature(message: bytes, secret_key: bytes, version: str = 'ref', nist_security_level: int = 3, aes=False) -> bytes:
    # aes -> version == 'avx2'
    lib = get_lib(version, nist_security_level, aes)
    f = lib.__getattr__(get_function_name(version, nist_security_level, aes, 'signature'))

    signature_length = __params[nist_security_level]['CRYPTO_BYTES']

    sig = (ctypes.c_uint8 * signature_length)()
    siglen = ctypes.c_size_t()
    m = ctypes.create_string_buffer(message, len(message))
    mlen = ctypes.c_size_t(len(m))
    sk = ctypes.create_string_buffer(secret_key, len(secret_key))

    f(ctypes.byref(sig),ctypes.byref(siglen), ctypes.byref(m), mlen, ctypes.byref(sk))

    return bytes(sig[:siglen.value])

def verify(s: bytes, message: bytes, public_key: bytes, version: str = 'ref', nist_security_level: int = 3, aes=False) -> bool:
    # aes -> version == 'avx2'
    lib = get_lib(version, nist_security_level, aes)
    f = lib.__getattr__(get_function_name(version, nist_security_level, aes, 'verify'))
    f.restype = ctypes.c_int

    sig = ctypes.create_string_buffer(s, len(s))
    siglen = ctypes.c_size_t(len(s))
    m = ctypes.create_string_buffer(message, len(message))
    mlen = ctypes.c_size_t(len(message))
    pk = ctypes.create_string_buffer(public_key, len(public_key))

    assert bytes(sig) == s
    assert bytes(m) == message
    assert bytes(pk) == public_key

    result = f(ctypes.byref(sig), siglen, ctypes.byref(m), mlen, ctypes.byref(pk))
    __logger.debug(f'siglen: {siglen};result: {result}')

    return result == 0