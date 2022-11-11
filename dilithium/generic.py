import ctypes
from typing import Tuple
from ctypes import CDLL

from . import __cdlls
from . import __defines
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
    function = lib.__getattr__(get_function_name(version, nist_security_level, aes, 'keypair'))

    __logger.debug(__defines)
    pk_buf_len = __defines[get_define_name(nist_security_level, 'PUBLICKEYBYTES')]
    sk_buf_len = __defines[get_define_name(nist_security_level, 'SECRETKEYBYTES')]

    pk_buf = (ctypes.c_uint8 * pk_buf_len)()
    sk_buf = (ctypes.c_uint8 * sk_buf_len)()

    function(ctypes.pointer(pk_buf), ctypes.pointer(sk_buf))

    return bytes(pk_buf), bytes(sk_buf)