import json
import os
import subprocess
import ctypes
import logging
import ctypes
import numpy as np

from typing import Union

GIT_REPO_URL = 'GIT_REPO_URL'
GIT_BRANCH = 'GIT_BRANCH'
RANDOMBYTES_DEFINE = 'RANDOMBYTES_DEFINE'

GIT_PATH = '/tmp/python-dilithium-git-repo'

DEFAULT_GIT_REPO_URL = 'https://github.com/pq-crystals/dilithium.git'
DEFAULT_GIT_BRANCH = 'master'
DEFAULT_RANDOMBYTES_DEFINE = "SOMETHING_NOT_DEFINED_HOPEFULLY=WHATEVER"

__name__ = 'dilithium'
__package__ = 'dilithium'

_cdlls = {}
_params = {2: {}, 3: {}, 5: {}}
_logger = logging.getLogger('io.github.alex1s.python-dilithium')

def setup(
        git_repo_url: Union[str, None] = None,
        git_branch: Union[str, None] = None,
        randombytes_define: Union[str, None] = None,
) -> None:
    global _cdlls, _params

    if git_repo_url is None and GIT_REPO_URL in os.environ:
        git_repo_url = os.environ[GIT_REPO_URL]
    elif git_repo_url is None:
        git_repo_url = DEFAULT_GIT_REPO_URL

    if git_branch is None and GIT_BRANCH in os.environ:
        git_branch = os.environ[GIT_BRANCH]
    elif git_branch is None:
        git_branch = DEFAULT_GIT_BRANCH

    if randombytes_define is None and RANDOMBYTES_DEFINE in os.environ:
        randombytes_define = os.environ[RANDOMBYTES_DEFINE]
    elif randombytes_define is None:
        randombytes_define = DEFAULT_RANDOMBYTES_DEFINE

    _logger.debug(' '.join([git_repo_url, git_branch, randombytes_define]))

    os.makedirs(GIT_PATH, exist_ok=True)

    completed_process = subprocess.run(['git', 'clone', '--branch', git_branch, git_repo_url, GIT_PATH], capture_output=True)
    assert(completed_process.returncode == 0 or b'already exists and is not an empty directory' in completed_process.stderr)
    _logger.debug(completed_process)

    ref_path = os.path.join(GIT_PATH, 'ref')
    avx2_path = os.path.join(GIT_PATH, 'avx2')


    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared'], cwd=ref_path, capture_output=True, check=True)
    _logger.debug(completed_process)

    completed_process = subprocess.run(['/usr/bin/env', 'gcc', '-shared', '-fPIC', f'-D{randombytes_define}', '-o', 'libpqcrystals_randombytes_ref.so', 'randombytes.c'], cwd=ref_path, capture_output=True, check=True)
    _logger.debug(completed_process)

    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared'], cwd=avx2_path, capture_output=True, check=True)
    _logger.debug(completed_process)

    ref_so_paths = [dir_entry.path for dir_entry in os.scandir(ref_path) if dir_entry.name.endswith('.so')]
#    __logger.debug(ref_so_paths)

    avx2_so_paths = [dir_entry.path for dir_entry in os.scandir(avx2_path) if dir_entry.name.endswith('.so')]
#    __logger.debug(avx2_so_paths)

#    __logger.debug([os.path.splitext(os.path.split(path)[1])[0] for path in  ref_so_paths])
#    __logger.debug([os.path.splitext(os.path.split(path)[1])[0] for path in  avx2_so_paths])

    all_so_paths = set(ref_so_paths + avx2_so_paths)

    # load the non avx3 version of fips
    fips202_non_avx2_paths = set(filter(lambda path: 'fips202x4' not in path and 'fips202' in path, all_so_paths))
    for so_path in fips202_non_avx2_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        _logger.debug(f'Loading {name}')
        _cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)

    # load radombytes as it might depend on fips
    randombytes_paths = set(filter(lambda path: 'randombytes' in path, all_so_paths))
    for so_path in randombytes_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        _logger.debug(f'Loading {name}')
        _cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)
    all_so_paths -= randombytes_paths

    all_so_paths -= fips202_non_avx2_paths

    leave_so_paths = set(filter(lambda path: 'aes256ctr' in path or 'fips202' in path or 'randombytes' in path, all_so_paths))
    for so_path in leave_so_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        _logger.debug(f'Loading {name}')
        _cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)

    all_so_paths -= leave_so_paths
    for so_path in all_so_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        _logger.debug(f'Loading {name}')
        _cdlls[name] = ctypes.CDLL(so_path)

    # load params
    current_path = os.path.dirname(__file__)
    dump_params_c_path = os.path.join(current_path, 'dump_params.c')
    dump_params_source = open(dump_params_c_path, 'rb').read()
    dump_params_path = os.path.join(ref_path, 'dump_params')
    for mode in [2, 3, 5]:
        completed_process = subprocess.run(
            # gcc -x c -o dump_params.c -
            ['/usr/bin/env', 'gcc', '-x', 'c', f'-DDILITHIUM_MODE={mode}', '-o', 'dump_params', '-'],
            check=True,
            cwd=ref_path,
            capture_output=True,
            input=dump_params_source
        )
        _logger.debug(completed_process)
        completed_process = subprocess.run([dump_params_path], check=True, capture_output=True, cwd=ref_path)
        _params[mode] = json.loads(completed_process.stdout.decode())
        _logger.debug(_params[mode])

        n = _params[mode]['N']
        l = _params[mode]['L']
        k = _params[mode]['K']

        class poly(ctypes.Structure):
            _fields_ = [
                ('coeffs', n * ctypes.c_int32)
            ]

        class polyvecl(ctypes.Structure):
            _fields_ = [
                ('vec', l * poly)
            ]

        class polyveck(ctypes.Structure):
            _fields_ = [
                ('vec', k * poly)
            ]

        _params[mode]['poly'] = poly
        _params[mode]['polyvecl'] = polyvecl
        _params[mode]['polyveck'] = polyveck

setup()


class Dilithium:
    @property
    def n(self) -> int:
        return self.__params['N']

    @property
    def eta(self) -> int:
        return self.__params['ETA']

    @property
    def tau(self) -> int:
        return self.__params['TAU']

    @property
    def beta(self) -> int:
        return self.eta * self.tau

    @property
    def _polyz_unpack_coeffs_per_iter(self) -> int:
        if self.__nist_security_level == 3 or self.__nist_security_level == 5:
            return 2
        elif self.__nist_security_level == 2:
            return 4
        else:
            assert False

    @property
    def _polyz_unpack_num_iters(self) -> int:
        return self.n // self._polyz_unpack_coeffs_per_iter

    @property
    def seedbytes(self) -> int:
        return self.__params['SEEDBYTES']

    def __init__(self, nist_security_level: int = 3, version: str = 'ref', aes: bool = False):
        assert version in ['ref', 'avx2']
        assert nist_security_level in [2, 3, 5]
        if aes:
            assert version == 'avx2'

        self.__version = version
        self.__nist_security_level = nist_security_level
        self.__aes = aes

        self.__lib = _cdlls['lib' + self.__get_base()]
        self.__lib_randombytes_ref = _cdlls['libpqcrystals_randombytes_ref']
        self.__params = _params[self.__nist_security_level]

        # load defines
        self.__CRYPTO_PUBLICKEYBYTES = self.__params['CRYPTO_PUBLICKEYBYTES']
        self.__CRYPTO_SECRETKEYBYTES = self.__params['CRYPTO_SECRETKEYBYTES']
        self.__CRYPTO_BYTES = self.__params['CRYPTO_BYTES']
        self._N = self.__params['N']
        self._L = self.__params['L']
        self._K = self.__params['K']
        self.__POLYZ_PACKEDBYTES = self.__params['POLYZ_PACKEDBYTES']
        self.__SEEDBYTES = self.__params['SEEDBYTES']

        # load types
        self.__pk_t = self.__CRYPTO_PUBLICKEYBYTES * ctypes.c_uint8
        self.__sk_t = self.__CRYPTO_SECRETKEYBYTES * ctypes.c_uint8
        self.__sig_t = self.__CRYPTO_BYTES * ctypes.c_uint8
        self.__poly_packed_t = self.__POLYZ_PACKEDBYTES * ctypes.c_uint8
        self.__c_t = self.__SEEDBYTES * ctypes.c_uint8

        class poly(ctypes.Structure):
            _fields_ = [
                ('coeffs', self._N * ctypes.c_int32)
            ]
        self.__poly_t = poly

        class polyvecl(ctypes.Structure):
            _fields_ = [
                ('vec', self._L * poly)
            ]
        self.__polyvecl_t = polyvecl

        class polyveck(ctypes.Structure):
            _fields_ = [
                ('vec', self._K * poly)
            ]
        self.__polyveck_t = polyveck

        # load functions
        self.__keypair = self.__lib.__getattr__(self.__get_function_name('keypair'))
        self.__keypair.restype = ctypes.c_int
        self.__keypair.argtypes = [self.__pk_t, self.__sk_t]

        self.__signature = self.__lib.__getattr__(self.__get_function_name('signature'))
        self.__signature.restype = ctypes.c_int
        self.__signature.argtypes = [
            self.__sig_t,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            self.__sk_t
        ]

        self.__verify = self.__lib.__getattr__(self.__get_function_name('verify'))
        self.__verify.restype = ctypes.c_int
        self.__verify.argtypes = [
            self.__sig_t,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            self.__pk_t
        ]

        self.__polyz_unpack = self.__lib.__getattr__(self.__get_function_name('polyz_unpack'))
        self.__polyz_unpack.restype = None
        self.__polyz_unpack.argtypes = [ctypes.POINTER(self.__poly_t), ]

        self.__unpack_sig = self.__lib.__getattr__(self.__get_function_name('unpack_sig'))
        self.__unpack_sig.restype = ctypes.c_int
        self.__unpack_sig.argtypes = [
            self.__c_t,
            ctypes.POINTER(self.__polyvecl_t),
            ctypes.POINTER(self.__polyveck_t),
            self.__sig_t
        ]

        self.__pseudorandombytes_seed = self.__lib_randombytes_ref.pseudorandombytes_seed
        self.__pseudorandombytes_seed.restype = None
        self.__pseudorandombytes_seed.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        self.__polyz_pack = self.__lib.__getattr__(self.__get_function_name('polyz_pack'))
        self.__polyz_pack.restype = None
        self.__polyz_pack.argtypes = [self.__POLYZ_PACKEDBYTES * ctypes.c_uint8, ctypes.POINTER(self.__poly_t)]

        self.__poly_challenge = self.__lib.__getattr__(self.__get_function_name('poly_challenge'))
        self.__poly_challenge.restype = None
        self.__poly_challenge.argtypes = [ctypes.POINTER(self.__poly_t), self.seedbytes * ctypes.c_uint8]

    def __get_base(self, ) -> str:
        base = f'pqcrystals_dilithium{self.__nist_security_level}{"aes" if self.__aes else ""}_{self.__version}'
        return base

    def __get_function_name(self, name: str) -> str:
        base = self.__get_base()
        symbol_name = base + '_' + name
        return symbol_name

    def __get_define_name(self, name: str) -> str:
        return f'pqcrystals_dilithium{self.__nist_security_level}_{name}'

    def keypair(self) -> (bytes, bytes):
        pk = self.__pk_t()
        sk = self.__sk_t()

        ret = self.__keypair(pk, sk)
        assert ret == 0

        return bytes(list(pk)), bytes(list(sk))

    def signature(self, message: bytes, secret_key: bytes) -> bytes:
        assert len(secret_key) == self.__CRYPTO_SECRETKEYBYTES

        sig = self.__sig_t()
        siglen = ctypes.c_size_t()
        m = (len(message) * ctypes.c_uint8)(*message)
        mlen = ctypes.c_size_t(len(m))
        sk = self.__sk_t(*secret_key)

        ret = self.__signature(
            sig,
            ctypes.byref(siglen),
            ctypes.cast(ctypes.byref(m), ctypes.POINTER(ctypes.c_uint8)),
            mlen,
            sk
        )
        assert ret == 0
        assert siglen.value == self.__CRYPTO_BYTES

        return bytes(list(sig))

    def verify(self, s: bytes, message: bytes, public_key: bytes) -> bool:
        assert len(s) == self.__CRYPTO_BYTES
        assert len(public_key) == self.__CRYPTO_PUBLICKEYBYTES

        sig = self.__sig_t(*s)
        siglen = ctypes.c_size_t(len(s))
        m = (len(message) * ctypes.c_uint8)(*message)
        mlen = ctypes.c_size_t(len(message))
        pk = self.__pk_t(*public_key)

        res = self.__verify(sig, siglen, ctypes.cast(m, ctypes.POINTER(ctypes.c_uint8)), mlen, pk)

        return res == 0

    def _polyz_unpack(self, packed_poly: bytes) -> np.ndarray:
        assert len(packed_poly) == self.__POLYZ_PACKEDBYTES

        r = self.__poly_t()
        a = self.__poly_packed_t(*packed_poly)
        self.__polyz_unpack(ctypes.byref(r), a)

        return np.array(r.coeffs)

    def _polyz_pack(self, poly: np.ndarray):
        assert poly.dtype == np.int32
        assert np.shape(poly) == (self._N,)

        r = (self.__POLYZ_PACKEDBYTES * ctypes.c_uint8)()
        a = self.__poly_t()
        a.coeffs = (self._N * ctypes.c_int32)(*poly)
        self.__polyz_pack(r, ctypes.byref(a))

        return bytes(list(r))


    def _unpack_sig(self, s: bytes) -> (bytes, np.ndarray, np.ndarray):
        assert len(s) == self.__CRYPTO_BYTES

        c = self.__c_t()
        z = self.__polyvecl_t()
        h = self.__polyveck_t()
        sig = self.__sig_t(*s)
        res = self.__unpack_sig(c, ctypes.byref(z), ctypes.byref(h), sig)
        assert res == 0

        return_z = np.vstack([np.array(list(z.vec[i].coeffs)) for i in range(self._L)])
        return_h = np.vstack([np.array(list(z.vec[i].coeffs)) for i in range(self._K)])

        return bytes(list(c)), return_z, return_h

    def _unpack_sig_full(self, s: bytes) -> (np.ndarray, np.ndarray, np.ndarray):
        challenge_seedbytes, z, h = self._unpack_sig(s)
        challenge = self._poly_challange(challenge_seedbytes)

        return challenge, z, h

    def pseudorandombytes_seed(self, new_seed: bytes) -> None:
        seed = (len(new_seed) * ctypes.c_uint8)(*new_seed)
        seedlen = ctypes.c_size_t(len(new_seed))

        self.__pseudorandombytes_seed(
            ctypes.cast(seed, ctypes.POINTER(ctypes.c_uint8)),
            seedlen
        )

    def _poly_challange(self, seed_as_bytes: bytes) -> np.ndarray:
        if not (type(seed_as_bytes) is bytes and len(seed_as_bytes) == self.seedbytes):
            raise ValueError()

        c = self.__poly_t()
        seed = (self.seedbytes * ctypes.c_uint8)(*seed_as_bytes)
        print('before call')
        self.__poly_challenge(ctypes.byref(c), seed)
        print('after call')

        return np.array(c.coeffs)

