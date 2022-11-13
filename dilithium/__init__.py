import json
import os
import subprocess
import ctypes
import logging

from typing import Union

GIT_REPO_URL = 'GIT_REPO_URL'
GIT_BRANCH = 'GIT_BRANCH'
RANDOMBYTES_DEFINE = 'RANDOMBYTES_DEFINE'

DEFAULT_GIT_REPO_URL = 'https://github.com/pq-crystals/dilithium.git'
DEFAULT_GIT_BRANCH = 'master'
DEFAULT_RANDOMBYTES_DEFINE = "SOMETHING_NOT_DEFINED_HOPEFULLY=WHATEVER"

__cdlls = {}
__params = {2: {}, 3: {}, 5: {}}
__logger = logging.getLogger('io.github.alex1s.python-dilithium')

def setup(
        git_repo_url: Union[str, None] = None,
        git_branch: Union[str, None] = None,
        randombytes_define: Union[str, None] = None,
        overwrite_repo: bool = False
) -> None:
    global __cdlls, __params

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

    __logger.debug(''.join([git_repo_url,git_branch, randombytes_define]))

    git_path = '/tmp/python-dilithium-git-repo'
    if overwrite_repo:
        completed_process = subprocess.run(['rm', '-rf', git_path], capture_output=True, check=True)
        __logger.debug(completed_process)

    os.makedirs(git_path, exist_ok=True)

    completed_process = subprocess.run(['git', 'clone', '--branch', git_branch, git_repo_url, git_path], capture_output=True)
    assert(completed_process.returncode == 0 or b'already exists and is not an empty directory' in completed_process.stderr)
    __logger.debug(completed_process)

    ref_path = os.path.join(git_path, 'ref')
    avx2_path = os.path.join(git_path, 'avx2')


    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared'], cwd=ref_path, capture_output=True, check=True)
    __logger.debug(completed_process)

    completed_process = subprocess.run(['/usr/bin/env', 'gcc', '-shared', '-fPIC', f'-D{randombytes_define}', '-o', 'libpqcrystals_randombytes_ref.so', 'randombytes.c'], cwd=ref_path, capture_output=True, check=True)
    __logger.debug(completed_process)

    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared'], cwd=avx2_path, capture_output=True, check=True)
    __logger.debug(completed_process)

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
        __logger.debug(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)

    # load radombytes as it might depend on fips
    randombytes_paths = set(filter(lambda path: 'randombytes' in path, all_so_paths))
    for so_path in randombytes_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        __logger.debug(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)
    all_so_paths -= randombytes_paths

    all_so_paths -= fips202_non_avx2_paths

    leave_so_paths = set(filter(lambda path: 'aes256ctr' in path or 'fips202' in path or 'randombytes' in path, all_so_paths))
    for so_path in leave_so_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        __logger.debug(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)

    all_so_paths -= leave_so_paths
    for so_path in all_so_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        __logger.debug(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path)

    # api_path = os.path.join(ref_path, 'api.h')
    # completed_process = subprocess.run(['gcc', '-E', '-dM' , api_path], check=True, capture_output=True)
    # output = completed_process.stdout.decode()
    # lines = output.split('\n')
    # table = map(lambda line: line.split(' '), lines)
    # filtered_table = filter(lambda row: len(row) == 3 and row[2].isdigit() and 'pqcrystals' in row[1], table)
    # __defines = {row[1]: int(row[2]) for row in filtered_table}
    # __logger.debug(__defines)

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
        __logger.debug(completed_process)
        completed_process = subprocess.run([dump_params_path], check=True, capture_output=True, cwd=ref_path)
        __params[mode] = json.loads(completed_process.stdout.decode())
        __logger.debug(__params[mode])



setup()
