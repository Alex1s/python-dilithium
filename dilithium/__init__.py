import os
import subprocess
import ctypes
import logging

from typing import Dict

__cdlls = {}
__defines = {}
__logger = logging.getLogger('io.github.alex1s.python-dilithium')

def setup(git_repo_url='https://github.com/pq-crystals/dilithium.git', git_branch='master', version='ref', overwrite_repo=False, make_env: Dict[str, str] = None) -> None:
    global __cdlls, __defines
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


    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared', 'libpqcrystals_randombytes_ref.so'], cwd=ref_path, capture_output=True, check=True, env=None if make_env is None else {**os.environ, **make_env})
    __logger.debug(completed_process)

    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared'], cwd=avx2_path, capture_output=True, check=True, env=None if make_env is None else {**os.environ, **make_env})
    __logger.debug(completed_process)

    ref_so_paths = [dir_entry.path for dir_entry in os.scandir(ref_path) if dir_entry.name.endswith('.so')]
#    __logger.debug(ref_so_paths)

    avx2_so_paths = [dir_entry.path for dir_entry in os.scandir(avx2_path) if dir_entry.name.endswith('.so')]
#    __logger.debug(avx2_so_paths)

#    __logger.debug([os.path.splitext(os.path.split(path)[1])[0] for path in  ref_so_paths])
#    __logger.debug([os.path.splitext(os.path.split(path)[1])[0] for path in  avx2_so_paths])

    all_so_paths = set(ref_so_paths + avx2_so_paths)

    fips202_non_avx2_paths = set(filter(lambda path: 'fips202x4' not in path and 'fips202' in path, all_so_paths))
    for so_path in fips202_non_avx2_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        __logger.debug(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)

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

    __logger.debug(__cdlls)

    api_path = os.path.join(ref_path, 'api.h')
    completed_process = subprocess.run(['gcc', '-E', '-dM' , api_path], check=True, capture_output=True)
    output = completed_process.stdout.decode()
    lines = output.split('\n')
    table = map(lambda line: line.split(' '), lines)
    filtered_table = filter(lambda row: len(row) == 3 and row[2].isdigit() and 'pqcrystals' in row[1], table)
    __defines = {row[1]: int(row[2]) for row in filtered_table}
    __logger.debug(__defines)



setup()
