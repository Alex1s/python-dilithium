import os
import subprocess
import ctypes

__cdlls = {}

def setup(git_repo_url='https://github.com/pq-crystals/dilithium.git', git_branch='master', version='ref', overwrite_repo=False) -> None:
    module_path = os.path.dirname(__file__)
    git_path = os.path.join(module_path, 'dilithium')

    if overwrite_repo:
        completed_process = subprocess.run(['rm', '-rf', git_path], capture_output=True, check=True)
        print(completed_process)

    completed_process = subprocess.run(['git', 'clone', '--branch', git_branch, git_repo_url, git_path], capture_output=True)
    assert(completed_process.returncode == 0 or b'already exists and is not an empty directory' in completed_process.stderr)
    print(completed_process)

    ref_path = os.path.join(git_path, 'ref')
    avx2_path = os.path.join(git_path, 'avx2')


    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared'], cwd=ref_path, capture_output=True, check=True)
    print(completed_process)

    completed_process = subprocess.run(['/usr/bin/env', 'make', 'shared'], cwd=avx2_path, capture_output=True, check=True)
    print(completed_process)

    ref_so_paths = [dir_entry.path for dir_entry in os.scandir(ref_path) if dir_entry.name.endswith('.so')]
#    print(ref_so_paths)

    avx2_so_paths = [dir_entry.path for dir_entry in os.scandir(avx2_path) if dir_entry.name.endswith('.so')]
#    print(avx2_so_paths)

#    print([os.path.splitext(os.path.split(path)[1])[0] for path in  ref_so_paths])
#    print([os.path.splitext(os.path.split(path)[1])[0] for path in  avx2_so_paths])

    all_so_paths = set(ref_so_paths + avx2_so_paths)

    fips202_non_avx2_paths = set(filter(lambda path: 'fips202x4' not in path and 'fips202' in path, all_so_paths))
    for so_path in fips202_non_avx2_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        print(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)

    all_so_paths -= fips202_non_avx2_paths

    leave_so_paths = set(filter(lambda path: 'aes256ctr' in path or 'fips202' in path or 'randombytes' in path, all_so_paths))
    for so_path in leave_so_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        print(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path, mode=ctypes.RTLD_GLOBAL)

    all_so_paths -= leave_so_paths
    for so_path in all_so_paths:
        name = os.path.splitext(os.path.split(so_path)[1])[0]
        print(f'Loading {name}')
        __cdlls[name] = ctypes.CDLL(so_path)

    print(__cdlls)

setup(git_repo_url='https://github.com/Alex1s/dilithium.git', git_branch='attack-shuffling-countermeasure')
