#!/usr/bin/env python3
import logging
from typing import Tuple

logging.basicConfig(level=logging.DEBUG)

import dilithium
import dilithium.generic
from dilithium import setup

def keypair() -> Tuple[bytes, bytes]:
    setup(
        git_repo_url='https://github.com/Alex1s/dilithium.git',
        git_branch='attack-shuffling-countermeasure',
        make_env={'RANDOMBYTES_SEED': 'attack-shuffling-countermeasure-keypair'},
        overwrite_repo=False
    )
    return dilithium.generic.keypair()



def main() -> None:
    print(keypair())


if __name__ == '__main__':
    main()