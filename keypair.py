#!/usr/bin/env python3
import logging
logging.basicConfig(level=logging.DEBUG)

import dilithium.generic

def main() -> None:
    print(dilithium.generic.keypair())

if __name__ == '__main__':
    main()