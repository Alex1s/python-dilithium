#!/usr/bin/env python3
import logging
logging.basicConfig(level=logging.DEBUG)
from dilithium.generic import keypair, signature, verify


def main() -> None:
    secret_key, public_key = keypair()
    message = "this a test".encode()
    sig = signature(message, secret_key)
    print(len(sig)) # 'pqcrystals_dilithium3_BYTES': 3293
    print(sig)

    verify_correct = verify(sig, message, public_key)
    verify_wrong = verify(sig, 'wrong'.encode(), public_key)

    print(f'correct: {verify_correct}; wrong: {verify_wrong}')

    assert verify_correct
    assert not verify_wrong



if __name__ == '__main__':
    main()
