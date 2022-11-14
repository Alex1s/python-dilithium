#!/usr/bin/env python3
import logging
logging.basicConfig(level=logging.DEBUG)
from dilithium.generic import keypair, signature, verify, _unpack_sig


def main() -> None:
    public_key, secret_key  = keypair()
    message = "this a test".encode()
    sig = signature(message, secret_key)
    logging.debug(len(sig)) # 'pqcrystals_dilithium3_BYTES': 3293
    logging.debug(sig)

    verify_correct = verify(sig, message, public_key)
    verify_wrong = verify(sig, 'wrong'.encode(), public_key)

    logging.debug(f'correct: {verify_correct}; wrong: {verify_wrong}')

    assert verify_correct
    assert not verify_wrong

    c, z, h = _unpack_sig(sig)

    print('Done!')

if __name__ == '__main__':
    main()
