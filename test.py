import unittest

from dilithium import Dilithium
from dilithium.generic import _unpack_sig
import random
import numpy as np
import os

_TEST_SEED = b'this is a test'
_TEST_MESSAGE = b'this is a test message'


class TestDilithium(unittest.TestCase):

    def setUp(self):
        random.seed(_TEST_SEED)
        self.d2 = Dilithium(2)
        self.d3 = Dilithium(3)
        self.d5 = Dilithium(5)

        self.d2.pseudorandombytes_seed(_TEST_SEED)
        self.d3.pseudorandombytes_seed(_TEST_SEED)
        self.d5.pseudorandombytes_seed(_TEST_SEED)

        self.all = [self.d2, self.d3, self.d5]

    def test_generate_sign_verify(self):
        """
        Test that it can sum a list of integers
        """
        for d in self.all:
            pk, sk = d.keypair()
            signature = d.signature(_TEST_MESSAGE, sk)
            self.assertTrue(d.verify(signature, _TEST_MESSAGE, pk))

    def test_pack_unpack(self):
        poly = np.array(
            [-100330, 65070, 9596, 57850, 35652, 105533, -12476, -46863, -37129, -56173, -21068, 2324, 115540, 44633, 125101, 3586, 69993, -81687, -64128, 120572, 2307, 130526, 4041, -41650, 84699, -8418, 74822, 109619, -91410, -91558, 115894, 23794, 38581, 97367, -68344, 13693, -29260, -93738, 25493, 28466, -98993, -35421, -129186, -35972, -98782, 5229, 121668, -36138, 43042, 126578, -51112, -26829, 88126, -48827, -6483, 91640, 26814, 122947, 26573, 69248, 24721, -59507, 95958, 40139, -14569, 50396, -112991, -68730, 66400, -78235, -86549, -76860, 64682, -31281, -67048, -120548, -94141, -16141, -41256, -107494, 123510, 92927, -46082, -106954, 123712, -54074, -68055, -27761, 95540, -34279, 88614, -16752, -106508, 110918, -79361, -111904, -61989, -37948, -98516, -55493, 39202, -40934, -32598, 76273, 51232, -41914, 65442, -16213, 55769, 94113, 50226, 120092, -128689, -94408, -61484, -19585, -88952, -76813, 2824, 91206, -56337, -118806, -96835, 15049, 128028, 59495, -17594, -36106, 17150, 47484, 87598, -26352, -53032, -77067, -39068, 40578, 11118, -28570, 75283, -34653, -5989, 63604, -62640, 129983, 82192, -4490, 12561, -25277, -66376, -122930, 59076, -108514, 45386, -3452, -26574, 77009, 107691, 130619, 83009, -15992, 67954, -115355, 51392, 109151, 14436, 87167, 98658, 26737, -40221, -51762, 14194, -41174, 57083, 83262, -28556, -118523, -21025, 102215, -112607, 13209, 29419, 91941, -11896, 90350, 8775, 28083, -2437, -100647, 57982, -82079, 43127, -121490, 55338, -76765, -88055, 57275, 82896, 45758, 115959, 83102, 20486, 108583, 130356, 8121, 24164, 33415, 127913, -66700, 126187, -94234, -129363, 19066, 49679, -42788, -37787, 76823, 87773, -78390, -93583, 34618, 10559, 16455, 20048, -108818, 22738, -81005, -38836, 96902, 123986, -110533, 123344, -60505, -107167, 60008, 122648, 63987, -41240, -90385, -36204, 125741, 89346, -67624, 85577, -51871, -75793, 35865, 84258, -26867, -21851, -32105, -7085, -34076, -79382, 103232, -3429, 17899],
            dtype=np.int32
        )
        poly_packed = self.d2._polyz_pack(poly)
        poly_unpacked = self.d2._polyz_unpack(poly_packed)
        self.assertTrue(np.all(poly == poly_unpacked))
        for byte in poly_packed:
            print(f'{hex(byte)},', end='')
        print()
        print(poly_packed)

    def test_different_unpacks(self):
        sig_len = 2420
        pk, sk = self.d2.keypair()
        sig = self.d2.signature(_TEST_MESSAGE, sk)
        old_c, old_z, old_h = _unpack_sig(sig, nist_security_level=2)
        new_c, new_z, new_h = self.d2._unpack_sig(sig)
        print(old_z)
        print(new_z)
        print(type(new_z))
        assert np.all(old_z == new_z)

    def test_properties(self):
        self.assertEqual(self.d2.n, 256)
        self.assertEqual(self.d2.beta, 78)
        self.assertEqual(self.d2._polyz_unpack_num_iters, 64)
        self.assertEqual(self.d2.gamma1, 2 ** 17)
        self.assertEqual(self.d2.nist_security_level, 2)

    def test_poly_challange_no_crash(self):
        seedbytes_as_bytes = bytes(range(self.d2.seedbytes))
        c = self.d2._poly_challange(seedbytes_as_bytes)
        print('c poly below:')
        print(c)

    def test_unpack_sk(self):
        self.d2.pseudorandombytes_seed(b'attack-shuffling-countermeasure-keypair')
        pk, sk = self.d2.keypair()
        print(sk)
        rho, tr, key, t0, s1, s2 = self.d2._unpack_sk(sk)
        print(f's1 and s2 below')
        print(s1)#[[ 0  1  2 ...  2  1 -1]
        print(s2)

    def test_faulted(self):
        self.d2.pseudorandombytes_seed(b'attack-shuffling-countermeasure-keypair')
        pk, sk = self.d2.keypair()
        sig, num_rej = self.d2.signature_faulted(b'\x02', sk, 0, 0)
        self.assertEqual(num_rej, 0)
        _, z, _ = self.d2._unpack_sig(sig)
        print(f'faulted z (faults_max = {(np.sum(np.abs(z) <= self.d2.beta))}) below:')
        print(z)
        print(list(z[0]))
        self.assertTrue(np.sum(np.abs(z) <= self.d2.beta) >= (self.d2._polyz_unpack_num_iters - 1) * self.d2._polyz_unpack_coeffs_per_iter)

        no_rej_found = False
        for i in range(256):
            sig, num_rej = self.d2.signature_faulted(bytes([i]), sk, 0, 0)
            if num_rej == 0:
                no_rej_found = True
                break
        assert no_rej_found


if __name__ == '__main__':
    unittest.main()
