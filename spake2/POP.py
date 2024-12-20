from spake2 import *

import os, json
from binascii import hexlify, unhexlify
from hashlib import sha256
from .params import _Params
from .parameters.ed25519 import ParamsEd25519
from .ed25519_basic import L
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

class PKEXError(Exception):
    pass
class RunSpakeFirst(PKEXError):
    """ start_pkex() may only be called when spake is already finished """
class DecryptionFailed(PKEXError):
    """Decryption failed"""

class I_PKEX(SPAKE2_Asymmetric):

    def start_pkex(self, key):
        if not self._finished: 
            raise RunSpakeFirst("start_pkex() may only be called when SPAKE2 protocol is finished running")

        g = self.params.group

        sk = HKDF(
                algorithm=hashes.SHA256(),
                length=len(key)*3,
                salt=None,
                info=None,
                ).derive(key)

        split_size = len(sk) // 3
        sk1 = sk[:split_size]
        assert len(sk1) == split_size, len(sk1)
        sk2 = sk[split_size:2*split_size]
        assert len(sk2) == split_size, len(sk2)
        self.pake_id = sk[2*split_size:]
        assert len(self.pake_id) == split_size, len(self.pake_id)

        # inbound_element is public key A (pA)
        # inbound_elem = g.bytes_to_element(self.inbound_message) 

        # sk = a, pk = g * a = A
        self.ab_scalar = g.random_scalar(self.entropy_f)
        self.AB_element = g.Base.scalarmult(self.ab_scalar)

        # random k
        self.k = g.random_scalar(self.entropy_f)
        # print("ab_scalar: ", self.ab_scalar)
        # print("k", self.k)
        self.K_element = g.Base.scalarmult(self.k)

        self.e = hashes.Hash(hashes.SHA256())
        self.e.update(self.K_element.to_bytes() + self.AB_element.to_bytes() + self.pake_id)
        self.e = self.e.finalize()

        print("To be checked: ", self.e)
        self.e = g.password_to_scalar(self.e)
        
        print(self.k)
        self.s = (self.k + self.e * (-self.ab_scalar)) % L

        return (self.AB_element.to_bytes(), self.s, self.e)

    def finalize(self, key, data):
        g = self.params.group

        (AB_element, s, e) = data
        AB_element = g.bytes_to_element(AB_element) 

        g_s = g.Base.scalarmult(s)
        pk_e = AB_element.scalarmult(e)

        K_element_check = g_s.add(pk_e)
        e_check = hashes.Hash(hashes.SHA256())
        e_check.update(K_element_check.to_bytes() + AB_element.to_bytes() + self.pake_id)
        e_check = e_check.finalize()
        e_check = g.password_to_scalar(e_check)
        print("To be checked: ", e)
        print("Checking e: ", e_check)

        return e_check == e

class I_PKEX_A(I_PKEX):
    side = b"A"
    def my_blinding(self): return self.params.M
    def my_unblinding(self): return self.params.N
    def X_msg(self): return self.outbound_message
    def Y_msg(self): return self.inbound_message

class I_PKEX_B(I_PKEX):
    side = b"B"
    def my_blinding(self): return self.params.N
    def my_unblinding(self): return self.params.M
    def X_msg(self): return self.inbound_message
    def Y_msg(self): return self.outbound_message
