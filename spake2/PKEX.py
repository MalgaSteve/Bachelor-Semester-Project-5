from spake2 import *

import os, json
from binascii import hexlify, unhexlify
from hashlib import sha256
from .params import _Params
from .parameters.ed25519 import ParamsEd25519
from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

class PKEXError(Exception):
    pass
class RunSpakeFirst(PKEXError):
    """ start_pkex() may only be called when spake is already finished """
class DecryptionFailed(PKEXError):
    """Decryption failed"""

class PKEX(SPAKE2_Asymmetric):
    def start_pkex(self, key):
        if not self._finished: 
            raise RunSpakeFirst("start_pkex() may only be called when SPAKE2 protocol is finished running")

        g = self.params.group

        # inbound_element is public key A (pA)
        inbound_elem = g.bytes_to_element(self.inbound_message) 

        # select random element a
        self.ab_scalar = g.random_scalar(self.entropy_f)
        self.AB_element = g.Base.scalarmult(self.ab_scalar)


        # pw_blinding = M or N * pw
        pw_unblinding = self.my_unblinding().scalarmult(-self.pw_scalar)
        self.opposite_element = inbound_elem.add(pw_unblinding)
        # element_to_send is ab_scalar * Y
        self.element_to_send = self.opposite_element.scalarmult(self.ab_scalar)
        data_to_authenticate = (self.element_to_send.to_bytes() + self.side +
                                self.AB_element.to_bytes() + 
                                self.opposite_element.to_bytes() +
                                self.xy_elem.to_bytes())


        self.u = self.hmac_f(key, data_to_authenticate).finalize()

        assert len(self.u) == 32, len(self.u)

        message = self.u + self.AB_element.to_bytes()

        # associated data?
        encrypted_data = self.encrypt_message(message, key)
        return encrypted_data

    def finalize(self, key, data):
        input_data = self.decrypt_message(data, key)

        input_hmac = input_data[:32]
        A_in_bytes = input_data[32:]

        g = self.params.group
        AB_element = g.bytes_to_element(A_in_bytes)

        self.shared_element = AB_element.scalarmult(self.xy_scalar)

        if self.side == b"A":
            in_side = b"B"
        elif self.side == b"B":
            in_side = b"A"

        data_to_authenticate = (self.shared_element.to_bytes()
                                    + in_side
                                    + AB_element.to_bytes()
                                    + self.xy_elem.to_bytes()
                                    + self.opposite_element.to_bytes())

        assert input_hmac != None
        self.u_check = self.hmac_f(key, data_to_authenticate)
        self.u_check.verify(input_hmac)

        return True

    def hmac_f(self, key, data):
        h = hmac.HMAC(key, algorithm=hashes.SHA256())
        h.update(data)
        return h
    
    def encrypt_message(self, data, key):
        if (self.side == b'A'):
            associated_data = [b'\x00']
        elif (self.side == b'B'):
            associated_data = [b'\x11']
        aessiv = AESSIV(key)
        return aessiv.encrypt(data, associated_data)
    
    def decrypt_message(self, data, key):
        if (self.side == b'A'):
            associated_data = [b'\x11']
        elif (self.side == b'B'):
            associated_data = [b'\x00']
        aessiv = AESSIV(key)
        return aessiv.decrypt(data, associated_data)

class PKEX_A(PKEX):
    side = b"A"
    def my_blinding(self): return self.params.M
    def my_unblinding(self): return self.params.N
    def X_msg(self): return self.outbound_message
    def Y_msg(self): return self.inbound_message

class PKEX_B(PKEX):
    side = b"B"
    def my_blinding(self): return self.params.N
    def my_unblinding(self): return self.params.M
    def X_msg(self): return self.inbound_message
    def Y_msg(self): return self.outbound_message
