from ./spake2 import *

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
    def __init__(self, password, idA=b"", idB=b"", params=DefaultParams,
                 entropy_f=os.urandom):
        SPAKE2_Asymmetric.__init(self, password, params=params,
                                 entropy_f=entropy_f)
    
    def start_pkex(self, key):
        if not self._finished: 
            raise RunSpakeFirst("start_pkex() may only be called when SPAKE2 protocol is finished running")

        g = self.params.group
        
        # inbound_element is public key A (pA)
        inbound_elem = g.bytes_to_element(self.inbound_message) 

        # select random element a
        self.ab_scalar = g.random_scalar(self.entropy_f)
        self.AB_element = g.Base.scalarmult(self.A_scalar)

        # pw_blinding = M or N * pw
        pw_unblinding =
                self.my_unblinding().scalarmult(self.pw_scalar)
        self.opposing_element = inbound_elem.add(- pw_unbinding)
        # element_to_send is ab_scalar * Y
        self.element_to_send = opposing_element.scalarmult(self.ab_scalar)
        data_to_authenticate = self.element_to_send.to_bytes() + side +
            self.AB_element.to_bytes() + self.opposing_element.to_bytes() +
            self.xy_elem.to_bytes() 


        self.h = hmac(data_to_authenticate)
        self.u = self.h.finalize()

        # associated data?
        encrypted_data = encrypt_message(self.u + self.AB_element, key)

        return encrypted_data

    def finalize(self, key, data):
        input_data = decrypt_message(data, key)

        input_hmac = input_data[:256]
        A_in_bytes = input_data[256:]

        g = self.params.group
        AB_element = g.bytes_to_element(A_in_bytes)
        self.shared_element = AB_element.scalarmult()

        data_to_authenticate = self.shared_element.to_bytes() + side
                                    + AB_element.to_bytes() + self.xy_elem.to_bytes()
                                    + self.opposing_element.to_bytes()
        self.u_check = hmac(data_to_authenticate)
        self.u_check.verify(input_hmac)
        self.u_check.finalize()

    def hmac(data):
        return hmac.HMAC(data, algorithm=hashes.SHA256())
    
    def encrypt_message(data, key):
        aessiv = aessiv.AESSIV(key)
        return AESSIV.encrypt_message(data)
    
    def decrypt_message(data, key):
        aessiv = aessiv.AESSIV(key)
        return AESSIV.decrypt_message(data)

class PKEX_A(PKEX)
    side = SideA

    def my_blinding(self): return self.params.M
    def my_unblinding(self): return self.params.N
    def X_msg(self): return self.outbound_message
    def Y_msg(self): return self.inbound_message

class PKEX_B(PKEX)
    side = SideB
    def my_blinding(self): return self.params.N
    def my_unblinding(self): return self.params.M
    def X_msg(self): return self.inbound_message
    def Y_msg(self): return self.outbound_message
