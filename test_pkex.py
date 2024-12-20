from spake2.PKEX import PKEX_A
from spake2.PKEX import PKEX_B

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

s_a = PKEX_A(b"our password")
s_b = PKEX_B(b"our password")

### SPAKE2 ===========================================================
msg_out_a = s_a.start()
msg_out_b = s_b.start()

print(msg_out_a)
print(msg_out_b)

key_a = s_a.finish(msg_out_b)
key_b = s_b.finish(msg_out_a)

assert key_a == key_b

print(key_a)
print(key_b)
print(len(key_a))

### PKEX =============================================================

msg_out_a_pkex = s_a.start_pkex(key_a)
print("Message out -------> ", msg_out_a_pkex)

msg_out_b_pkex = s_b.start_pkex(key_b)
print("Message out -------> ", msg_out_b_pkex)


finished_a = s_a.finalize(key_a, msg_out_b_pkex)
finished_b = s_b.finalize(key_b, msg_out_a_pkex)

if finished_a and finished_b:
    print("Successful exchange!")
