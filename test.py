from spake2 import SPAKE2_A
from spake2 import SPAKE2_B

s_a = SPAKE2_A(b"our password")
s_b = SPAKE2_B(b"our password")
msg_out_a = s_a.start()
msg_out_b = s_b.start()

print(msg_out_a)
print(msg_out_b)

key_a = s_a.finish(msg_out_b)
key_b = s_b.finish(msg_out_a)

assert key_a == key_b

print(key_a)
print(key_b)
