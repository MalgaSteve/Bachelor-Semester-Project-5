from spake2.POP import I_PKEX_A
from spake2.POP import I_PKEX_B

s_a = I_PKEX_A(b"our password")
s_b = I_PKEX_B(b"our password")

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

msg_out_a_ipkex = s_a.start_pkex(key_a)
print("Message out -------> ", msg_out_a_ipkex)

msg_out_b_ipkex = s_b.start_pkex(key_b)
print("Message out -------> ", msg_out_b_ipkex)


finished_a = s_a.finalize(key_a, msg_out_b_ipkex)
print("Finished a -------> ", finished_a)
finished_b = s_b.finalize(key_b, msg_out_a_ipkex)
print("Finished b -------> ", finished_b)

if finished_a and finished_b:
    print("Successful exchange!")
else:
    print("Unsuccessful!!")
