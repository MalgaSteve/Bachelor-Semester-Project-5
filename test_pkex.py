from spake2.PKEX import PKEX_A
from spake2.PKEX import PKEX_B

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import time

start_time = time.time()

for i in range(10):
    temp = "our password"
    s_a = PKEX_A(b"our password{i}")
    s_b = PKEX_B(b"our password{i}")
    
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

end_time = time.time()
print(f"Execution time: {end_time - start_time:.5f} seconds")
