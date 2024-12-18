# "python-spake2" Copyright (c) 2015 Brian Warner
# 
# The MIT License (MIT)
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os, binascii, math

def size_bits(maxval):
    if hasattr(maxval, "bit_length"): # python-2.7 or 3.x
        return maxval.bit_length() or 1
    # 2.6
    return len(bin(maxval)) - 2

def size_bytes(maxval):
    return int(math.ceil(size_bits(maxval) / 8))

def number_to_bytes(num, maxval):
    if num > maxval:
        raise ValueError
    num_bytes = size_bytes(maxval)
    fmt_str = "%0" + str(2*num_bytes) + "x"
    s_hex = fmt_str % num
    s = binascii.unhexlify(s_hex.encode("ascii"))
    assert len(s) == num_bytes
    assert isinstance(s, type(b""))
    return s

def bytes_to_number(s):
    if not isinstance(s, type(b"")):
        raise TypeError
    return int(binascii.hexlify(s), 16)

def generate_mask(maxval):
    num_bytes = size_bytes(maxval)
    num_bits = size_bits(maxval)
    leftover_bits = num_bits % 8
    if leftover_bits:
        top_byte_mask_int = (0x1 << leftover_bits) - 1
    else:
        top_byte_mask_int = 0xff
    assert 0 <= top_byte_mask_int <= 0xff
    return (top_byte_mask_int, num_bytes)

def random_list_of_ints(count, entropy_f=os.urandom):
    # return a list of ints, each 0<=x<=255, for masking
    return list(iter(entropy_f(count)))
def mask_list_of_ints(top_byte_mask_int, list_of_ints):
    return [top_byte_mask_int & list_of_ints[0]] + list_of_ints[1:]
def list_of_ints_to_number(l):
    s = "".join(["%02x" % b for b in l])
    return int(s, 16)

def unbiased_randrange(start, stop, entropy_f):
    """Return a random integer k such that start <= k < stop, uniformly
    distributed across that range, like random.randrange but
    cryptographically bound and unbiased.

    r(0,p) provides a random group element of the integer group Zp.
    r(1,p) provides a random group element of the integer group Zp*.
    """

    # we generate a random binary string up to 7 bits larger than we really
    # need, mask that down to be the right number of bits, then compare
    # against the range and try again if it's wrong. This will take a random
    # number of tries, but on average less than two

    # first we get 0<=number<(stop-start)
    maxval = stop - start

    top_byte_mask_int, num_bytes = generate_mask(maxval)
    while True:
        enough_bytes = random_list_of_ints(num_bytes, entropy_f)
        assert len(enough_bytes) == num_bytes
        candidate_bytes = mask_list_of_ints(top_byte_mask_int, enough_bytes)
        candidate_int = list_of_ints_to_number(candidate_bytes)
        #print ["0x%02x" % b for b in candidate_bytes], candidate_int
        if candidate_int < maxval:
            return start + candidate_int
