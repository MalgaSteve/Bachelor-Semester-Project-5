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

# M and N are defined as "randomly chosen elements of the group". It is
# important that nobody knows their discrete log (if your
# parameter-provider picked a secret 'haha' and told you to use
# M=pow(g,haha,p), you couldn't tell that M wasn't randomly chosen, but
# they could then mount an active attack against your PAKE session). S
# is the same, but used for both sides of a symmetric session.
#
# The safe way to choose these is to hash a public string.

class _Params:
    def __init__(self, group, M=b"M", N=b"N", S=b"symmetric"):
        self.group = group
        self.M = group.arbitrary_element(seed=M)
        self.N = group.arbitrary_element(seed=N)
        self.S = group.arbitrary_element(seed=S)
        self.M_str = M
        self.N_str = N
        self.S_str = S
