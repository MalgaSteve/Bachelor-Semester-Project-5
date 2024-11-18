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

from . import ed25519_basic
from .groups import password_to_scalar

class _Ed25519Group:
    def random_scalar(self, entropy_f):
        return ed25519_basic.random_scalar(entropy_f)
    def scalar_to_bytes(self, i):
        return ed25519_basic.scalar_to_bytes(i)
    def bytes_to_scalar(self, b):
        return ed25519_basic.bytes_to_scalar(b)
    def password_to_scalar(self, pw):
        return password_to_scalar(pw, self.scalar_size_bytes, self.order())
    def arbitrary_element(self, seed):
        return ed25519_basic.arbitrary_element(seed)
    def bytes_to_element(self, b):
        return ed25519_basic.bytes_to_element(b)
    def order(self):
        return ed25519_basic.L

Ed25519Group = _Ed25519Group()
Ed25519Group.Base = ed25519_basic.Base
Ed25519Group.Zero = ed25519_basic.Zero
Ed25519Group.scalar_size_bytes = 32
Ed25519Group.element_size_bytes = 32
