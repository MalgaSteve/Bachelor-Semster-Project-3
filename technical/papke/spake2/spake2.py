import os, json
from binascii import hexlify, unhexlify
from hashlib import sha256
import hashlib
import hmac
from hkdf import Hkdf
from .groups import Params3072, _Params

# Exceptions
class SPAKEError(Exception):
    pass


class OnlyCallStartOnce(SPAKEError):
    """start() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""

class OnlyCallComputeOnce(SPAKEError):
    """compute() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""

class OnlyCallFinishOnce(SPAKEError):
    """finish() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""


class OffSides(SPAKEError):
    """I received a message from someone on the same side that I'm on: I was
    expecting the opposite side."""


class WrongGroupError(SPAKEError):
    pass


class ReflectionThwarted(SPAKEError):
    """Someone tried to reflect our message back to us."""

class IncorrectCode(SPAKEError):
    """Someone sent wring confirmation code."""


SideA = b"A"
SideB = b"B"

DefaultParams = Params3072

# x = random(Zp)
# X = exp(g, x)
# X* = X * exp(M, int(pw))
#  y = random(Zp)
#  Y = exp(g, y)
#  Y* = Y * exp(N, int(pw))
# KA = exp(Y* + exp(N, -int(pw)), x)
# key = H(H(pw) + H(idA) + H(idB) + X* + Y* + KA)
# KB = exp(X* + exp(M, -int(pw)), y)
# key = H(H(pw) + H(idA) + H(idB) + X* + Y* + KB)


class PAPKE_A:
    "This class manages one side of a SPAKE2 key negotiation."

    side = SideA

    def M(self):
        return self.params.M

    def N(self):
        return self.params.N

    def X_msg(self):
        return self.outbound_message

    def Y_msg(self):
        return self.inbound_message

    def __init__(
        self,
        password,
        idA=b"",
        idB=b"",
        params=DefaultParams,
        entropy_f=os.urandom,
    ):

        self.pw = password
        self.pw_exponent = params.group.password_to_exponent(password)

        self.idA = idA
        self.idB = idB

        self.params = params
        self.entropy_f = entropy_f

        self._started = False
        self._computed = False
        self._finished = False

    def gen(self, k):
        g = self.params.group
        self.sk = g.random_exponent(self.entropy_f)
        self.apk = g.Base.exp(self.sk)

        return self.apk

    ########################################
   
    def dec(self, inbound_code):
        #dec with secret key sk an cipher text which gives either the c or error
        return

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        inbound_message = inbound_side_and_message[1:]

        if other_side not in (b"A", b"B"):
            raise OffSides("I don't know what side they're on")
        if self.side == other_side:
            if self.side == SideA:
                raise OffSides("I'm A, but I got a message from A (not B).")
            else:
                raise OffSides("I'm B, but I got a message from B (not A).")
        return inbound_message


class SPAKE2_B:
    "This class manages one side of a SPAKE2 key negotiation."

    side = SideB

    def M(self):
        return self.params.M

    def N(self):
        return self.params.N

    def X_msg(self):
        return self.inbound_message

    def Y_msg(self):
        return self.outbound_message

    def __init__(
        self,
        password,
        idA=b"",
        idB=b"",
        params=DefaultParams,
        entropy_f=os.urandom,
    ):

        self.pw = password
        self.pw_exponent = params.group.password_to_exponent(password)

        self.idA = idA
        self.idB = idB

        self.params = params
        self.entropy_f = entropy_f

        self._started = False
        self._computed = False
        self._finished = False

    def enc(self, inbound_message):
        self.apk = self._extract_message(inbound_message)
        self.session_k = os.urandom(32)
        #enc using session_k, apk, and pw = ciphertext

        return 

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        inbound_message = inbound_side_and_message[1:]

        if other_side not in (b"A", b"B"):
            raise OffSides("I don't know what side they're on")
        if self.side == other_side:
            if self.side == SideA:
                raise OffSides("I'm A, but I got a message from A (not B).")
            else:
                raise OffSides("I'm B, but I got a message from B (not A).")
        return inbound_message
