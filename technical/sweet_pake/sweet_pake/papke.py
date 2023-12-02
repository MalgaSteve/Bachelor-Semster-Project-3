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


ClientId = b"C"
ServerId = b"S"

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


class PAPKE_Client:
    "This class manages one side of a SPAKE2 key negotiation."

    side = ClientId

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

        self.idA = idA
        self.idB = idB

        self.params = params
        self.entropy_f = entropy_f

        self._started = False
        self._computed = False
        self._finished = False

    def gen(self):
        #gen function
        group = self.params.group
        self.random_exponent = group.random_exponent(self.entropy_f)
        self.y1_elem = group.Base1.exp(self.random_exponent)
        self.y2_elem = group.Base2.exp(self.random_exponent)
        Y2_elem = self.y2_elem.elementmult(group.password_to_hash(self.pw))

        #self.outbound_message = (self.y1+self.Y2) <-- apk
        y1_bytes = self.y1_elem.to_bytes()
        Y2_bytes = Y2_elem.to_bytes()
        self.outbound_message =  y1_bytes + Y2_bytes

        outbound_id_and_message = self.side + self.outbound_message

        return outbound_id_and_message

    def dec(self, inbound_message):
        #parse message
        group = self.params.group
        self.inbound_message = self._extract_message(inbound_message)
        (c1, c2, c3) = self._parse_key(self.inbound_message)
        c1 = group.bytes_to_element(c1)
        c2 = group.bytes_to_element(c2)

        #computation
        R_elem = c2.elementmult(c1.exp(-self.random_exponent))
        session_key_computed = group.xor(c3, R_elem.to_bytes())
        (r1, r2) = group.secrets_to_hash(R_elem, self.y1_elem, self.y2_elem, session_key_computed)
        if c1.to_bytes() != group.Base1.exp(r1).elementmult(group.Base2.exp(r2)).to_bytes():
            raise IncorrectCode("Not the expected key")

        self.session_key = session_key_computed
        return self.session_key

    def _parse_key(self, c):
        elem_size = self.params.group.element_size_bytes
        return c[:elem_size], c[elem_size:2*elem_size], c[2*elem_size:]

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        inbound_message = inbound_side_and_message[1:]

        if other_side not in (b"C", b"S"):
            raise OffSides("I don't know what side they're on")
        if self.side == other_side:
            if self.side == ClientId:
                raise OffSides("I'm C, but I got a message from C (not S).")
            else:
                raise OffSides("I'm S, but I got a message from S (not C).")
        return inbound_message


class PAPKE_Server:
    "This class manages one side of a SPAKE2 key negotiation."

    side = ServerId

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

        self.idA = idA
        self.idB = idB

        self.params = params
        self.entropy_f = entropy_f

        self._started = False
        self._computed = False
        self._finished = False

    def enc(self, inbound_message):
        #parse inbound_messahe
        self.inbound_message = self._extract_message(inbound_message)
        apk = self.parse_apk(self.inbound_message)
        group = self.params.group
        y1_elem = group.bytes_to_element(apk[0])
        Y2_elem = group.bytes_to_element(apk[1])

        #enc_function
        self.session_k = os.urandom(32)

        pw_to_hash = group.password_to_hash(self.pw)
        y2_elem = Y2_elem.elementmult((pw_to_hash.exp(-1)))

        random_exponent = group.random_exponent(self.entropy_f)
        R_elem = group.Base1.exp(random_exponent)

        (r1, r2) = group.secrets_to_hash(R_elem, y1_elem, y2_elem, self.session_k)

        c1 = group.Base1.exp(r1).elementmult(group.Base2.exp(r2))
        c2 = y1_elem.exp(r1).elementmult(y2_elem.exp(r2)).elementmult(R_elem)
        c3 = group.xor(hashlib.sha256(R_elem.to_bytes()).digest(), self.session_k)

        #message
        #self.outbound_message = c = (c1, c2, c3)
        self.outbound_message = c1.to_bytes() + c2.to_bytes() + c3
        outbound_sid_and_message = self.side + self.outbound_message
        return outbound_sid_and_message
    

    def parse_apk(self, apk_bytes):
        size_bytes = self.params.group.element_size_bytes
        return apk_bytes[:size_bytes], apk_bytes[size_bytes:]
        

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        inbound_message = inbound_side_and_message[1:]

        if other_side not in (b"C", b"S"):
            raise OffSides("I don't know what side they're on")
        if self.side == other_side:
            if self.side == ClientId:
                raise OffSides("I'm C, but I got a message from C (not S).")
            else:
                raise OffSides("I'm S, but I got a message from S (not C).")
        return inbound_message
