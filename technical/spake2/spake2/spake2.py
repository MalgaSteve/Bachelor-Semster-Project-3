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


class SPAKE2_A:
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

    def start(self):
        if self._started:
            raise OnlyCallStartOnce("start() can only be called once")
        self._started = True

        g = self.params.group
        self.x_exponent = g.random_exponent(self.entropy_f)
        self.x_elem = g.Base.exp(self.x_exponent)

        ########################################
        # task2 pw_blinding
        pw_blinding = self.M().exp(self.pw_exponent)
        message_elem = self.x_elem.elementmult(pw_blinding)
        self.outbound_message = message_elem.to_bytes()

        outbound_side_and_message = self.side + self.outbound_message
        return outbound_side_and_message

    ########################################
    def compute(self, inbound_side_and_message):
        if self._computed:
            raise OnlyCallComputeOnce("compute() can only be called once")
        self._computed = True

        self.inbound_message = self._extract_message(inbound_side_and_message)

        g = self.params.group
        inbound_elem = g.bytes_to_element(self.inbound_message)
        if inbound_elem.to_bytes() == self.outbound_message:
            raise ReflectionThwarted

        ########################################
        #task3 pw_unblinding and K_elem computation
        pw_unblinding = self.N().exp(-self.pw_exponent)
        K_elem = inbound_elem.elementmult(pw_unblinding).exp(self.x_exponent)

        ########################################
        K_bytes = K_elem.to_bytes()
        keys = self._finalize(K_bytes)
        self.key_ae = keys[0]
        self.key_mac_s = keys[1]
        self.key_mac_c = keys[2]
        ########################################
        #task4 sid creation (similar to trascript) and HMAC computation
        #hmac.new(byte_key, message, hashlib.sha256).digest()
        self.sid = b"".join(
            [
                sha256(self.idA).digest(),
                sha256(self.idB).digest(),
                self.X_msg(),
                self.Y_msg(),
            ]
        )
        self.code_s = hmac.new(self.key_mac_s, self.sid, hashlib.sha256).digest()
        self.code_c = hmac.new(self.key_mac_c, self.sid, hashlib.sha256).digest()
        ########################################
        return self.code_c

    def finish(self, inbound_code):
        if self._finished:
            raise OnlyCallFinishOnce("finish() can only be called once")
        self._finished = True

        if hmac.compare_digest(inbound_code, self.code_s):
            return self.key_ae
        else:
            raise IncorrectCode("Confirmation code from server isn't correct.")


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

    def _finalize(self, K_bytes):
        transcript = b"".join(
            [
                sha256(self.pw).digest(),
                sha256(self.idA).digest(),
                sha256(self.idB).digest(),
                self.X_msg(),
                self.Y_msg(),
                K_bytes,
            ]
        )

        ikm = sha256(transcript).digest()
        h = Hkdf(salt=b"", input_key_material=ikm, hash=hashlib.sha256)
        info = b"SPAKE2_key_for_AE"
        infos = b"SPAKE2_key_for_MAC_server"
        infoc = b"SPAKE2_key_for_MAC_client"
        key_ae = h.expand(info, 32)
        key_mac_s = h.expand(infos, 32)
        key_mac_c = h.expand(infoc, 32)

        return key_ae, key_mac_s, key_mac_c

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

    def start(self):
        if self._started:
            raise OnlyCallStartOnce("start() can only be called once")
        self._started = True

        g = self.params.group
        self.y_exponent = g.random_exponent(self.entropy_f)
        self.y_elem = g.Base.exp(self.y_exponent)

        ########################################
        pw_blinding = self.N().exp(self.pw_exponent)
        message_elem = self.y_elem.elementmult(pw_blinding)
        ########################################
        self.outbound_message = message_elem.to_bytes()
        outbound_side_and_message = self.side + self.outbound_message

        return outbound_side_and_message
        ########################################


    def compute(self, inbound_side_and_message):
        if self._computed:
            raise OnlyCallComputeOnce("compute() can only be called once")
        self._computed = True

        # extract DH value and compute keys
        self.inbound_message = self._extract_message(inbound_side_and_message)

        g = self.params.group
        inbound_elem = g.bytes_to_element(self.inbound_message)
        if inbound_elem.to_bytes() == self.outbound_message:
            raise ReflectionThwarted

        ########################################
        pw_unblinding = self.M().exp(-self.pw_exponent)
        K_elem = inbound_elem.elementmult(pw_unblinding).exp(self.y_exponent)

        ########################################
        K_bytes = K_elem.to_bytes()
        keys = self._finalize(K_bytes)
        self.key_ae = keys[0]
        self.key_mac_s = keys[1]
        self.key_mac_c = keys[2]
        ########################################

        self.sid = b"".join(
            [
                sha256(self.idA).digest(),
                sha256(self.idB).digest(),
                self.X_msg(),
                self.Y_msg(),
            ]
        )
        self.code_s = hmac.new(self.key_mac_s, self.sid, hashlib.sha256).digest()
        self.code_c = hmac.new(self.key_mac_c, self.sid, hashlib.sha256).digest()

        return self.code_s


    def finish(self, inbound_code):
        if self._finished:
            raise OnlyCallFinishOnce("finish() can only be called once")
        self._finished = True

        if hmac.compare_digest(inbound_code, self.code_c):
            return self.key_ae
        else:
            raise IncorrectCode("Confirmation code from client isn't correct.")

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

    def _finalize(self, K_bytes):
        transcript = b"".join(
            [
                sha256(self.pw).digest(),
                sha256(self.idA).digest(),
                sha256(self.idB).digest(),
                self.X_msg(),
                self.Y_msg(),
                K_bytes,
            ]
        )

        ikm = sha256(transcript).digest()
        h = Hkdf(salt=b"", input_key_material=ikm, hash=hashlib.sha256)
        info = b"SPAKE2_key_for_AE"
        infos = b"SPAKE2_key_for_MAC_server"
        infoc = b"SPAKE2_key_for_MAC_client"
        key_ae = h.expand(info, 32)
        key_mac_s = h.expand(infos, 32)
        key_mac_c = h.expand(infoc, 32)

        # hardcoded 32 bytes outout key
        return key_ae, key_mac_s, key_mac_c
