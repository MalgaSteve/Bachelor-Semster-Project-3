import os, json
from binascii import hexlify, unhexlify
from hashlib import sha256
import hashlib
import hmac
from hkdf import Hkdf
from .file_operations import get_dict_from_entries, fisher_yates
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


class SweetPAKE_Client:
    "This class manages one side of a SPAKE2 key negotiation."

    side = ClientId

    def X_msg(self):
        return self.outbound_message

    def Y_msg(self):
        return self.inbound_message

    def __init__(
        self,
        username,
        password,
        idA=b"",
        idB=b"",
        params=DefaultParams,
        entropy_f=os.urandom,
    ):

        self.username = username
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

        username_size = len(self.username).to_bytes()

        outbound_id_and_message = self.side + username_size + self.username + self.outbound_message

        return outbound_id_and_message

    def dec(self, inbound_message):
        #parse message
        group = self.params.group
        self.inbound_message = self._extract_message(inbound_message)

        len_ciphers = int.from_bytes(self.inbound_message[:1])
        if len_ciphers < 0:
            raise ValueError("Invalid size")

        self.inbound_message = self.inbound_message[1:]
        ciphers = self._parse_array(self.inbound_message, len_ciphers)
        index = -1

        #dec
        for i in range(len(ciphers)):
            session_key_computed = self._papke_dec(group, ciphers[i])
            
            #checks if decryption is successful
            if session_key_computed != -1:
                index = i
                break

        if index == -1:
            raise ValueError("Could not decrypt")

        self.session_key = session_key_computed

        self.second_outbound_message = i.to_bytes()

        return self.side + self.second_outbound_message

    def _papke_dec(self, group, cipher_tuple):
        (c1, c2, c3) = self._parse_key(cipher_tuple)
        c1 = group.bytes_to_element(c1)
        c2 = group.bytes_to_element(c2)

        #computation
        R_elem = c2.elementmult(c1.exp(-self.random_exponent))
        session_key_computed = group.xor(c3, hashlib.sha256(R_elem.to_bytes()).digest())
        (r1, r2) = group.secrets_to_hash(R_elem, self.y1_elem, self.y2_elem, session_key_computed)

        if c1.to_bytes() != group.Base1.exp(r1).elementmult(group.Base2.exp(r2)).to_bytes():
            return -1

        return session_key_computed


    def _parse_array(self, message, size):
        arr = []
        length_cipher = len(message) // size
        for i in range(size):
            arr.append(message[i*length_cipher:length_cipher*i+length_cipher])
        return arr

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


class SweetPAKE_Server:
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

        self.database = get_dict_from_entries("./pw_file")

        self._started = False
        self._computed = False
        self._finished = False

    def enc(self, inbound_message):
        #parse inbound_messahe
        self.inbound_message = self._extract_message(inbound_message)

        #get username from message
        username_size = int.from_bytes(self.inbound_message[:1])
        self.working_with = self.inbound_message[1:username_size+1].decode('utf-8')

        self.inbound_message = self.inbound_message[username_size+1:]

        apk = self.parse_apk(self.inbound_message)
        group = self.params.group
        y1_elem = group.bytes_to_element(apk[0])
        Y2_elem = group.bytes_to_element(apk[1])
        client_pw_array = self.database[self.working_with]

        #PRF - get array of keys
        k = os.urandom(32)
        self.arr_K = group.secrets_to_array(k, y1_elem, Y2_elem, len(client_pw_array), 32)
        #self.arr_K = []
        self.ciphers = []

        #enc_function
        for i in range(len(client_pw_array)):
            gen_ciphers = self._papke_enc(group, y1_elem, Y2_elem, client_pw_array[i], self.arr_K[i])
            self.ciphers.append(gen_ciphers)
        
        #shuffle cipher array
        rp_ciphers, self.pmap = fisher_yates(self.ciphers)

        #message
        #self.outbound_message = c = (c1, c2, c3)
        self.outbound_message = b"".join(rp_ciphers)
        outbound_sid_and_message = self.side + len(rp_ciphers).to_bytes() + self.outbound_message
        return outbound_sid_and_message

    def _papke_enc(self, group, y1_elem, Y2_elem, pw, session_key):
        #session_key = os.urandom(32)
        #self.arr_K.append(session_key)

        pw_to_hash = group.password_to_hash(bytes.fromhex(pw))
        y2_elem = Y2_elem.elementmult((pw_to_hash.exp(-1)))

        random_exponent = group.random_exponent(self.entropy_f)
        R_elem = group.Base1.exp(random_exponent)

        (r1, r2) = group.secrets_to_hash(R_elem, y1_elem, y2_elem, session_key)

        c1 = group.Base1.exp(r1).elementmult(group.Base2.exp(r2))
        c2 = y1_elem.exp(r1).elementmult(y2_elem.exp(r2)).elementmult(R_elem)
        c3 = group.xor(hashlib.sha256(R_elem.to_bytes()).digest(), session_key)

        C = c1.to_bytes() + c2.to_bytes() + c3

        return C

    def parse_apk(self, apk_bytes):
        size_bytes = self.params.group.element_size_bytes
        return apk_bytes[:size_bytes], apk_bytes[size_bytes:]

    def retrieve_key_ask_honeychecker(self, inbound_message):
        self.second_inbound_message = self._extract_message(inbound_message)
        index = int.from_bytes(self.second_inbound_message)
        original_index = self.pmap[index]
        self.session_key = self.arr_K[original_index]

        # todo verify honeychecker

        return self.session_key
        
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
