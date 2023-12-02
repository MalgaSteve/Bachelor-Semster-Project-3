from __future__ import division
import hashlib
from hkdf import Hkdf
from .six import integer_types
from .util import (
    size_bits,
    size_bytes,
    unbiased_randrange,
    bytes_to_number,
    number_to_bytes,
)

"""Interface specification for a Group.

A cyclic abelian group, in the mathematical sense, is a collection of
'elements' and an operation that takes two elements and produces a
third. It has the following additional properties:

* there is an 'identity' element named 1, and X*1=X
* there is a distinguished 'generator' element G
* multiplying G by itself 'n' times is called exponentiation: Y=G^n
"""

###############################################
# transforming and expanding password into bytes

def password_to_exponent(pw, exponent_size_bytes, q):
    h = Hkdf(salt=b"", input_key_material=pw, hash=hashlib.sha256)
    info = b"SPAKE2 password" 
    expanded_password = h.expand(info, exponent_size_bytes + 16)
    i = bytes_to_number(expanded_password)
    pw_exponent = i % q
    return pw_exponent

###############################################
# transforming and expanding secrets into bytes

def key_to_2exponents(R, y1, y2, k, exponent_size_bytes, q):
    ikm = R.to_bytes() + y1.to_bytes() + y2.to_bytes() + k
    h = Hkdf(salt=b"", input_key_material=ikm, hash=hashlib.sha256)
    info = b"SweetPAKE FO random exponents"
    seed_rs = h.expand(info, 2 * exponent_size_bytes + 32)

    (r1_bytes, r2_bytes) = splitInHalf(seed_rs)
    r1_number = bytes_to_number(r1_bytes)
    r2_number = bytes_to_number(r2_bytes)
    r1_exponent = r1_number % q
    r2_exponent = r2_number % q
    
    return (r1_exponent, r2_exponent)

###############################################

def splitInHalf(data):
    midPoint = len(data) // 2
    r1 = data[:midPoint]
    r2 = data[midPoint:]
    
    return r1, r2

###############################################

def expand_arbitrary_element_seed(data, num_bytes):
    h = Hkdf(salt=b"", input_key_material=data, hash=hashlib.sha256)
    info = b"SPAKE2 arbitrary element"
    return h.expand(info, num_bytes)


# Element class
class _Element:
    def __init__(self, group, e):
        self._group = group
        self._e = e

    def elementmult(self, other):
        return self._group._elementmult(self, other)

    def exp(self, s):
        return self._group._exp(self, s)

    def to_bytes(self):
        return self._group._element_to_bytes(self)


class IntegerGroup:
    def __init__(self, p, q, g1, g2):
        self.q = q  # the subgroup order, used for exponents
        self.p = p  # the field size
        self.Zero = _Element(self, 1)
        self.Base1 = _Element(self, g1)  # generator of the subgroup
        self.Base2 = _Element(self, g2)

        # these are the public system parameters
        self.exponent_size_bytes = size_bytes(self.q)
        self.element_size_bits = size_bits(self.p)
        self.element_size_bytes = size_bytes(self.p)

        # double-check that the generator has the right order
        assert pow(g1, self.q, self.p) == 1
        assert pow(g2, self.q, self.p) == 1

    def order(self):
        return self.q

    def random_exponent(self, entropy_f):
        return unbiased_randrange(0, self.q, entropy_f)

    def exponent_to_bytes(self, i):
        # both for hashing into transcript, and save/restore of
        # intermediate state
        assert isinstance(i, integer_types)
        assert 0 <= 0 < self.q
        return number_to_bytes(i, self.q)

    def bytes_to_exponent(self, b):
        # for restore of intermediate state
        assert isinstance(b, bytes)
        assert len(b) == self.exponent_size_bytes
        i = bytes_to_number(b)
        assert 0 <= i < self.q, (0, i, self.q)
        return i

    def password_to_exponent(self, pw):
        return password_to_exponent(pw, self.exponent_size_bytes, self.q)

    def arbitrary_element(self, seed):
        # we do *not* know the discrete log of this one. Nobody should.
        processed_seed = expand_arbitrary_element_seed(
            seed, self.element_size_bytes
        )
        assert isinstance(processed_seed, bytes)
        assert len(processed_seed) == self.element_size_bytes
        # The larger (non-prime-order) group (Zp*) we're using has order
        # p-1. The smaller (prime-order) subgroup has order q. Subgroup
        # orders always divide the larger group order, so r*q=p-1 for
        # some integer r. If h is an arbitrary element of the larger
        # group Zp*, then e=h^r will be an element of the subgroup. If h
        # is selected uniformly at random, so will e, and nobody will
        # know its discrete log. We can enforce this for pre-selected
        # parameters by choosing h as the output of a hash function.
        r = (self.p - 1) // self.q
        assert r * self.q == self.p - 1
        h = bytes_to_number(processed_seed) % self.p
        element = _Element(self, pow(h, r, self.p))
        assert self._is_member(element)
        return element

    def password_to_hash(self, pw):
        return self.arbitrary_element(pw)

    def secrets_to_hash(self, R, y1, y2, k):
        return key_to_2exponents(R, y1, y2, k, self.exponent_size_bytes, self.q)

    def xor(self, bytes1, bytes2):
        xor = [a ^ b for a, b in zip(bytes1, bytes2)]
        return bytes(xor)
    
    def _is_member(self, e):
        if not e._group is self:
            return False
        if pow(e._e, self.q, self.p) == 1:
            return True
        return False

    def _element_to_bytes(self, e):
        # for sending to other side, and hashing into transcript
        assert isinstance(e, _Element)
        assert e._group is self
        return number_to_bytes(e._e, self.p)

    def bytes_to_element(self, b):
        # for receiving from other side: test group membership here
        assert isinstance(b, bytes)
        assert len(b) == self.element_size_bytes
        i = bytes_to_number(b)
        if i <= 0 or i >= self.p:  # Zp* excludes 0
            raise ValueError("alleged element not in the field")
        e = _Element(self, i)
        if not self._is_member(e):
            raise ValueError("element is not in the right group")
        return e

    def _exp(self, e1, i):
        if not isinstance(e1, _Element):
            raise TypeError("E^i requires E be an element")
        assert e1._group is self
        if not isinstance(i, integer_types):
            raise TypeError("E^i requires i be an integer")
        return _Element(self, pow(e1._e, i % self.q, self.p))

    def _elementmult(self, e1, e2):
        if not isinstance(e1, _Element):
            raise TypeError("E1*E2 requires E1 be an element")
        assert e1._group is self
        if not isinstance(e2, _Element):
            raise TypeError("E1*E2 requires E2 be an element")
        assert e2._group is self
        return _Element(self, (e1._e * e2._e) % self.p)


# This 1024-bit group originally came from the J-PAKE demo code,
# http://haofeng66.googlepages.com/JPAKEDemo.java . That java code
# recommended these 2048 and 3072 bit groups from this NIST document:
# http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/DSA2_All.pdf

# L=1024, N=160
I1024 = IntegerGroup(
    p=0xE0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B,
    q=0xE950511EAB424B9A19A2AEB4E159B7844C589C4F,
    g1=0xD29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75,
    g2=0x88a16759f3d9af80570cd50be78820f0923c10711589daab90b75bfeabafef5c41daafbe45d45119c7710156606c2f6a14aeee233a15cfc9b5ad87c1864982f2d3c296b9c9d9c389c2066bb8fda097ff2169f09021c57d407838cf3962d56327e6ce2c4460c22ff18112ceb396c90af3d00bb05f4ca3bc8ac92ae529829f530e
)

# L=2048, N=224
I2048 = IntegerGroup(
    p=0xC196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83,
    q=0x90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D,
    g1=0xA59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085,
    g2=0xa113cbb08ec7a826fd602032ac56a589ea661eae34f20f035dd960995ba4d1bc104828b04181c28b53434f134e4e24a0ef0799b71153bad8c0c9446d2d674ed650fba33182a7d67423e76674de8c1c18dd99373614ae7180e979f2750225d9a74d96c1a085ba239a7b2c09a8cffd3fe12b28e31157acf8961b5487af21b89bac8f43e421a815b2c1bd484dd2daf643dc315e6f034edc6a3a30edb208909b2904c4a898a67f4e683296273b019f59880342c81c7bf46c3eb92a3fcfcc8e0d95d5700e2c5dbdf88ba977f6ec771e1a5a08d8ecea294c5b87734b49beaa155d13ab77a0cd910a94d4812ace70bc5a5db81a7c4cc614800b3a9240516ea4f445f749,

)

# L=3072, N=256
I3072 = IntegerGroup(
    p=0x90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73,
    q=0xCFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D,
    g1=0x5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B,
    g2=0x70ad01a0d2872b54e442abe2af1cf0c956016c608ef0b735107fb53d5b194d1730f41cf019acb3729264bce984c8f0373485560c7b92f156c84f538a061ac1ea3e335925ea27f26ba898ca2b8952f70c3494a3a8d2ae26697bc88e37769c41585a032e433f0f8584ed805863ae6606c49463e6835655f802a93d73e573a00c8615e75d7fd6ad5c42a5d1b397c51d669e163ab1dc6777015d6bf9a1cc7870e27c82ea08be5c7a5963fc66a4b5085a2d063a103b7b38c7d2367df9ec85191552b549f6d703f0e942c8795259df75f71e1e4232a0e8210a2d34b0d39ac0fbb57fd071e584fb79d13b7fb196a01a6ed8a827272e3cd9368b710042e92625319e082c74662a2f00bfa3ac2a65d25254be065ed10f564774c703ad5f4c572110aaac56ab5f61d509b4e164e4b28d5b3e481a4372feb10e0cc4b0012d70b96eda351f2d5fa8eeefdb35dba5743af3e763ed3f72c70bb6aa0169f0103374496af39204f76095ded1c0ff19895df2de86a86cede38273faadf5b129cede7a54591d978424,
)

# M and N are defined as "randomly chosen elements of the group". It is
# important that nobody knows their discrete log (if your
# parameter-provider picked a secret 'haha' and told you to use
# M=pow(g,haha,p), you couldn't tell that M wasn't randomly chosen, but
# they could then mount an active attack against your PAKE session). S
# is the same, but used for both sides of a symmetric session.
#
# The safe way to choose these is to hash a public string.


class _Params:
    def __init__(self, group, M=b"M", N=b"N"):
        self.group = group
        #self.M = group.arbitrary_element(seed=M)
        #self.N = group.arbitrary_element(seed=N)
        #self.M_str = M
        #self.N_str = N


# Params3072 has 128-bit security.
Params3072 = _Params(I3072)
# Params2048 has 112-bit security and comes from NIST.
Params2048 = _Params(I2048)
# Params1024 is roughly as secure as an 80-bit symmetric key, and uses a
# 1024-bit modulus.
Params1024 = _Params(I1024)
