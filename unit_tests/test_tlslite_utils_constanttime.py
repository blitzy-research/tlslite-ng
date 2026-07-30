# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.utils.constanttime import ct_lt_u32, ct_gt_u32, ct_le_u32, \
        ct_lsb_prop_u8, ct_isnonzero_u32, ct_neq_u32, ct_eq_u32, \
        ct_check_cbc_mac_and_pad, ct_compare_digest, ct_lsb_prop_u16, \
        ct_nonzero_u8

from hypothesis import given, example
import hypothesis.strategies as st
from tlslite.utils.compat import compatHMAC
from tlslite.utils.cryptomath import getRandomBytes
from tlslite.recordlayer import RecordLayer
import tlslite.utils.tlshashlib as hashlib
import hmac
import sys

class TestContanttime(unittest.TestCase):

    @given(i=st.integers(0,2**32 - 1), j=st.integers(0,2**32 - 1))
    @example(i=0, j=0)
    @example(i=0, j=1)
    @example(i=1, j=0)
    @example(i=2**32 - 1, j=2**32 - 1)
    @example(i=2**32 - 2, j=2**32 - 1)
    @example(i=2**32 - 1, j=2**32 - 2)
    def test_ct_lt_u32(self, i, j):
        self.assertEqual((i < j), (ct_lt_u32(i, j) == 1))

    @given(i=st.integers(0,2**32 - 1), j=st.integers(0,2**32 - 1))
    @example(i=0, j=0)
    @example(i=0, j=1)
    @example(i=1, j=0)
    @example(i=2**32 - 1, j=2**32 - 1)
    @example(i=2**32 - 2, j=2**32 - 1)
    @example(i=2**32 - 1, j=2**32 - 2)
    def test_ct_gt_u32(self, i, j):
        self.assertEqual((i > j), (ct_gt_u32(i, j) == 1))

    @given(i=st.integers(0,2**32 - 1), j=st.integers(0,2**32 - 1))
    @example(i=0, j=0)
    @example(i=0, j=1)
    @example(i=1, j=0)
    @example(i=2**32 - 1, j=2**32 - 1)
    @example(i=2**32 - 2, j=2**32 - 1)
    @example(i=2**32 - 1, j=2**32 - 2)
    def test_ct_le_u32(self, i, j):
        self.assertEqual((i <= j), (ct_le_u32(i, j) == 1))

    @given(i=st.integers(0,2**32 - 1), j=st.integers(0,2**32 - 1))
    @example(i=0, j=0)
    @example(i=0, j=1)
    @example(i=1, j=0)
    @example(i=2**32 - 1, j=2**32 - 1)
    @example(i=2**32 - 2, j=2**32 - 1)
    @example(i=2**32 - 1, j=2**32 - 2)
    def test_ct_neq_u32(self, i, j):
        self.assertEqual((i != j), (ct_neq_u32(i, j) == 1))

    @given(i=st.integers(0,2**32 - 1), j=st.integers(0,2**32 - 1))
    @example(i=0, j=0)
    @example(i=0, j=1)
    @example(i=1, j=0)
    @example(i=2**32 - 1, j=2**32 - 1)
    @example(i=2**32 - 2, j=2**32 - 1)
    @example(i=2**32 - 1, j=2**32 - 2)
    def test_ct_eq_u32(self, i, j):
        self.assertEqual((i == j), (ct_eq_u32(i, j) == 1))

    @given(i=st.integers(0,255))
    @example(i=0)
    @example(i=255)
    def test_ct_lsb_prop_u8(self, i):
        self.assertEqual(((i & 0x1) == 1), (ct_lsb_prop_u8(i) == 0xff))
        self.assertEqual(((i & 0x1) == 0), (ct_lsb_prop_u8(i) == 0x00))

    @given(i=st.integers(0, 2**16-1))
    @example(i=0)
    @example(i=255)
    @example(i=2**16-1)
    def test_ct_lsb_prop_u16(self, i):
        self.assertEqual(((i & 0x1) == 1), (ct_lsb_prop_u16(i) == 0xffff))
        self.assertEqual(((i & 0x1) == 0), (ct_lsb_prop_u16(i) == 0x0000))

    @given(i=st.integers(0,2**32 - 1))
    @example(i=0)
    def test_ct_isnonzero_u32(self, i):
        self.assertEqual((i != 0), (ct_isnonzero_u32(i) == 1))

    @given(i=st.integers(0,255))
    @example(i=0)
    @example(i=255)
    def test_ct_nonzero_u8(self, i):
        self.assertEqual((i != 0), (ct_nonzero_u8(i) == 1))

    def test_ct_nonzero_u8_exhaustive(self):
        # the byte domain is just 256 values wide, so rather than only
        # sampling it, enumerate every single input
        for i in range(256):
            res = ct_nonzero_u8(i)
            self.assertEqual(1 if i else 0, res,
                             "wrong result for byte value %d" % i)
            # callers combine the result with |, & and ^, so it has to
            # be a plain int; a bool or a 0xff style mask would be a
            # latent defect that comparing against 1 alone would miss
            self.assertEqual(int, type(res),
                             "not a plain int for byte value %d" % i)

    def test_ct_nonzero_u8_byte_neq(self):
        # the production call sites express a byte compare as
        # ct_nonzero_u8(a ^ b), replacing ct_neq_u32(a, b)
        for lhs, rhs in ((0, 0), (0, 2), (2, 2), (0xff, 0xff),
                         (0xf0, 0x02), (2, 0)):
            self.assertEqual(1 if lhs != rhs else 0,
                             ct_nonzero_u8(lhs ^ rhs),
                             "wrong result for %d vs %d" % (lhs, rhs))

    def test_ct_nonzero_u8_byte_domain(self):
        # This is why ct_nonzero_u8 exists instead of reusing
        # ct_isnonzero_u32: the 32 bit primitives mask a negation to
        # 32 bits, so a zero operand keeps every intermediate a small
        # int while a non-zero one needs a wider, multi digit int. The
        # count of those wider values then depends on the data. The
        # fold below never leaves the byte domain, which makes it
        # allocation uniform on CPython. That is a measurable leak
        # reduction, not a guarantee of absolute constant time work.
        byte_size = sys.getsizeof(0xff)
        wide_size = sys.getsizeof(0xffffffff)
        for i in range(256):
            # replay the fold step by step, keeping every intermediate
            val = i
            steps = [val]
            val |= val >> 4
            steps.append(val)
            val |= val >> 2
            steps.append(val)
            val |= val >> 1
            steps.append(val)
            steps.append(val & 1)
            # if the primitive is ever rewritten, this catches the
            # replay above silently drifting away from it
            self.assertEqual(ct_nonzero_u8(i), steps[-1],
                             "replayed fold diverged for value %d" % i)
            for item in steps:
                # interpreter independent, so always asserted
                self.assertTrue(0 <= item <= 0xff,
                                "intermediate %d leaves the byte "
                                "domain for value %d" % (item, i))
                # CPython specific, so calibrated against this
                # interpreter rather than a hard coded object size
                if wide_size > byte_size:
                    self.assertTrue(sys.getsizeof(item) <= byte_size,
                                    "intermediate %d is wider than a "
                                    "byte for value %d" % (item, i))

class TestContanttimeCBCCheck(unittest.TestCase):

    @staticmethod
    def data_prepare(application_data, seqnum_bytes, content_type, version,
                     mac, key):
        r_layer = RecordLayer(None)
        r_layer.version = version

        h = hmac.new(key, digestmod=mac)

        digest = r_layer.calculateMAC(h, seqnum_bytes, content_type,
                                      application_data)

        return application_data + digest

    def test_with_empty_data_and_minimum_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(0)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x00')
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_empty_data_and_maximum_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(0)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\xff'*256)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_little_data_and_minimum_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*32)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x00')
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_little_data_and_maximum_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*32)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\xff'*256)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_lots_of_data_and_minimum_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*1024)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x00')
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_lots_of_data_and_maximum_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*1024)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\xff'*256)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_lots_of_data_and_small_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*1024)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x0a'*11)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_too_little_data(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        mac = hashlib.sha1

        data = bytearray(mac().digest_size)

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertFalse(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                  content_type, version))

    def test_with_invalid_hash(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*1024)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)
        data[-1] ^= 0xff

        padding = bytearray(b'\xff'*256)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertFalse(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                  content_type, version))

    @given(i=st.integers(1, 20))
    def test_with_invalid_random_hash(self, i):
        key = compatHMAC(getRandomBytes(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x15
        version = (3, 3)
        application_data = getRandomBytes(63)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)
        data[-i] ^= 0xff
        padding = bytearray(b'\x00')
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size
        self.assertFalse(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                  content_type, version))

    def test_with_invalid_pad(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*1024)
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x00' + b'\xff'*255)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertFalse(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                  content_type, version))

    def test_with_pad_longer_than_data(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01')
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\xff')
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertFalse(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                  content_type, version))

    def test_with_pad_longer_than_data_in_SSLv3(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 0)
        application_data = bytearray(b'\x01')
        mac = hashlib.sha1

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray([len(application_data) + mac().digest_size + 1])
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertFalse(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                  content_type, version))

    def test_with_null_pad_in_SSLv3(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 0)
        application_data = bytearray(b'\x01'*10)
        mac = hashlib.md5

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x00'*10 + b'\x0a')
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_MD5(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 1)
        application_data = bytearray(b'\x01'*10)
        mac = hashlib.md5

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x0a'*11)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_SHA256(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 3)
        application_data = bytearray(b'\x01'*10)
        mac = hashlib.sha256

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x0a'*11)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

    def test_with_SHA384(self):
        key = compatHMAC(bytearray(20))
        seqnum_bytes = bytearray(16)
        content_type = 0x14
        version = (3, 3)
        application_data = bytearray(b'\x01'*10)
        mac = hashlib.sha384

        data = self.data_prepare(application_data, seqnum_bytes, content_type,
                                 version, mac, key)

        padding = bytearray(b'\x0a'*11)
        data += padding

        h = hmac.new(key, digestmod=mac)
        h.block_size = mac().block_size # python2 workaround
        self.assertTrue(ct_check_cbc_mac_and_pad(data, h, seqnum_bytes,
                                                 content_type, version))

class TestCompareDigest(unittest.TestCase):
    def test_with_equal_length(self):
        self.assertTrue(ct_compare_digest(bytearray(10), bytearray(10)))

        self.assertTrue(ct_compare_digest(bytearray(b'\x02'*8),
                                          bytearray(b'\x02'*8)))

    def test_different_lengths(self):
        self.assertFalse(ct_compare_digest(bytearray(10), bytearray(12)))

        self.assertFalse(ct_compare_digest(bytearray(20), bytearray(12)))

    def test_different(self):
        self.assertFalse(ct_compare_digest(bytearray(b'\x01'),
                                           bytearray(b'\x03')))

        self.assertFalse(ct_compare_digest(bytearray(b'\x01'*10 + b'\x02'),
                                           bytearray(b'\x01'*10 + b'\x03')))

        self.assertFalse(ct_compare_digest(bytearray(b'\x02' + b'\x01'*10),
                                           bytearray(b'\x03' + b'\x01'*10)))
