# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import ast
import dis
import inspect
import sys
import textwrap

from tlslite.utils.constanttime import ct_lt_u32, ct_gt_u32, ct_le_u32, \
        ct_lsb_prop_u8, ct_isnonzero_u32, ct_neq_u32, ct_eq_u32, \
        ct_check_cbc_mac_and_pad, ct_compare_digest, ct_lsb_prop_u16, \
        ct_nonzero_u8

from hypothesis import given, example
import hypothesis.strategies as st
from tlslite.utils.compat import compatHMAC
from tlslite.utils.cryptomath import getRandomBytes
from tlslite.recordlayer import RecordLayer
# Import consumers as modules so the tests can inspect the helper aliases
# bound in each namespace.
from tlslite import keyexchange as keyexchange_module
from tlslite.utils import rsakey as rsakey_module
import tlslite.utils.tlshashlib as hashlib
import hmac

# int, and on Python 2 also long, spelled without naming long so that
# this module keeps importing on Python 3
_INT_TYPES = tuple(set((int, type(2 ** 64))))

# Python 3.8+ parses numeric literals as ast.Constant; older versions
# use ast.Num
if sys.version_info >= (3, 8):
    _NUM_NODES = (ast.Constant,)
else:
    _NUM_NODES = (ast.Num,)

# reject calls, conditional control flow and indirection so the helper
# cannot delegate to a wider primitive or branch on the input
_BANNED_NODE_NAMES = ("Call", "If", "IfExp", "While", "For", "BoolOp",
                      "Compare", "UnaryOp", "Attribute", "Subscript",
                      "Lambda", "ListComp", "SetComp", "DictComp",
                      "GeneratorExp", "Assert", "Raise", "Try",
                      "TryExcept", "TryFinally", "With", "Break",
                      "Continue")

# built with getattr because the set of node classes differs between
# Python 2 and Python 3
_BANNED_NODES = tuple(getattr(ast, name) for name in _BANNED_NODE_NAMES
                      if hasattr(ast, name))

_ALLOWED_OPS = (ast.BitOr, ast.BitAnd, ast.BitXor, ast.RShift)


def _literal_value(node):
    """Return the value of a numeric literal node, portably."""
    if sys.version_info >= (3, 8):
        return node.value
    return node.n


def _code_of(func):
    """Return func's code object on both Python 2 and Python 3.

    Python 3 spells the attribute ``__code__``; the oldest interpreters
    this project supports may only expose ``func_code``, so fall back to
    it rather than assuming either spelling exists.
    """
    code = getattr(func, "__code__", None)
    if code is None:
        code = getattr(func, "func_code", None)
    return code


# output-equivalent insecure fixtures verify that the structural checks
# reject delegation, wide masking and secret-dependent branching
def _u32_delegate(val):
    """Insecure shape: hands a secret byte to a 32 bit primitive."""
    return ct_isnonzero_u32(val)


def _u32_inline(val):
    """Insecure shape: masks a negation to 32 bits, as ct_*_u32 do."""
    val &= 0xffffffff
    return (val | (-val & 0xffffffff)) >> 31


def _secret_branch(val):
    """Insecure shape: branches on the byte it is meant to hide."""
    val |= val >> 4
    val |= val >> 2
    val |= val >> 1
    if val & 1:
        return 1
    return 0


# Controls for the wide-helper check in TestCtNonzeroU8Consumers.  Each
# folds in the byte domain first and only then reaches one wide helper,
# so the check's "the fold is named at all" assertion is satisfied and
# its wide-helper loop is the only assertion left that can reject the
# fixture.  A control that never folds cannot tell the two apart: the
# first assertion raises in place of the second, and the loop could be
# deleted without the control noticing.  All five answer exactly as
# ct_nonzero_u8() does for every byte, so a real call site reaching one
# of them would change no value anywhere - only its CPython allocation
# cost - which is why the structural check exists in the first place.
def _fold_then_isnonzero_u32(val):
    """Insecure shape: folds, then hands the bit to ct_isnonzero_u32."""
    return ct_isnonzero_u32(ct_nonzero_u8(val))


def _fold_then_neq_u32(val):
    """Insecure shape: folds, then tests the bit with ct_neq_u32."""
    return ct_neq_u32(ct_nonzero_u8(val), 0)


def _fold_then_eq_u32(val):
    """Insecure shape: folds, then tests the bit with ct_eq_u32."""
    return ct_eq_u32(ct_nonzero_u8(val), 1)


def _fold_then_gt_u32(val):
    """Insecure shape: folds, then tests the bit with ct_gt_u32."""
    return ct_gt_u32(ct_nonzero_u8(val), 0)


def _fold_then_le_u32(val):
    """Insecure shape: folds, then tests the bit with ct_le_u32."""
    return ct_le_u32(1, ct_nonzero_u8(val))


# the name every secret-dependent call site has to keep resolving
_HELPER_NAME = "ct_nonzero_u8"

# The two consumers whose secret-byte folds must resolve to this helper.
# Each imports its own alias, so both bindings are checked.
_CONSUMER_MODULES = (rsakey_module, keyexchange_module)

# The wide zero and inequality helpers.  On CPython each masks a two's
# complement negation to 32 bits, which needs a fresh multi-digit
# integer for a non-zero operand and none at all for a zero one, so
# reaching one of them from a secret byte is the very asymmetry the
# byte-domain fold was written to remove.  None of them may appear at a
# secret call site.  ct_lt_u32() is deliberately absent because this
# guard is scoped to zero/equality folds on individual bytes; decrypt()
# uses ct_lt_u32() in separate synthetic-length selection and
# public-index logic.  ct_lsb_prop_u8() and ct_lsb_prop_u16() are also
# absent because their intermediates stay within their declared bit
# widths.
_WIDE_HELPER_NAMES = ("ct_isnonzero_u32", "ct_neq_u32", "ct_eq_u32",
                      "ct_gt_u32", "ct_le_u32")

# One control per name above, so a name whose rejection stopped being
# asserted is caught even if the others still are.  The pairing itself is
# asserted, so a wide helper added to the list without a control fails
# loudly rather than going unexercised.
_WIDE_CONTROL_FIXTURES = (("ct_isnonzero_u32", _fold_then_isnonzero_u32),
                          ("ct_neq_u32", _fold_then_neq_u32),
                          ("ct_eq_u32", _fold_then_eq_u32),
                          ("ct_gt_u32", _fold_then_gt_u32),
                          ("ct_le_u32", _fold_then_le_u32))

# Phrases unique to each rejection assert_no_wide_helper() can make.
# They are written once here and used both by that method's messages and
# by the controls, so a reworded message cannot quietly leave a control
# accepting the wrong rejection.
_NO_FOLD_PHRASE = "does not reference"
_WIDE_CALL_PHRASE = "whose CPython cost depends on its operand"


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
        for lhs, rhs in ((0, 0), (0, 2), (2, 2), (0xff, 0xff),
                         (0xf0, 0x02), (2, 0)):
            self.assertEqual(1 if lhs != rhs else 0,
                             ct_nonzero_u8(lhs ^ rhs),
                             "wrong result for %d vs %d" % (lhs, rhs))

    # bind structural checks to the real helper: output-only tests would
    # also accept a wider masked implementation whose allocation cost
    # depends on the input. These checks reduce CPython timing
    # variability; they do not establish absolute constant-time behavior.

    @staticmethod
    def _body_ast(func):
        """Return func's FunctionDef when source is available, else None."""
        try:
            src = inspect.getsource(func)
        except (IOError, OSError, TypeError):
            return None
        return ast.parse(textwrap.dedent(src)).body[0]

    def _assert_code_shape(self, func):
        """Reject byte code with name lookups, closures, wide constants
        or jumps.
        """
        code = _code_of(func)
        name = func.__name__
        # never let a missing code object turn the checks below into a
        # silent pass
        self.assertTrue(code is not None,
                        "no code object available for %s" % name)
        # with no name lookups at all the function cannot reach
        # ct_isnonzero_u32(), ct_neq_u32() or any other callable
        self.assertEqual((), code.co_names,
                         "%s looks up the global names %r"
                         % (name, code.co_names))
        self.assertEqual((), code.co_freevars,
                         "%s closes over %r" % (name, code.co_freevars))
        for const in code.co_consts:
            if isinstance(const, _INT_TYPES):
                # reject wide mask constants used by value-dependent
                # multi-digit arithmetic
                self.assertTrue(0 <= const <= 0xff,
                                "%s holds the wide constant %r"
                                % (name, const))
        # calibrate against a known straight-line helper before treating
        # jump targets as evidence of branching
        if not dis.findlabels(_code_of(ct_lsb_prop_u8).co_code):
            self.assertEqual([], dis.findlabels(code.co_code),
                             "%s branches" % name)

    def _assert_source_shape(self, func):
        """Assert func's source is a branch-free byte-domain fold."""
        node = self._body_ast(func)
        if node is None:
            return
        name = func.__name__
        arg = _code_of(func).co_varnames[0]
        returns = 0
        for item in ast.walk(node):
            self.assertFalse(isinstance(item, _BANNED_NODES),
                             "%s uses %s" % (name, type(item).__name__))
            if isinstance(item, ast.Return):
                returns += 1
            if isinstance(item, (ast.BinOp, ast.AugAssign)):
                self.assertTrue(isinstance(item.op, _ALLOWED_OPS),
                                "%s uses the operator %s"
                                % (name, type(item.op).__name__))
            if isinstance(item, ast.Name):
                self.assertEqual(arg, item.id,
                                 "%s references %s" % (name, item.id))
            if isinstance(item, _NUM_NODES):
                num = _literal_value(item)
                if isinstance(num, _INT_TYPES):
                    self.assertTrue(0 <= num <= 0xff,
                                    "%s uses the literal %r"
                                    % (name, num))
        self.assertEqual(1, returns,
                         "%s has %d return statements" % (name, returns))

    @staticmethod
    def _trace_call(func, val):
        """Call func(val) under tracing.

        Return the result, the local values observed at line events and
        the executed line numbers.
        """
        seen = []
        lines = []
        name = _code_of(func).co_varnames[0]

        def local_trace(frame, event, _arg):
            """Record one event of the traced frame."""
            if event == "line":
                lines.append(frame.f_lineno)
                seen.append(frame.f_locals[name])
            return local_trace

        def global_trace(frame, event, _arg):
            """Start recording once the traced function is entered."""
            if event == "call" and frame.f_code is _code_of(func):
                return local_trace
            return None

        outer = sys.gettrace()
        sys.settrace(global_trace)
        try:
            res = func(val)
        finally:
            sys.settrace(outer)
        return res, seen, lines

    def _assert_traced_shape(self, func):
        """Assert the line sequence and the byte-domain local
        observations are uniform for all byte inputs.
        """
        byte_size = sys.getsizeof(0xff)
        wide_size = sys.getsizeof(0xffffffff)
        first = None
        for i in range(256):
            res, seen, lines = self._trace_call(func, i)
            self.assertEqual(1 if i else 0, res,
                             "wrong result for byte value %d" % i)
            # a tracer that never fired would leave the rest of this
            # loop vacuous, so require the fold's own steps to show up
            self.assertTrue(len(seen) >= 4,
                            "only %d traced steps for byte value %d"
                            % (len(seen), i))
            for val in seen:
                # interpreter independent, so always asserted
                self.assertTrue(0 <= val <= 0xff,
                                "intermediate %d leaves the byte "
                                "domain for value %d" % (val, i))
                # CPython specific, so calibrated against this
                # interpreter rather than a hard coded object size
                if wide_size > byte_size:
                    self.assertTrue(sys.getsizeof(val) <= byte_size,
                                    "intermediate %d is wider than a "
                                    "byte for value %d" % (val, i))
            if first is None:
                first = lines
            else:
                self.assertEqual(first, lines,
                                 "byte value %d executes other lines"
                                 % i)

    def test_ct_nonzero_u8_real_shape(self):
        # check the helper itself, not a duplicated model that could drift
        self._assert_code_shape(ct_nonzero_u8)
        self._assert_source_shape(ct_nonzero_u8)

    def test_ct_nonzero_u8_traced_steps(self):
        if sys.gettrace() is not None:
            self.skipTest("another tracer is already installed")
        self._assert_traced_shape(ct_nonzero_u8)

    def test_ct_nonzero_u8_rejections(self):
        # output-equivalent insecure fixtures must fail the structural
        # checks; otherwise the tests would not detect a leaking
        # implementation shape
        for func in (ct_isnonzero_u32, _u32_delegate, _u32_inline,
                     _secret_branch):
            for i in range(256):
                self.assertEqual(ct_nonzero_u8(i), func(i),
                                 "%s is not output equivalent at %d"
                                 % (func.__name__, i))
            self.assertRaises(AssertionError,
                              self._assert_code_shape, func)
            if self._body_ast(func) is not None:
                self.assertRaises(AssertionError,
                                  self._assert_source_shape, func)
        if sys.gettrace() is None:
            self.assertRaises(AssertionError,
                              self._assert_traced_shape, _secret_branch)

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

class TestCtNonzeroU8Consumers(unittest.TestCase):
    """Bind ct_nonzero_u8 to the consumers that fold secret bytes.

    An output-equivalent 32-bit helper preserves return values and gives
    each probe class the same alternative helper trace, so value tests and
    the within-run operation-sequence invariant do not pin helper identity.
    The consumer must therefore bind ct_nonzero_u8 itself and name no wide
    helper.  Negative controls verify the code-object and module-binding
    checks.

    Consumer-fixture tests separately assert fold counts, byte-domain
    arguments, and value preservation.  These checks do not measure
    duration or install a trace function, so they run under coverage.
    """

    def tearDown(self):
        # a substituted alias must never outlive a test: a leaked one
        # would quietly invalidate every assertion made after it, which
        # would be a worse defect than the one guarded against here
        for module in _CONSUMER_MODULES:
            self.assertIs(ct_nonzero_u8, getattr(module, _HELPER_NAME),
                          "%s.%s was left substituted"
                          % (module.__name__, _HELPER_NAME))

    @staticmethod
    def consumer_methods():
        """Return the two secret-processing methods under guard.

        :rtype: tuple
        """
        exchange = keyexchange_module.RSAKeyExchange
        return (rsakey_module.RSAKey.decrypt,
                exchange.processClientKeyExchange)

    def assert_helper_binding(self, module):
        """Assert the module's helper name resolves the real primitive.

        The fold shape of that primitive is pinned exhaustively by
        test_ct_nonzero_u8_real_shape, so an identity check here is what
        completes the chain from a secret call site to a byte-domain fold:
        whatever the call site reaches is the function whose every
        intermediate has been shown to stay inside the byte domain.

        :param module: module whose helper alias is checked
        """
        bound = getattr(module, _HELPER_NAME, None)
        self.assertIs(
            ct_nonzero_u8, bound,
            "%s.%s resolves %r instead of the byte-domain helper, so the "
            "secret call sites reached through it no longer fold in the "
            "byte domain" % (module.__name__, _HELPER_NAME, bound))

    def assert_no_wide_helper(self, func):
        """Assert func's code object names no wide 32-bit helper.

        The names are read from the real code object rather than from a
        copy of the source, so this cannot drift away from the code that
        actually runs.

        Two rejections are possible and each carries its own phrase, so
        the controls below can require the one whose assertion they guard
        instead of accepting whichever happens to fire first.

        :param func: function or method to inspect
        """
        code = _code_of(func)
        name = getattr(func, "__name__", repr(func))
        self.assertTrue(code is not None,
                        "no code object available for %s" % name)
        self.assertIn(_HELPER_NAME, code.co_names,
                      "%s %s %s at all"
                      % (name, _NO_FOLD_PHRASE, _HELPER_NAME))
        for wide in _WIDE_HELPER_NAMES:
            self.assertNotIn(wide, code.co_names,
                             "%s references %s, %s"
                             % (name, wide, _WIDE_CALL_PHRASE))

    def assert_rejected_for(self, func, reason, detail):
        """Assert assert_no_wide_helper() rejects func for one reason.

        That method asserts the byte-domain helper is named before it
        asserts that no wide helper is, so a control which only required
        "some AssertionError" would keep passing if the second assertion
        were deleted - the first would raise in its place.  The message is
        therefore read back and both the phrase of the intended rejection
        and the name it reports are required, which is what ties each
        control to the single assertion it exists to guard.

        :param func: function whose code object has to be rejected
        :param reason: phrase unique to the intended rejection
        :param detail: name that rejection has to report
        """
        label = getattr(func, "__name__", repr(func))
        try:
            self.assert_no_wide_helper(func)
        except AssertionError as err:
            reported = str(err)
        else:
            self.fail("%s was accepted, expected a rejection saying %r"
                      % (label, reason))
        for needle in (reason, detail):
            self.assertIn(needle, reported,
                          "%s was rejected without mentioning %r: %s"
                          % (label, needle, reported))

    def assert_binding_rejected(self, module, helper):
        """Assert the binding check fails for a substituted helper.

        The helper is restored in a finally block and restoration is
        asserted so the negative control cannot contaminate later tests.

        :param module: module whose helper alias is substituted
        :param helper: output-equivalent replacement to install
        """
        label = "%s.%s replaced by %s" % (module.__name__, _HELPER_NAME,
                                          helper.__name__)
        real = getattr(module, _HELPER_NAME)
        setattr(module, _HELPER_NAME, helper)
        try:
            self.assertRaises(AssertionError, self.assert_helper_binding,
                              module)
        finally:
            setattr(module, _HELPER_NAME, real)
        self.assertIs(real, getattr(module, _HELPER_NAME), label)

    def test_consumers_bind_the_real_helper(self):
        for module in _CONSUMER_MODULES:
            self.assert_helper_binding(module)

    def test_consumers_name_no_wide_helper(self):
        for func in self.consumer_methods():
            self.assert_no_wide_helper(func)

    def test_wide_helper_reference_is_detected(self):
        # a control on the wide-helper loop of the check above: each
        # fixture folds in the byte domain and then still reaches one wide
        # helper, so that loop is the only assertion able to reject it and
        # its removal is detected.  One fixture per name in
        # _WIDE_HELPER_NAMES, so dropping a single name is detected too.
        for wide, func in _WIDE_CONTROL_FIXTURES:
            self.assert_rejected_for(func, _WIDE_CALL_PHRASE, wide)

    def test_missing_helper_reference_is_detected(self):
        # and a control on the other assertion of the same check: a call
        # site the fold no longer reaches at all is rejected for that
        # reason, which is what keeps the checks above from passing
        # vacuously against code the helper was removed from
        self.assert_rejected_for(_u32_delegate, _NO_FOLD_PHRASE,
                                 _HELPER_NAME)

    def test_every_wide_helper_has_a_control(self):
        # the controls are only as complete as this pairing: a wide helper
        # listed without a fixture would never be exercised, and a fixture
        # that stopped folding would silently stop discriminating between
        # the two rejections - the same defect the controls guard against
        self.assertEqual(sorted(_WIDE_HELPER_NAMES),
                         sorted(pair[0] for pair
                                in _WIDE_CONTROL_FIXTURES))
        for wide, func in _WIDE_CONTROL_FIXTURES:
            code = _code_of(func)
            self.assertIn(_HELPER_NAME, code.co_names,
                          "%s does not fold, so it cannot isolate the "
                          "wide-helper assertion" % func.__name__)
            self.assertIn(wide, code.co_names,
                          "%s does not reach %s"
                          % (func.__name__, wide))
            # output equivalence is what makes the control faithful: a
            # call site reaching one of these would change no value, so
            # only a structural check could ever notice
            for i in range(256):
                self.assertEqual(ct_nonzero_u8(i), func(i),
                                 "%s is not output equivalent at %d"
                                 % (func.__name__, i))

    def test_substituted_helper_is_detected(self):
        # Negative control: output-equivalent stand-ins must fail the
        # identity check.
        for insecure in (_u32_delegate, _u32_inline, _secret_branch):
            for module in _CONSUMER_MODULES:
                self.assert_binding_rejected(module, insecure)
