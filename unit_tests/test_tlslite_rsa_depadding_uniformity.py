# Copyright (c) 2026, tlslite-ng contributors
#
# See the LICENSE file for legal information regarding use of this file.

"""Operation-sequence uniformity of the RSA PKCS#1 v1.5 de-padding path.

A Bleichenbacher-style padding oracle (CWE-208, the family of
CVE-2020-26263) exists whenever the amount of work a server performs
while de-padding a decrypted RSA block depends on whether the PKCS#1
v1.5 padding is well formed, or on the structure of the recovered
plaintext.  ``RSAKey.decrypt()`` and
``RSAKeyExchange.processClientKeyExchange()`` therefore have to perform a
fixed sequence of operations whatever the ciphertext decrypts to, and
select between the recovered plaintext and a synthetic value with
arithmetic rather than with a branch.

This module turns that requirement into an exact, machine-checkable
invariant.  For every class of the published padding-oracle probe
taxonomy it counts the Python line events executed inside the ``tlslite``
package with ``sys.settrace()`` and asserts that the counts are
*identical*.  The measurement is deterministic and noise free, which is
precisely why it can live in a unit-test suite: a wall-clock timing
assertion would be flaky in CI and would be a liability here.  Nothing
in this module measures duration - the invariant is an operation count,
and it must stay one.

The module fails loudly if a future edit reintroduces a data-dependent
branch, a secret-dependent loop bound or an early exit inside the
secret-dependent region.  That is its entire purpose, so it must not be
weakened into a tolerance-based comparison.

Two deliberate exclusions, each of which would otherwise make the module
assert something false:

- The *publicly invalid* class - a ciphertext whose length does not match
  the modulus, or which encodes an integer that is not smaller than it -
  is not part of the equivalence set.  Both conditions are facts the
  attacker already possesses about the message they sent, so the early
  ``None`` return in ``decrypt()`` is not an oracle and is retained on
  purpose.  It is asserted to be a *distinct* class, never an equal one.
- Absolute line-event counts are interpreter specific and legitimately
  differ between the CPython versions this library supports, and between
  modulus widths.  Only equality within a single run and within a single
  modulus width is asserted; no absolute count is hard coded here.

The tests skip themselves when another ``sys.settrace()`` tracer is
already installed - ``coverage`` above all - because line events cannot
then be attributed to this measurement.  They run normally under
``python -m unittest discover`` and under ``pytest``, neither of which
installs a tracer, so the skip is expected only under coverage.
"""

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import sys

from tlslite.constants import CipherSuite
from tlslite.keyexchange import RSAKeyExchange
from tlslite.messages import ClientHello, ClientKeyExchange, ServerHello
from tlslite.utils.cryptomath import bytesToNumber, numBytes
from tlslite.utils.keyfactory import generateRSAKey


# Line events are attributed to the code under test by module name rather
# than by file name: ``co_filename`` is relative or absolute depending on
# how the package was imported, while ``__name__`` is the same in every
# configuration and on every supported interpreter.
PACKAGE_NAME = "tlslite"
PACKAGE_PREFIX = "tlslite."

# Reported when something else owns the trace hook.  ``coverage``
# installs its own tracer and the project's canonical coverage command
# runs the whole unit-test suite under it, so skipping is required rather
# than merely polite: without it this module would be unrunnable under a
# gate that the project depends on.
TRACER_BUSY = (
    "another sys.settrace() tracer is already installed (coverage, a "
    "profiler or a debugger), so Python line events cannot be "
    "attributed to this measurement")

# The two hello messages deliberately carry different protocol versions.
# That is what makes the tolerated buggy-Internet-Explorer probe class (a
# premaster secret carrying the Server Hello version instead of the
# Client Hello one) distinguishable from the wrong-version class.
CLIENT_VERSION = (3, 3)
SERVER_VERSION = (3, 2)

# A TLS premaster secret is exactly 48 bytes: two version bytes followed
# by 46 bytes of client entropy.
PREMASTER_LENGTH = 48

# PKCS#1 v1.5 mandates a 0x00 0x02 prefix followed by at least eight
# non-zero padding bytes, so the null separator can never sit below
# offset 10 and the longest representable payload is numBytes(n) - 11
# bytes long.
MIN_SEPARATOR_OFFSET = 10
MAX_PAYLOAD_MARGIN = 11

# Modulus sizes exercised.  1026 bits is included deliberately: it is the
# only size here whose modulus is 129 bytes wide, so it covers a width
# that is neither a power of two nor a multiple of the 32 byte PRF block.
# 2049 bits is included because the pure-Python generator rounds it to
# the same 256 byte width as 2048 bits, which cross-checks that the
# operation count follows the public modulus width and nothing else.
KEY_BITS_NARROW = 1024
KEY_BITS_ODD_WIDTH = 1026
KEY_BITS_WIDE = 2048
KEY_BITS_ODD_REQUEST = 2049

# The name of the one probe class that is guaranteed to exist for every
# modulus width, used for cache warming and as the basis of the publicly
# invalid ciphertext.
CONFORMANT = "pkcs1_conformant"

# Key generation and probe encryption are shared by every test in this
# module: they are pure set-up, they must stay out of every traced
# region, and repeating them per test would needlessly slow the suite.
_SUITE_CACHE = {}


def tracing_active():
    """Return True when another trace function already owns the hook.

    :rtype: bool
    """
    return sys.gettrace() is not None


def count_line_events(operation, payload):
    """Count Python line events executed inside tlslite by one call.

    ``operation`` is called exactly once, with ``payload`` as its only
    argument, while a trace function counts the ``'line'`` events raised
    by frames that belong to the ``tlslite`` package.  Only ``'line'``
    events are counted, because their number is the direct measure of how
    many Python operations the interpreter performed - which is the
    property the de-padding path has to keep independent of secret data.

    The global trace function must return a local trace function for a
    frame before that frame raises ``'line'`` events at all, which is why
    the tracer returns itself for the frames of interest.  It returns
    None for every other frame so that unrelated library and standard
    library code is neither counted nor slowed down.

    Whatever tracer was installed beforehand is restored in a ``finally``
    block, so neither a normal return nor an exception raised inside
    ``operation`` can leave a tracer behind to slow down or perturb the
    rest of the test suite.

    :param operation: callable invoked once under the tracer
    :param payload: sole argument passed to ``operation``
    :rtype: int
    :returns: number of line events executed inside the tlslite package
    """
    counter = [0]

    def tracer(frame, event, _arg):
        """Count 'line' events raised by frames of the tlslite package."""
        name = frame.f_globals.get("__name__")
        if name is not None and (name == PACKAGE_NAME
                                 or name.startswith(PACKAGE_PREFIX)):
            if event == "line":
                counter[0] += 1
            return tracer
        return None

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        operation(payload)
    finally:
        sys.settrace(previous)
    return counter[0]


def pkcs1_block(size, separator, payload):
    """Build a modulus-wide, PKCS#1 v1.5 shaped encryption block.

    The block is ``0x00 0x02``, then non-zero padding, then an optional
    null separator, then the payload.  Every padding byte is non-zero so
    that each probe class differs from the conformant one in exactly one
    respect.

    Passing None as ``separator`` builds a block with no null byte at all
    past the two byte prefix, so that the de-padding loop can never find
    a separator.

    The representability of the requested geometry is checked rather than
    assumed: a silently clamped separator or an overlong payload would
    produce a block belonging to a different equivalence class than the
    one under test, and the measurement would then be meaningless.

    :param int size: width of the modulus in bytes
    :param separator: offset of the null separator, or None for a block
        that contains no separator at all
    :param payload: byte values placed directly after the separator
    :rtype: bytearray
    """
    block = bytearray(b"\xa5" * size)
    block[0] = 0x00
    block[1] = 0x02
    if separator is None:
        if payload:
            raise ValueError("a payload needs a separator to follow")
        return block
    if separator < MIN_SEPARATOR_OFFSET:
        raise ValueError(
            "separator at offset %s would leave fewer than eight padding "
            "bytes" % separator)
    if separator + 1 + len(payload) > size:
        raise ValueError(
            "a %s byte payload at separator %s does not fit a %s byte "
            "block" % (len(payload), separator, size))
    block[separator] = 0x00
    for offset, value in enumerate(payload):
        block[separator + 1 + offset] = value
    return block


def depadding_probes(size):
    """Build one block per secret-dependent probe class.

    The taxonomy is the published padding-oracle probe taxonomy that
    differential TLS test suites drive against a server: a conformant
    block, blocks carrying the wrong protocol version, blocks whose
    payload is a length other than 48 bytes, a block without a null
    separator, and blocks with a null byte planted inside the mandatory
    eight padding bytes and elsewhere in the padding.  The two byte
    prefix is corrupted as well, so that all four rejection conditions
    the de-padding loop folds are represented.

    Every class differs from the conformant block only in data the
    attacker cannot observe directly, so de-padding must execute exactly
    the same number of Python lines for all of them.  Note that the
    classes deliberately do not share an outcome: a null byte planted
    past offset 10 simply becomes the separator and yields a valid, if
    unexpected, plaintext.  Uniformity is about the operation count, not
    about the result.

    :param int size: width of the modulus in bytes
    :rtype: dict
    :returns: probe-class name to block mapping
    """
    premaster = bytearray(b"\xf0" * PREMASTER_LENGTH)
    premaster[0] = CLIENT_VERSION[0]
    premaster[1] = CLIENT_VERSION[1]
    # offset of the separator that yields a full length premaster secret
    aligned = size - PREMASTER_LENGTH - 1

    wrong_version = bytearray(premaster)
    wrong_version[0] = 0x09
    wrong_version[1] = 0x09
    server_version = bytearray(premaster)
    server_version[0] = SERVER_VERSION[0]
    server_version[1] = SERVER_VERSION[1]

    probes = {}
    probes[CONFORMANT] = pkcs1_block(size, aligned, premaster)
    probes["wrong_version"] = pkcs1_block(size, aligned, wrong_version)
    probes["buggy_ie_version"] = pkcs1_block(size, aligned, server_version)
    probes["no_null_byte"] = pkcs1_block(size, None, bytearray(0))
    probes["pms_size_0"] = pkcs1_block(size, size - 1, bytearray(0))
    probes["pms_size_2"] = pkcs1_block(size, size - 3, premaster[:2])
    probes["pms_size_47"] = pkcs1_block(size, size - 48, premaster[:47])
    if size - MAX_PAYLOAD_MARGIN >= 200:
        # a 200 byte payload is representable only by a wide modulus, and
        # asking a narrow one for it would silently build a different
        # class instead
        probes["pms_size_200"] = pkcs1_block(size, size - 201,
                                             bytearray(b"\x5a" * 200))

    # inside the eight mandatory padding bytes, so the block is rejected
    planted = pkcs1_block(size, aligned, premaster)
    planted[MIN_SEPARATOR_OFFSET - 5] = 0x00
    probes["zero_in_pkcs_padding"] = planted

    # past them, where the loop simply takes it for the separator: the
    # outcome differs from the class above, the operation count must not
    planted = pkcs1_block(size, aligned, premaster)
    planted[MIN_SEPARATOR_OFFSET + 5] = 0x00
    probes["zero_in_padding"] = planted

    # 0x01 rather than a large value: the block still has to encode an
    # integer smaller than the modulus, whose leading byte is at least
    # 0x80 for a key of the declared size
    planted = pkcs1_block(size, aligned, premaster)
    planted[0] = 0x01
    probes["no_leading_zero"] = planted

    planted = pkcs1_block(size, aligned, premaster)
    planted[1] = 0x03
    probes["wrong_block_type"] = planted
    return probes


def encrypt_block(key, block):
    """Apply the raw public key operation to a hand-built block.

    ``key.encrypt()`` always produces conformant padding, so every probe
    class other than the conformant one has to be encrypted directly.
    Reaching for the raw operation is established practice in this test
    suite.

    The block is validated first.  A block that is not as wide as the
    modulus, or that encodes an integer which is not smaller than it,
    would be rejected by ``decrypt()`` as publicly invalid, and the
    measurement would then silently be taken on the wrong equivalence
    class rather than on the one the probe describes.

    :param key: RSA key providing the public operation
    :param block: modulus-wide block to encrypt
    :rtype: bytearray
    """
    if len(block) != numBytes(key.n):
        raise ValueError("block is %s bytes wide, modulus is %s"
                         % (len(block), numBytes(key.n)))
    if bytesToNumber(block) >= key.n:
        raise ValueError("block does not encode an integer below the "
                         "modulus, decrypt() would reject it as "
                         "publicly invalid")
    # reaching for the raw operation is what lets a non-conformant block
    # be encrypted at all; the scope of the exemption ends with this
    # function
    # pylint: disable=protected-access
    return key._raw_public_key_op_bytes(block)


def probe_suite(bits):
    """Return a memoised key and probe ciphertexts for one key size.

    Key generation and encryption happen once per key size and are shared
    by every test, both to keep the suite fast and to keep that work out
    of every traced region.

    The fresh key is then used for one untraced decryption.  This is not
    optional: ``decrypt()`` caches the hash of the private exponent on
    first use and the pure-Python backend initialises its blinding pair
    on the first private key operation.  Neither one-off cost may be
    charged to whichever probe class happens to be measured first, or the
    invariant would report a spurious divergence.

    :param int bits: requested modulus size in bits
    :rtype: tuple
    :returns: (key, probe-class name to ciphertext mapping)
    """
    suite = _SUITE_CACHE.get(bits)
    if suite is None:
        key = generateRSAKey(bits)
        ciphertexts = {}
        for name, block in depadding_probes(numBytes(key.n)).items():
            ciphertexts[name] = encrypt_block(key, block)
        key.decrypt(ciphertexts[CONFORMANT])
        suite = (key, ciphertexts)
        _SUITE_CACHE[bits] = suite
    return suite


def publicly_invalid(ciphertext):
    """Return a ciphertext that is invalid for publicly visible reasons.

    One byte short of the modulus width, so ``decrypt()`` returns None
    straight from its length check.  That early exit is deliberately
    retained upstream, because the length of the message the attacker
    transmitted is a fact they already possess, and it is therefore a
    legitimately separate equivalence class.

    :param ciphertext: a full width probe ciphertext
    :rtype: bytearray
    """
    return ciphertext[:-1]


def measure(operation, payloads):
    """Return a probe-class to line-event-count mapping.

    Payloads are visited in sorted order so that the measurement is
    reproducible whatever the mapping's own iteration order happens to
    be on a given interpreter.

    :param operation: callable measured once per payload
    :param payloads: probe-class name to single-argument mapping
    :rtype: dict
    """
    counts = {}
    for name in sorted(payloads):
        counts[name] = count_line_events(operation, payloads[name])
    return counts


def format_counts(label, counts):
    """Render a deterministically ordered per-probe-class count report.

    A bare assertion over a set of counts is not actionable, so failures
    carry the count of every probe class, the spread, and a marker
    against each class that diverges from the smallest count.  The order
    is sorted by class name so that the report is stable across runs and
    across interpreters with different mapping order.

    :param str label: description of the measured configuration
    :param counts: probe-class name to line-event-count mapping
    :rtype: str
    """
    lowest = min(counts.values())
    highest = max(counts.values())
    lines = ["%s: %s probe classes, %s distinct line-event counts, "
             "min=%s max=%s spread=%s"
             % (label, len(counts), len(set(counts.values())),
                lowest, highest, highest - lowest)]
    for name in sorted(counts):
        if counts[name] == lowest:
            marker = ""
        else:
            marker = "   <-- diverges by %+d" % (counts[name] - lowest)
        lines.append("    %-24s %7s%s" % (name, counts[name], marker))
    return "\n".join(lines)


def check_uniformity(case, label, counts):
    """Assert one single operation count for every probe class.

    Equality is asserted within the run rather than against an absolute
    number: line-event counts legitimately differ between the CPython
    versions this library supports and between modulus widths, so any
    hard-coded count would be wrong somewhere.

    The two anti-vacuity guards matter as much as the equality itself.
    A measurement that counted nothing, or that covered a single class,
    would satisfy an equality assertion while proving nothing at all.

    :param case: test case whose assertion methods are used
    :param str label: description of the measured configuration
    :param counts: probe-class name to line-event-count mapping
    """
    case.assertTrue(
        len(counts) >= 2,
        "%s: fewer than two probe classes were measured, so a uniformity "
        "assertion would be vacuous" % label)
    report = format_counts(label, counts)
    case.assertTrue(
        min(counts.values()) > 0,
        "no line events were counted at all, so the tracer is not "
        "installed correctly and this assertion would be vacuous:\n"
        + report)
    case.assertEqual(
        max(counts.values()) - min(counts.values()), 0,
        "the spread of executed Python lines across padding classes is "
        "not zero: a data-dependent branch, a secret-dependent loop "
        "bound or an early exit has been reintroduced into the RSA "
        "de-padding path:\n" + report)
    case.assertEqual(
        len(set(counts.values())), 1,
        "the executed line counts are not identical across padding "
        "classes:\n" + report)


def check_public_class(case, label, counts, public):
    """Assert the publicly invalid class is a measurably separate class.

    The early ``None`` return taken for a ciphertext of the wrong length,
    or one encoding an integer that is not smaller than the modulus, is
    retained on purpose: both conditions are facts the attacker already
    possesses about the message they sent, so neither carries secret
    information.  This asserts that the class is distinct, and never that
    it matches the secret-dependent count - the latter would be
    asserting something false, and would fail.

    :param case: test case whose assertion methods are used
    :param str label: description of the measured configuration
    :param counts: secret-dependent probe-class counts
    :param int public: line-event count of the publicly invalid class
    """
    report = format_counts(label, counts)
    case.assertTrue(
        public > 0,
        "no line events were counted for the publicly invalid class, so "
        "the tracer is not installed correctly:\n" + report)
    case.assertNotIn(
        public, set(counts.values()),
        "the publicly invalid class executed %s lines, the same as a "
        "secret-dependent class; it is a separate public class and must "
        "not be folded into the equivalence set:\n" % public + report)
    case.assertTrue(
        public < min(counts.values()),
        "the publicly invalid class executed %s lines, which is not "
        "fewer than the secret-dependent classes; its documented early "
        "exit appears to be gone:\n" % public + report)


def make_key_exchange(key):
    """Build a server side RSAKeyExchange and report its cipher suite.

    Only the private key and the two hello messages are needed, so no
    certificate is involved: the probe ciphertexts are produced with the
    public operation of the same key object.

    :param key: server private key
    :rtype: tuple
    :returns: (cipher suite, RSAKeyExchange)
    """
    suite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    client_hello = ClientHello().create(CLIENT_VERSION, bytearray(32),
                                        bytearray(0), [])
    server_hello = ServerHello().create(SERVER_VERSION, bytearray(32),
                                        bytearray(0), suite)
    return suite, RSAKeyExchange(suite, client_hello, server_hello, key)


def client_key_exchange(suite, ciphertext):
    """Wrap one probe ciphertext in a ClientKeyExchange message.

    :param suite: negotiated cipher suite
    :param ciphertext: encrypted premaster secret to carry
    :rtype: tlslite.messages.ClientKeyExchange
    """
    message = ClientKeyExchange(suite, SERVER_VERSION)
    message.createRSA(ciphertext)
    return message


def key_exchange_probes(bits):
    """Build a server key exchange and its probe messages for one size.

    The messages are built here, outside every traced region, so that the
    measurement covers ``processClientKeyExchange()`` and nothing else.
    One untraced call is made for the same reason the de-padding fixture
    makes one: no one-off cost inside the callee may be charged to
    whichever probe class is measured first.

    :param int bits: requested modulus size in bits
    :rtype: tuple
    :returns: (key, cipher suite, RSAKeyExchange, name to message map)
    """
    key, ciphertexts = probe_suite(bits)
    suite, exchange = make_key_exchange(key)
    messages = {}
    for name in sorted(ciphertexts):
        messages[name] = client_key_exchange(suite, ciphertexts[name])
    exchange.processClientKeyExchange(messages[CONFORMANT])
    return key, suite, exchange, messages


class UniformityTestCase(unittest.TestCase):
    """Base class owning the trace hook guards shared by both layers."""

    @classmethod
    def setUpClass(cls):
        """Skip the whole class, and its fixtures, when a tracer is up."""
        if tracing_active():
            raise unittest.SkipTest(TRACER_BUSY)

    def setUp(self):
        # guarded again per test: a tracer installed between class set-up
        # and the test itself would make every measurement meaningless
        if tracing_active():
            self.skipTest(TRACER_BUSY)

    def tearDown(self):
        # the tracer must never outlive a measurement; a leaked one would
        # slow down and perturb every test that runs afterwards, which
        # would be a worse defect than the one this module guards against
        self.assertIsNone(
            sys.gettrace(),
            "a trace function outlived the measurement and would now "
            "perturb the rest of the test suite")


# Test methods in this package carry no docstrings: their names describe
# the case and every module here follows that convention.  Helpers,
# classes and the module itself are documented above, as the project's
# pylint configuration requires.
# pylint: disable=missing-function-docstring


class TestRSADepaddingOperationCount(UniformityTestCase):
    """Line-event uniformity of RSAKey.decrypt() de-padding."""

    def check_key_size(self, bits):
        """Measure every probe class for one key size and check it.

        :param int bits: requested modulus size in bits
        :rtype: tuple
        :returns: (key, name to ciphertext map, name to count map)
        """
        key, ciphertexts = probe_suite(bits)
        counts = measure(key.decrypt, ciphertexts)
        check_uniformity(self, self.label(bits, key), counts)
        return key, ciphertexts, counts

    @staticmethod
    def label(bits, key):
        """Describe the measured configuration for failure messages.

        :param int bits: requested modulus size in bits
        :param key: the key actually generated for that request
        :rtype: str
        """
        return "RSAKey.decrypt(), %s bit request, %s byte modulus" \
            % (bits, numBytes(key.n))

    def test_narrow_key(self):
        self.check_key_size(KEY_BITS_NARROW)

    def test_odd_width_key(self):
        self.check_key_size(KEY_BITS_ODD_WIDTH)

    def test_wide_key(self):
        self.check_key_size(KEY_BITS_WIDE)

    def test_odd_request_key(self):
        self.check_key_size(KEY_BITS_ODD_REQUEST)

    def test_public_class_distinct(self):
        key, ciphertexts, counts = self.check_key_size(KEY_BITS_NARROW)
        public = count_line_events(
            key.decrypt, publicly_invalid(ciphertexts[CONFORMANT]))
        check_public_class(self, self.label(KEY_BITS_NARROW, key), counts,
                           public)

    def test_repeatable(self):
        key, ciphertexts = probe_suite(KEY_BITS_NARROW)
        first = measure(key.decrypt, ciphertexts)
        second = measure(key.decrypt, ciphertexts)
        self.assertEqual(
            first, second,
            "repeating the measurement changed the operation counts, so "
            "the invariant is not deterministic:\n"
            + format_counts("first pass", first) + "\n"
            + format_counts("second pass", second))


class TestPremasterSecretOperationCount(UniformityTestCase):
    """Line-event uniformity of the premaster secret selection."""

    def check_key_size(self, bits):
        """Measure every probe class for one key size and check it.

        :param int bits: requested modulus size in bits
        :rtype: tuple
        :returns: (cipher suite, exchange, ciphertext map, count map)
        """
        key, suite, exchange, messages = key_exchange_probes(bits)
        counts = measure(exchange.processClientKeyExchange, messages)
        check_uniformity(self, self.label(bits, key), counts)
        return suite, exchange, messages, counts

    @staticmethod
    def label(bits, key):
        """Describe the measured configuration for failure messages.

        :param int bits: requested modulus size in bits
        :param key: the key actually generated for that request
        :rtype: str
        """
        return "processClientKeyExchange(), %s bit request, %s byte " \
            "modulus" % (bits, numBytes(key.n))

    def test_narrow_key(self):
        self.check_key_size(KEY_BITS_NARROW)

    def test_wide_key(self):
        self.check_key_size(KEY_BITS_WIDE)

    def test_public_class_distinct(self):
        key, ciphertexts = probe_suite(KEY_BITS_NARROW)
        suite, exchange, _, counts = self.check_key_size(KEY_BITS_NARROW)
        invalid = client_key_exchange(
            suite, publicly_invalid(ciphertexts[CONFORMANT]))
        public = count_line_events(exchange.processClientKeyExchange,
                                   invalid)
        check_public_class(self, self.label(KEY_BITS_NARROW, key), counts,
                           public)

    def test_repeatable(self):
        _, _, exchange, messages = key_exchange_probes(KEY_BITS_NARROW)
        first = measure(exchange.processClientKeyExchange, messages)
        second = measure(exchange.processClientKeyExchange, messages)
        self.assertEqual(
            first, second,
            "repeating the measurement changed the operation counts, so "
            "the invariant is not deterministic:\n"
            + format_counts("first pass", first) + "\n"
            + format_counts("second pass", second))


if __name__ == "__main__":
    unittest.main()
