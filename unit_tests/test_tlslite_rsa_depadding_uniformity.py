# Copyright (c) 2026, tlslite-ng contributors
#
# See the LICENSE file for legal information regarding use of this file.

"""Operation-sequence uniformity of the RSA PKCS#1 v1.5 de-padding path.

A Bleichenbacher-style padding oracle (CWE-208, the family of
CVE-2020-26263) exists whenever the amount of work a server performs
while de-padding a decrypted RSA block depends on whether the PKCS#1
v1.5 padding is well formed, or on the structure of the recovered
plaintext.  ``RSAKey.decrypt()`` and
``RSAKeyExchange.processClientKeyExchange()`` therefore have to follow the
same Python-level control-flow sequence whatever the ciphertext decrypts
to, and select between the recovered plaintext and a synthetic value with
arithmetic rather than with a branch.

This module turns that requirement into an exact, machine-checkable
invariant.  For every class of the published padding-oracle probe
taxonomy it records, with ``sys.settrace()``, the ordered sequence of
Python line events executed inside the ``tlslite`` package - each event
identified by the module, the function and the source line it belongs
to - and asserts that those *sequences* are identical, not merely that
they are equally long.  The event total is reported alongside them and
is asserted too, because a spread in the totals names the diverging
class at a glance, but a total is deliberately not the property the
invariant rests on: two different paths of the same length would
satisfy a count comparison while executing different code.  The
invariant records line events rather than duration, avoiding scheduler
and timer noise that would make a wall-clock assertion flaky in CI.
Nothing in this module measures duration - the invariant is over
executed source lines, and it must stay one.

The module fails loudly if a future edit reintroduces a data-dependent
branch, a secret-dependent loop bound or an early exit inside the
secret-dependent region, because each of those makes at least one probe
class reach a source line the others do not, or reach it a different
number of times.  That is its entire purpose, so it must not be weakened
into a comparison of totals alone, nor into a tolerance-based one.  What
it cannot see is a divergence that never leaves a single source line - a
conditional expression choosing between two C-level calls, say - so it
is a regression guard against reintroduced Python control flow rather
than a proof that the path is constant time.

Two deliberate exclusions, each of which would otherwise make the module
assert something false:

- The *publicly invalid* class is not part of the equivalence set, and
  neither of its two triggers is: a ciphertext whose length does not
  match the modulus, and one that encodes an integer which is not
  smaller than the modulus.  Both are facts the attacker already
  possesses about the message they sent, so the early ``None`` return in
  ``decrypt()`` is not an oracle and is retained on purpose.  Each
  trigger is built and measured as its own subtype, and each is asserted
  to be a *distinct* class, never an equal one.
- Absolute line-event counts, and the source lines the recorded
  sequences are made of, are interpreter specific: both legitimately
  differ between the CPython versions this library supports, between
  modulus widths and between revisions of the code under test.  Only
  equality within a single run and within a single modulus width is
  asserted; no absolute count and no source line is hard coded here.

The tests skip themselves when another ``sys.settrace()`` tracer is
already installed - especially ``coverage`` - because line events cannot
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
from tlslite.utils.cryptomath import bytesToNumber, numberToByteArray, \
    numBytes
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
# invalid ciphertexts.
CONFORMANT = "pkcs1_conformant"

# The two publicly visible reasons decrypt() reports an error straight
# away.  They are named rather than anonymous because each is measured
# as a class in its own right: asserting only one of them would leave
# half of the retained early exit unchecked.
PUBLIC_WRONG_LENGTH = "wrong_length"
PUBLIC_NOT_BELOW_MODULUS = "not_below_modulus"
PUBLIC_SUBTYPES = (PUBLIC_WRONG_LENGTH, PUBLIC_NOT_BELOW_MODULUS)

# Key generation and probe encryption are shared by every test in this
# module: they are pure set-up, they must stay out of every traced
# region, and repeating them per test would needlessly slow the suite.
_SUITE_CACHE = {}


def tracing_active():
    """Return True when another trace function already owns the hook.

    :rtype: bool
    """
    return sys.gettrace() is not None


def trace_line_events(operation, payload):
    """Record the Python line events executed inside tlslite by one call.

    ``operation`` is called exactly once, with ``payload`` as its only
    argument, while a trace function records the ``'line'`` events raised
    by frames that belong to the ``tlslite`` package.  Only ``'line'``
    events are recorded, because the sequence of source lines the
    interpreter executed is the direct measure of the operations it
    performed - which is the property the de-padding path has to keep
    independent of secret data.

    Each event is recorded as the module name, the name of the code
    object and the source line, which together identify *where* the
    interpreter was rather than merely *how often* it stopped.  That
    distinction is the whole point: a bare count cannot tell two
    equally long paths apart, whereas the ordered sequence can.  The
    triple is used in preference to the frame or code object itself so
    that nothing keeps a traced frame alive and so that a failure
    message reads as source locations.

    The global trace function must return a local trace function for a
    frame before that frame raises ``'line'`` events at all, which is why
    the tracer returns itself for the frames of interest.  It returns
    None for every other frame so that unrelated library and standard
    library code is neither recorded nor slowed down.

    Whatever tracer was installed beforehand is restored in a ``finally``
    block, so neither a normal return nor an exception raised inside
    ``operation`` can leave a tracer behind to slow down or perturb the
    rest of the test suite.

    :param operation: callable invoked once under the tracer
    :param payload: sole argument passed to ``operation``
    :rtype: list
    :returns: ordered list of (module name, code name, line number)
        triples, one per line event executed inside the tlslite package
    """
    steps = []

    def tracer(frame, event, _arg):
        """Record 'line' events raised by frames of the tlslite package."""
        name = frame.f_globals.get("__name__")
        if name is not None and (name == PACKAGE_NAME
                                 or name.startswith(PACKAGE_PREFIX)):
            if event == "line":
                steps.append((name, frame.f_code.co_name, frame.f_lineno))
            return tracer
        return None

    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        operation(payload)
    finally:
        sys.settrace(previous)
    return steps


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

    Every class must produce the same ordered Python line-event sequence
    even though their results differ; a null byte past offset 10 becomes
    a valid earlier separator.  Uniformity here concerns the control-flow
    sequence, not the returned value.

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
    # integer smaller than the modulus, and 0x01 is below the leading
    # byte of every modulus generated for the widths requested here.
    # The prime generator forces the top two bits of both primes, so the
    # modulus always fills its requested bit length: a request whose half
    # is a whole number of bytes (1024, 2048 and 2049, which rounds down
    # to two 1024 bit primes) leaves a leading byte of 0x90 or above,
    # while the 1026 bit request - the only one here whose modulus does
    # not fill its byte width - leaves 0x02 or 0x03 in its 129 byte
    # field.  encrypt_block() rechecks the result either way.
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


def public_probes(key, ciphertext):
    """Build one ciphertext per publicly invalid subtype.

    ``decrypt()`` reports an error straight away for two distinct
    reasons, and both are covered here rather than only the first:

    - ``wrong_length`` is one byte short of the modulus width, so the
      length check rejects it.
    - ``not_below_modulus`` is exactly the modulus, encoded at the full
      modulus width.  It is therefore not smaller than the modulus by
      construction rather than by chance, which a random high value
      would not guarantee, and it isolates the range check from the
      length check by getting the length right.

    That early exit is deliberately retained upstream, because both the
    length of the message the attacker transmitted and whether the
    integer they chose is below the public modulus are facts they already
    possess.  Each subtype is therefore a legitimately separate
    equivalence class and is measured as one.

    :param key: RSA key whose modulus defines both subtypes
    :param ciphertext: a full width probe ciphertext to truncate
    :rtype: dict
    :returns: publicly invalid subtype name to ciphertext mapping
    """
    probes = {}
    probes[PUBLIC_WRONG_LENGTH] = ciphertext[:-1]
    probes[PUBLIC_NOT_BELOW_MODULUS] = numberToByteArray(key.n,
                                                         numBytes(key.n))
    return probes


def measure(operation, payloads):
    """Return a probe-class to recorded-trace mapping.

    Payloads are visited in sorted order so that the measurement is
    reproducible whatever the mapping's own iteration order happens to
    be on a given interpreter.

    The traces are kept whole rather than reduced to their lengths on the
    way out, because their lengths can be recovered at any time while the
    sequences they came from cannot.

    :param operation: callable measured once per payload
    :param payloads: probe-class name to single-argument mapping
    :rtype: dict
    :returns: probe-class name to ordered trace mapping
    """
    traces = {}
    for name in sorted(payloads):
        traces[name] = trace_line_events(operation, payloads[name])
    return traces


def event_totals(traces):
    """Return the line-event total of every recorded trace.

    The totals are the module's diagnostic view of a measurement: they
    summarise it in one number per class, which is what makes a failure
    readable, and they are asserted as well.  They are derived from the
    traces and never stored in their place.

    :param traces: probe-class name to ordered trace mapping
    :rtype: dict
    :returns: probe-class name to line-event total mapping
    """
    totals = {}
    for name in traces:
        totals[name] = len(traces[name])
    return totals


def format_step(trace, index):
    """Render one step of a recorded trace as a source location.

    :param trace: ordered trace to read from
    :param int index: position of the step to render
    :rtype: str
    """
    if index >= len(trace):
        return "(the trace ended here)"
    step = trace[index]
    return "%s:%s in %s()" % (step[0], step[2], step[1])


def first_divergence(trace, reference):
    """Return the index of the first step that differs, or None.

    Comparing whole sequences in a failure message would bury the one
    fact a developer needs under thousands of identical steps, so the
    position where two traces part company is located instead.

    :param trace: ordered trace under examination
    :param reference: ordered trace it is compared against
    :rtype: int or None
    :returns: index of the first differing step, or None when the two
        traces are identical
    """
    for i, step in enumerate(trace):
        if i >= len(reference) or step != reference[i]:
            return i
    if len(reference) > len(trace):
        return len(trace)
    return None


def divergences(traces, reference):
    """Return the classes whose trace differs from the reference.

    :param traces: probe-class name to ordered trace mapping
    :param reference: ordered trace every class is compared against
    :rtype: list
    :returns: (class name, divergence index) pairs, sorted by class name
    """
    found = []
    for name in sorted(traces):
        index = first_divergence(traces[name], reference)
        if index is not None:
            found.append((name, index))
    return found


def format_traces(label, traces):
    """Render a deterministically ordered per-probe-class report.

    A bare assertion over a set of traces is not actionable, so failures
    carry the line-event total of every probe class, the spread of those
    totals, and - against each class that diverges from the reference -
    the position at which it parts company with it and the two source
    locations involved.  That is what tells a developer which class broke
    and where, which is the first thing they act on.

    The reference is the alphabetically first class, so the report is
    stable across runs and across interpreters with different mapping
    order; the classes themselves are listed sorted for the same reason.

    :param str label: description of the measured configuration
    :param traces: probe-class name to ordered trace mapping
    :rtype: str
    """
    reference_name = sorted(traces)[0]
    reference = traces[reference_name]
    totals = event_totals(traces)
    lowest = min(totals.values())
    highest = max(totals.values())
    lines = ["%s: %s probe classes, %s distinct line-event totals, "
             "min=%s max=%s spread=%s, sequences compared against %s"
             % (label, len(traces), len(set(totals.values())),
                lowest, highest, highest - lowest, reference_name)]
    for name in sorted(traces):
        index = first_divergence(traces[name], reference)
        if index is None:
            marker = ""
        else:
            marker = "   <-- %+d events, diverges at step %s: %s not %s" \
                % (totals[name] - len(reference), index,
                   format_step(traces[name], index),
                   format_step(reference, index))
        lines.append("    %-24s %7s%s" % (name, totals[name], marker))
    return "\n".join(lines)


def check_uniformity(case, label, traces):
    """Assert one single operation sequence for every probe class.

    Three properties are asserted, in ascending order of strength, so
    that a failure is reported at the coarsest level that explains it.
    First that the line-event totals do not spread, then that there is
    exactly one distinct total, and finally - the property that actually
    defines the invariant - that the *ordered* sequences of executed
    source lines are identical.  The last assertion is what makes the
    module a real guard: two classes that took different branches of the
    same length would satisfy the first two and fail the third.

    Equality is asserted within the run rather than against an absolute
    number: line-event totals, and the source lines the sequences name,
    legitimately differ between the CPython versions this library
    supports, between modulus widths and between revisions of the code
    under test, so any hard-coded expectation would be wrong somewhere.

    The two anti-vacuity guards matter as much as the equality itself.
    A measurement that recorded nothing, or that covered a single class,
    would satisfy an equality assertion while proving nothing at all.

    :param case: test case whose assertion methods are used
    :param str label: description of the measured configuration
    :param traces: probe-class name to ordered trace mapping
    """
    case.assertTrue(
        len(traces) >= 2,
        "%s: fewer than two probe classes were measured, so a uniformity "
        "assertion would be vacuous" % label)
    totals = event_totals(traces)
    report = format_traces(label, traces)
    case.assertTrue(
        min(totals.values()) > 0,
        "no line events were recorded at all, so the tracer is not "
        "installed correctly and this assertion would be vacuous:\n"
        + report)
    case.assertEqual(
        max(totals.values()) - min(totals.values()), 0,
        "the spread of executed Python lines across padding classes is "
        "not zero: a data-dependent branch, a secret-dependent loop "
        "bound or an early exit has been reintroduced into the RSA "
        "de-padding path:\n" + report)
    case.assertEqual(
        len(set(totals.values())), 1,
        "the executed line totals are not identical across padding "
        "classes:\n" + report)
    reference_name = sorted(traces)[0]
    diverging = divergences(traces, traces[reference_name])
    case.assertEqual(
        [], [name for name, _ in diverging],
        "the padding classes above execute the same number of Python "
        "lines but not the same ones, so a data-dependent branch has "
        "been reintroduced into the RSA de-padding path without changing "
        "the operation count:\n" + report)


def check_public_classes(case, label, traces, public):
    """Assert each publicly invalid subtype is a separate class.

    The early ``None`` return is taken for two distinct reasons - a
    ciphertext of the wrong length, and one encoding an integer that is
    not smaller than the modulus - and it is retained on purpose for
    both: each condition is a fact the attacker already possesses about
    the message they sent, so neither carries secret information.

    Both subtypes are required to have been measured, because checking
    one of the two would leave the other unverified while the module's
    documentation claims otherwise.  For each, this asserts that the
    subtype is distinct, and never that it matches a secret-dependent
    class - the latter would be asserting something false, and would
    fail.

    Distinctness is the whole of the contract.  How *much* work the public
    class performs relative to the secret-dependent ones is an
    implementation cost, not a property the attacker can draw a secret
    from, so no ordering between the counts is asserted here: pinning one
    would constrain the implementation beyond what the security property
    requires.

    :param case: test case whose assertion methods are used
    :param str label: description of the measured configuration
    :param traces: secret-dependent probe-class traces
    :param public: publicly invalid subtype name to trace mapping
    """
    report = format_traces(label, traces)
    totals = event_totals(traces)
    case.assertEqual(
        sorted(PUBLIC_SUBTYPES), sorted(public),
        "both publicly invalid subtypes have to be measured, otherwise "
        "the retained early exit is only half checked")
    for name in sorted(public):
        recorded = len(public[name])
        case.assertTrue(
            recorded > 0,
            "no line events were recorded for the publicly invalid %s "
            "subtype, so the tracer is not installed correctly:\n%s"
            % (name, report))
        case.assertNotIn(
            recorded, set(totals.values()),
            "the publicly invalid %s subtype executed %s lines, the same "
            "as a secret-dependent class; it is a separate public class "
            "and must not be folded into the equivalence set:\n%s"
            % (name, recorded, report))


def check_repeatable(case, label, first, second):
    """Assert two passes recorded the same sequence for every class.

    Determinism is what lets the invariant be an exact equality rather
    than a tolerance: a measurement that wandered between passes could
    neither prove nor disprove uniformity.  The two passes are compared
    per probe class and by ordered sequence, so a difference is reported
    as the class and the step at which the passes parted company rather
    than as two multi-thousand entry sequences.

    :param case: test case whose assertion methods are used
    :param str label: description of the measured configuration
    :param first: probe-class name to trace mapping from the first pass
    :param second: the same mapping from the second pass
    """
    case.assertEqual(
        sorted(first), sorted(second),
        "the two passes measured different probe classes, so they cannot "
        "be compared")
    unstable = []
    for name in sorted(first):
        if first_divergence(first[name], second[name]) is not None:
            unstable.append(name)
    case.assertEqual(
        [], unstable,
        "repeating the measurement changed the recorded operation "
        "sequence, so the invariant is not deterministic:\n"
        + format_traces(label + ", first pass", first) + "\n"
        + format_traces(label + ", second pass", second))


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
        :returns: (key, name to ciphertext map, name to trace map)
        """
        key, ciphertexts = probe_suite(bits)
        traces = measure(key.decrypt, ciphertexts)
        check_uniformity(self, self.label(bits, key), traces)
        return key, ciphertexts, traces

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

    def test_public_classes_distinct(self):
        key, ciphertexts, traces = self.check_key_size(KEY_BITS_NARROW)
        public = measure(key.decrypt,
                         public_probes(key, ciphertexts[CONFORMANT]))
        check_public_classes(self, self.label(KEY_BITS_NARROW, key),
                             traces, public)

    def test_repeatable(self):
        key, ciphertexts = probe_suite(KEY_BITS_NARROW)
        first = measure(key.decrypt, ciphertexts)
        second = measure(key.decrypt, ciphertexts)
        check_repeatable(self, self.label(KEY_BITS_NARROW, key), first,
                         second)


class TestPremasterSecretOperationCount(UniformityTestCase):
    """Line-event uniformity of the premaster secret selection."""

    def check_key_size(self, bits):
        """Measure every probe class for one key size and check it.

        :param int bits: requested modulus size in bits
        :rtype: tuple
        :returns: (cipher suite, exchange, message map, trace map)
        """
        key, suite, exchange, messages = key_exchange_probes(bits)
        traces = measure(exchange.processClientKeyExchange, messages)
        check_uniformity(self, self.label(bits, key), traces)
        return suite, exchange, messages, traces

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

    def test_public_classes_distinct(self):
        key, ciphertexts = probe_suite(KEY_BITS_NARROW)
        suite, exchange, _, traces = self.check_key_size(KEY_BITS_NARROW)
        invalid = {}
        for name, ciphertext in public_probes(
                key, ciphertexts[CONFORMANT]).items():
            invalid[name] = client_key_exchange(suite, ciphertext)
        public = measure(exchange.processClientKeyExchange, invalid)
        check_public_classes(self, self.label(KEY_BITS_NARROW, key),
                             traces, public)

    def test_repeatable(self):
        key, _ = probe_suite(KEY_BITS_NARROW)
        _, _, exchange, messages = key_exchange_probes(KEY_BITS_NARROW)
        first = measure(exchange.processClientKeyExchange, messages)
        second = measure(exchange.processClientKeyExchange, messages)
        check_repeatable(self, self.label(KEY_BITS_NARROW, key), first,
                         second)


if __name__ == "__main__":
    unittest.main()
