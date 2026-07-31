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
than a proof that the path is constant time.  That blind spot is covered
by three sibling tests, and the coupling is deliberate rather than
incidental: ``test_every_secret_byte_is_folded_in_the_byte_domain`` and
``test_wide_fold_substitution_changes_no_plaintext`` in
``test_tlslite_utils_rsakey.py`` instrument the fold call sites
themselves, and ``test_consumers_name_no_wide_helper`` in
``test_tlslite_utils_constanttime.py`` refuses a consumer that so much as
names a wide helper.  Whoever weakens one of the four should expect the
others to be all that is left.

Three deliberate exclusions, each of which would otherwise make the
module assert something false:

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
- Object finalizers are not part of any measurement.  ``__del__`` is
  code the interpreter runs on its own account, at whatever point the
  last reference to an object happens to go away, so which probe class's
  traced window it lands in is a function of the allocation history of
  the whole test run and not of the ciphertext being de-padded.  The
  package defines five of them, all releasing a native handle in an
  M2Crypto backed wrapper, and none is ever called by the code under
  test, so a recorded finalizer can only ever be noise.  Recording one
  would report a divergence in code that did not diverge - and would do
  so with a message accusing the de-padding path of a timing leak, which
  is the most misleading failure this module could produce.  Finalizer
  frames and everything they call are therefore left out of the
  recording, and the collector is held off for the duration of each
  measurement so that it cannot run one there in the first place.

The tests skip themselves when another ``sys.settrace()`` tracer is
already installed - especially ``coverage`` - because line events cannot
then be attributed to this measurement.  They run normally under
``python -m unittest discover`` and under ``pytest``, neither of which
installs a tracer, so the skip is expected only under coverage.

The hygiene that keeps a finalizer and the collector out of a traced
window is described where it is built, in ``trace_line_events``, and is
asserted by the tests in ``TestTracerHygiene`` rather than left to
inspection.  It matters most where M2Crypto is installed, because that is
the only configuration in which the package's finalizers exist to be
reached at all, and it is one the project supports and its CI exercises.
"""

# The instrument, the probe taxonomy, the fixtures and the invariant they
# serve belong together: each of them is only meaningful beside the
# others, and a measurement whose method lived in another file would be
# read without it.  That puts the module over the default length limit,
# as the two test modules it corroborates are as well.
# pylint: disable=too-many-lines

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import gc
import sys
from types import FunctionType

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

# A finalizer runs whenever the interpreter decides the object owning it
# is unreachable, which has nothing to do with the operation being
# measured: the garbage collector can fire one in the middle of any probe
# class and charge that class lines the other classes never execute.  The
# collector is therefore drained and switched off around every
# measurement (see trace_line_events), and frames of this name are never
# recorded, so that a finalizer reached by a reference count dropping to
# zero cannot contaminate a measurement either.  Every finalizer tlslite
# defines today lives in one of the optional OpenSSL modules, which is
# why leaving this unguarded only broke the measurement when M2Crypto was
# installed - a configuration this project supports and its CI exercises.
FINALIZER_NAME = "__del__"

# Names of the code objects the interpreter runs on its own account
# rather than on behalf of the code under test, and which are therefore
# excluded from every recording along with everything they call.
#
# ``__del__`` is the only one the package defines: the M2Crypto backed
# cipher and RSA key wrappers release their native handles there
# (``openssl_rsakey``, ``openssl_aes`` twice, ``openssl_rc4`` and
# ``openssl_tripledes``).  Nothing calls any of them explicitly, so a
# finalizer frame can never be a legitimate step of the de-padding path;
# it is reached only when the last reference to such an object goes away,
# which is a property of the allocation history of the whole test run.
# Its own frame is not the whole of the exposure either - a finalizer may
# call back into the package, as ``OpenSSL_RSAKey.__del__`` does when it
# reads an attribute of a class that defines ``__getattr__`` - so the
# suppression has to cover the callees too, and it does.  The tuple is
# built from FINALIZER_NAME so that the suppression and the tests that
# assert it cannot come to disagree about what a finalizer is called.
INTERPRETER_CALLBACKS = (FINALIZER_NAME,)

# Module name the stand-in finalizer of the hygiene tests is attributed
# to.  It names the package on purpose - that is what makes the tracer
# treat the stand-in exactly as it would treat a finalizer the library
# really defines - and it names no real module, so nothing can import it.
FINALIZER_MODULE = PACKAGE_PREFIX + "finalizer_stand_in"

# Number of unreachable finalizer cycles the hygiene tests leave pending.
# One would do; a few dozen make it near certain that a collection which
# fired inside a measurement would be seen in the recorded sequence
# rather than merely be possible.
FINALIZER_CYCLES = 64

# How close to the collector's own generation zero threshold the hygiene
# tests arm it.  Small enough that the next handful of allocations would
# trigger a collection, which is what puts a collection inside the
# measured window when nothing keeps it out.
GC_ARMING_MARGIN = 20

# Handed to a package function when a measurement has to record
# something and what it computes is beside the point.  Any integer wider
# than a machine word does; nothing depends on the value.
SAMPLE_INTEGER = 1 << 127

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

    What the operation itself executes is the only thing measured, so the
    work the interpreter does on its own account while the hook is up is
    kept out of the recording in two complementary ways.  Neither weakens
    the invariant: both remove events that belong to the process rather
    than to the payload, and an event the code under test executed is
    still recorded whatever the payload is.

    - Finalizers are suppressed as whole subtrees.  A frame named in
      ``INTERPRETER_CALLBACKS`` is counted in when it is entered and out
      when it returns, and nothing at all is recorded while that count is
      non zero, so a finalizer that calls back into the package cannot
      contribute either.  The count is balanced even when a finalizer
      raises, because the interpreter reports ``'return'`` for a frame
      that is unwinding as well as for one returning normally.  Keying on
      the frame rather than on the collector is what covers the finalizer
      of an object whose reference count reaches zero while the operation
      runs, because that happens whether the collector is on or off.
    - The cyclic garbage collector is held off for the duration of the
      measurement, and pending garbage is collected before the hook goes
      up rather than during it, which runs whatever finalizers are due
      outside the window rather than inside it.  Which measurement a
      collection would otherwise fall in depends on how much the rest of
      the test run has allocated, which is exactly the kind of process
      wide accident that must not be mistaken for a property of the
      ciphertext.

    Without those guards a finalizer belonging to the package - every one
    tlslite has lives in an optional OpenSSL module - lands inside one
    probe class's window and only that class's, which reads as a spread in
    the executed line counts and accuses the de-padding path of a
    regression it does not have.

    Whatever tracer was installed beforehand is restored in a ``finally``
    block, and so is the collector's previous state, so neither a normal
    return nor an exception raised inside ``operation`` can leave either
    behind to slow down or perturb the rest of the test suite.  The
    collector is restored to the state it was found in rather than simply
    enabled, so a caller that deliberately runs without it keeps its
    choice.

    :param operation: callable invoked once under the tracer
    :param payload: sole argument passed to ``operation``
    :rtype: list
    :returns: ordered list of (module name, code name, line number)
        triples, one per line event executed inside the tlslite package
    """
    steps = []
    # depth of the finalizer subtree currently executing; held in a list
    # because the nested functions below have to mutate it and this
    # module supports interpreters without ``nonlocal``
    suppressed = [0]

    def suppress(_frame, event, _arg):
        """Swallow a finalizer frame's events and count it out again."""
        if event == "return":
            suppressed[0] -= 1
        return suppress

    def tracer(frame, event, _arg):
        """Record 'line' events raised by frames of the tlslite package."""
        if event == "call" \
                and frame.f_code.co_name in INTERPRETER_CALLBACKS:
            suppressed[0] += 1
            return suppress
        name = frame.f_globals.get("__name__")
        if name is not None and (name == PACKAGE_NAME
                                 or name.startswith(PACKAGE_PREFIX)):
            if event == "line" and not suppressed[0]:
                steps.append((name, frame.f_code.co_name, frame.f_lineno))
            return tracer
        return None

    collecting = gc.isenabled()
    gc.collect()
    if collecting:
        gc.disable()
    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        operation(payload)
    finally:
        sys.settrace(previous)
        if collecting:
            gc.enable()
    return steps


def finalizer_steps(trace):
    """Return the steps of one trace that a finalizer contributed.

    A finalizer belongs to whatever object the interpreter happened to
    reclaim, never to the operation under measurement, so a recorded
    trace containing one is a contaminated measurement whatever else it
    says.

    :param trace: ordered trace to examine
    :rtype: list
    :returns: the recorded (module, code name, line) triples raised by a
        finalizer frame, in the order they were recorded
    """
    found = []
    for step in trace:
        if step[1] == FINALIZER_NAME:
            found.append(step)
    return found


class _FinalizerStandIn(object):
    """Template the stand-in finalizer's code object is taken from.

    Nothing instantiates this class: only the code object of its
    finalizer is used, because a code object compiled from a real
    ``__del__`` carries the name a real finalizer's frames carry, which
    is what the guard in ``trace_line_events`` keys on.  Writing it out
    here rather than building it from a string keeps it readable and
    keeps it under the same static analysis as the rest of the module.
    """

    # nothing but the finalizer belongs here, and a public method would
    # have to be invented to satisfy the usual minimum
    # pylint: disable=too-few-public-methods

    #: replaced by the list make_finalizer_class() is given
    recorder = []

    def __del__(self):
        self.recorder.append(1)


def make_finalizer_class(recorder):
    """Build a class whose finalizer is attributed to the package.

    A stand-in is used rather than one of the library's own finalizers
    because every finalizer tlslite defines lives in an optional OpenSSL
    module: a test built on one of those would exercise the guard only
    where M2Crypto happens to be installed, which is precisely the
    configuration in which the guard was found to be missing.  Rebinding
    the template's code object to a namespace whose ``__name__`` names
    the package produces a finalizer the tracer's predicate accepts on
    every installation, so the guard is tested everywhere.

    :param recorder: list every finalization appends to, so that a test
        can tell a finalizer that ran from one that never did
    :rtype: type
    :returns: class whose instances record their own finalization
    """
    template = _FinalizerStandIn.__dict__[FINALIZER_NAME]
    namespace = {"__name__": FINALIZER_MODULE}
    finalizer = FunctionType(template.__code__, namespace, FINALIZER_NAME)
    return type("FinalizerStandIn", (object,),
                {"__del__": finalizer, "recorder": recorder})


def seed_finalizer_cycles(recorder, count):
    """Leave unreachable reference cycles carrying a package finalizer.

    The cycle is what makes the finalization *pending*: nothing but the
    collector can reach the objects, so their finalizers run when it next
    runs rather than at a point the caller controls.  That is the state
    the optional OpenSSL cipher objects of an earlier test are left in,
    and it is what used to contaminate a measurement here.

    Collecting first is what makes the seeding reliable rather than
    likely: it puts the collector's generation zero counter back at the
    bottom of its range, so the cycles seeded here cannot trip a
    collection of their own on the way in and be gone again before the
    measurement they are meant to threaten.

    :param recorder: list every finalization appends to
    :param int count: number of unreachable cycles to leave behind
    :rtype: None
    """
    gc.collect()
    stand_in = make_finalizer_class(recorder)
    for _ in range(count):
        obj = stand_in()
        obj.self_reference = obj
        del obj


def fill_young_generation():
    """Allocate tracked objects until a collection is imminent.

    Arming the collector this way is what turns "a collection could fire
    inside the measured window" into "the next few allocations will fire
    one", which is what the guards in ``trace_line_events`` have to
    withstand.  The returned list has to stay alive for the arming to
    hold: freeing a tracked object decrements the very counter allocating
    it incremented.

    :rtype: tuple
    :returns: (list holding the allocated objects alive, generation zero
        count reached)
    """
    target = gc.get_threshold()[0] - GC_ARMING_MARGIN
    ballast = []
    while gc.get_count()[0] < target:
        ballast.append([])
    return ballast, gc.get_count()[0]


def observe_collector(recorder):
    """Record the collector's state from inside the measured window.

    A little package work is done as well, so that the measurement
    records something: assertions made against an empty recording would
    hold for a tracer that was never installed at all.

    :param recorder: list the observation is appended to, as a
        (collector enabled, generation zero count) pair
    :rtype: None
    """
    recorder.append((gc.isenabled(), gc.get_count()[0]))
    numBytes(SAMPLE_INTEGER)


def churn_inside_window(recorder):
    """Allocate past the armed threshold from inside the window.

    Arming the collector only makes a collection imminent; something has
    to make the allocations that trip it.  De-padding a real block makes
    thousands of them, which is why the invariant's own measurements are
    exposed to this at all, and this does the same for a fraction of the
    cost so that the guards can be tested without a key.  The collector's
    state is recorded first, so a caller can tell an armed collection
    that was prevented from one that was never armed.

    :param recorder: list the observation is appended to
    :rtype: None
    """
    observe_collector(recorder)
    churn = [[] for _ in range(GC_ARMING_MARGIN * 4)]
    del churn[:]


def drop_only_reference(holder):
    """Release the payload's contents from inside the measured window.

    Emptying the list drops the last reference to whatever it held, so a
    finalizer runs at that point rather than at some later and unrelated
    one.  The same package work as ``observe_collector`` follows it, so
    that a recording made with something in the holder can be compared
    against one made with an empty holder.

    :param holder: list emptied inside the window
    :rtype: None
    """
    del holder[:]
    numBytes(SAMPLE_INTEGER)


def raise_inside_window(payload):
    """Fail from inside the measured window, after doing package work.

    :param payload: ignored, the signature is the one measure() needs
    :rtype: None
    :raises ValueError: always, which is the whole point
    """
    del payload
    numBytes(SAMPLE_INTEGER)
    raise ValueError("failure raised inside the measured window")


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
        # recorded before the tracer guard so that tearDown can hold the
        # measurement to handing the process back as it found it
        self.collecting = gc.isenabled()
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
        # and neither may the collector be left in the state a
        # measurement put it in: measurements hold it off so that a
        # collection cannot run a finalizer inside a traced window, and
        # leaving it off afterwards would let the rest of the suite
        # accumulate unreclaimed cycles
        self.assertEqual(
            self.collecting, gc.isenabled(),
            "the measurement left the cyclic garbage collector %s"
            % ("disabled" if self.collecting else "enabled"))


# Test methods in this package carry no docstrings: their names describe
# the case and every module here follows that convention.  Helpers,
# classes and the module itself are documented above, as the project's
# pylint configuration requires.
# pylint: disable=missing-function-docstring


class TestTracerHygiene(UniformityTestCase):
    """The measurement is fenced off from the garbage collector.

    The invariant the rest of the module asserts is only as trustworthy
    as the instrument it is measured with, and there is one thing in the
    interpreter that executes package code without being asked to: a
    finalizer.  These tests pin the two guards that keep one out of a
    measurement - the collector is drained before each window and
    switched off inside it, and a frame named ``__del__`` is never
    recorded - and pin that neither guard outlives the window.
    """

    def setUp(self):
        UniformityTestCase.setUp(self)
        # for the same reason the probe fixtures make one untraced call:
        # no one-off cost inside a package function may be charged to
        # whichever measurement happens to run first
        numBytes(SAMPLE_INTEGER)

    def test_collector_off_in_window(self):
        recorder = []
        collecting = gc.isenabled()
        steps = trace_line_events(observe_collector, recorder)
        self.assertEqual(1, len(recorder))
        self.assertFalse(
            recorder[0][0],
            "the collector was running during the measurement, so it "
            "could have run a finalizer inside it")
        self.assertEqual(
            collecting, gc.isenabled(),
            "the measurement changed whether the collector runs, and left "
            "it changed for the rest of the suite")
        self.assertTrue(
            steps,
            "no package line events were recorded, so this assertion "
            "would be vacuous")

    def test_collector_stays_off(self):
        recorder = []
        collecting = gc.isenabled()
        gc.disable()
        try:
            trace_line_events(observe_collector, recorder)
            self.assertFalse(
                gc.isenabled(),
                "the measurement switched the collector back on, which "
                "the caller had deliberately switched off")
        finally:
            if collecting:
                gc.enable()
        self.assertFalse(recorder[0][0])

    def test_restored_after_failure(self):
        collecting = gc.isenabled()
        self.assertRaises(ValueError, trace_line_events,
                          raise_inside_window, None)
        self.assertIsNone(
            sys.gettrace(),
            "a failure inside the measurement left the tracer installed")
        self.assertEqual(
            collecting, gc.isenabled(),
            "a failure inside the measurement left the collector switched "
            "off for the rest of the suite")

    def test_garbage_drained_before(self):
        if not gc.get_threshold()[0]:
            self.skipTest("automatic collection is switched off, so there "
                          "is no collection to arm")
        recorder = []
        ballast, armed = fill_young_generation()
        try:
            trace_line_events(observe_collector, recorder)
        finally:
            del ballast[:]
        observed = recorder[0][1]
        self.assertTrue(
            observed * 2 < armed,
            "%s tracked objects were still waiting to be collected inside "
            "the measurement against %s just before it, so pending "
            "finalizers are not being run outside the window"
            % (observed, armed))

    def test_finalizer_not_recorded(self):
        recorder = []
        holder = [make_finalizer_class(recorder)()]
        clean = trace_line_events(drop_only_reference, [])
        steps = trace_line_events(drop_only_reference, holder)
        self.assertEqual(
            [1], recorder,
            "the stand-in was not finalized inside the measurement, so "
            "this assertion would be vacuous")
        self.assertEqual(
            [], finalizer_steps(steps),
            "a finalizer frame was recorded as part of the measurement, "
            "so a reclaimed object can still be charged to whichever "
            "probe class happens to release it")
        self.assertTrue(clean, "nothing was recorded at all")
        self.assertEqual(
            clean, steps,
            "a finalizer running inside the measurement changed the "
            "recorded sequence")

    def test_pending_cycles_kept_out(self):
        finalized = []
        observed = []
        seed_finalizer_cycles(finalized, FINALIZER_CYCLES)
        ballast, _ = fill_young_generation()
        try:
            steps = trace_line_events(churn_inside_window, observed)
        finally:
            del ballast[:]
        self.assertEqual(
            [], finalizer_steps(steps),
            "a collection ran inside the measurement and charged it the "
            "finalizers of %s cycles left pending before it"
            % FINALIZER_CYCLES)
        self.assertFalse(
            observed[0][0],
            "the collector was running inside a measurement that had a "
            "collection armed and the allocations to trip it")
        self.assertTrue(steps, "nothing was recorded at all")


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

    def test_uniform_with_finalizers(self):
        # the invariant end to end under the condition that used to break
        # it: unreachable cycles carrying a package finalizer waiting to
        # be collected, and a collection due within the next handful of
        # allocations, of which de-padding makes thousands.  On an
        # interpreter that cannot collect a cycle carrying a finalizer at
        # all this degenerates to a second plain uniformity measurement,
        # which is harmless.
        finalized = []
        key, ciphertexts = probe_suite(KEY_BITS_NARROW)
        seed_finalizer_cycles(finalized, FINALIZER_CYCLES)
        ballast, _ = fill_young_generation()
        try:
            traces = measure(key.decrypt, ciphertexts)
        finally:
            del ballast[:]
        for name in sorted(traces):
            self.assertEqual(
                [], finalizer_steps(traces[name]),
                "the %s class was charged the finalizers of cycles left "
                "pending before the measurement" % name)
        check_uniformity(self, self.label(KEY_BITS_NARROW, key), traces)


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
