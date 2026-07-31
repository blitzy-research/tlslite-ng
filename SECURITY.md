# Security Policy

tlslite-ng received little-to-none 3rd party security review.

tlslite-ng **CANNOT** verify certificates – users of the library must use
external means to check if certificate of the peer is the expected one.

Because python execution environment uses hash tables to store variables (that
includes functions, objects and classes) it's very hard to create
implementations that are timing attack resistant. Additionally, all integers
use arbitrary precision arithmentic, so binary operations are data dependant
(see Hubert Kario
[blog post](https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/)
on this topic). This means that CBC MAC-then-encrypt de-padding leaks timing
information and all pure python cipher implementations will leak timing
information. None of the included cipher implementations are written in a way
that even tries to hide the data dependance.

The RSA PKCS#1 v1.5 decryption path has been hardened further against the
Bleichenbacher-style padding oracle tracked as CVE-2020-26263. De-padding no
longer branches on secret data, no longer exits early inside the
secret-dependent region, and no longer runs loops whose trip count is derived
from a secret, so the sequence of operations it performs does not depend on
whether the padding was well formed, nor on the length or the two leading
version bytes of the recovered plaintext. When the padding does not check out
it still substitutes a deterministically derived synthetic plaintext, the
behaviour RFC 5246 section 7.4.7.1 requires of a TLS server that receives an
incorrectly formatted premaster secret. The Python-level path is structured
to keep the same control-flow shape for all secret-dependent input classes.

This is timing hardening, **NOT** an absolute constant-time guarantee, so the
residual is described here rather than left implicit. Because the public RSA
decryption call is documented to return a variable-length buffer, the copy
that produces it and the later truncation to 48 bytes are each a single
variable-size copy below the Python level, and those copy sizes scale with
the RSA modulus and with the recovered value. Together with CPython's
allocator behaviour, garbage collection and ordinary interpreter jitter they
leave a residual which pure Python cannot remove. Measurements for the key
sizes evaluated here found that residual to be sub-microsecond, but its
magnitude depends on the key size, the interpreter, the allocator, the
hardware and the path it is observed over, and it is **not zero**.
Decryption also still reports an error immediately when the ciphertext is the
wrong length for the modulus or encodes an integer that is not smaller than
it; that early exit is deliberate and is not an oracle, because whoever sent
the message already knows both facts about it. That uniformity also relies on
CPython caching small integers as singletons, the same interpreter behaviour
described above, so the residual timing profile may differ on other Python
implementations, which our CI does not exercise; the functional result is
identical on any conforming Python, only the timing profile would differ.

In other words, pure-python (tlslite-ng internal) implementations of all
ciphers, as well as all CBC mode ciphers working in MAC-then-encrypt mode are
**NOT** secure. Don't use them. In addition to that, use AEAD ciphersuites
(AES-GCM) or encrypt-then-MAC mode for CBC ciphers.

(Note: PyCrypto aes-gcm cipher is also not secure as it uses Python to
calculate GCM tag, see issue
[#301](https://github.com/tlsfuzzer/tlslite-ng/issues/301))

## Supported Versions

Only the current stable release is considered supported (will have fixes to
security issues backported and new patches will trigger a new release).

| Version | Supported          |
| ------- | ------------------ |
| 0.8.0-alpha | :x:                |
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

## Reporting a Vulnerability

Security issues can be reported by sending an email to hkario@redhat.com.
Answer to the initial email can be expected in 2 work-days.

If an issue is recognised as a vulnerability, fixes for it will be developed
on a good faith basis.

Unless otherwise agreed to, we'd like to request the reporter to keep the
vulnerability confidential for the industry-accepted period for responsible
disclosure of 90 days. The period will be cut short if the fix is released
earlier.
