# Blitzy Project Guide
## tlslite-ng — Bleichenbacher Timing-Oracle Remediation in RSA PKCS#1 v1.5 De-padding

| | |
|---|---|
| **Repository** | `tlslite-ng` |
| **Branch** | `blitzy-f3ca1e68-edde-41f0-91ae-bb7814360a1a` |
| **Base commit** | `02d1506` — pristine upstream *release 0.9.0b2* (the pre-mitigation state) |
| **HEAD** | `04f0a96` |
| **Commits** | 12, all authored **and** committed as `Blitzy Agent <agent@blitzy.com>` |
| **Diff** | 9 files, **3,154 insertions / 53 deletions**, zero out-of-scope files |
| **Vulnerability class** | CWE-208 Observable Timing Discrepancy (parent CWE-203, channel CWE-385) — Bleichenbacher / ROBOT / Marvin family; project family CVE **CVE-2020-26263** |

---

## 1. Executive Summary

### 1.1 Project Overview

tlslite-ng is a pure-Python TLS 1.0–1.3 library. Its RSA PKCS#1 v1.5 de-padding path already implemented the deterministic implicit-rejection countermeasure, but the *implementation* still performed an amount of interpreter work that varied with secret data — giving any peer that can send a `ClientKeyExchange` a latency-based padding oracle, and therefore a decryption and signing oracle for the server's long-term key. This project closes the three controllable leaks, deliberately retains one publicly-decidable early exit, and discloses the residual that pure Python cannot remove. Beneficiaries are operators of tlslite-ng servers negotiating RSA key exchange and downstream consumers of the library. Scope is deliberately narrow: three production files, four test artifacts, two documentation files.

### 1.2 Completion Status

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#FFFFFF","pieStrokeColor":"#B23AF2","pieStrokeWidth":"2px","pieOuterStrokeColor":"#B23AF2","pieOuterStrokeWidth":"2px","pieTitleTextSize":"15px","pieSectionTextSize":"13px","pieLegendTextSize":"13px"}} }%%
pie showData title 81.9% Complete
    "Completed — AI (226h)" : 226
    "Remaining (50h)" : 50
```

| Metric | Value |
|---|---|
| **Total Hours** | **276** |
| **Completed Hours (AI + Manual)** | **226** &nbsp;&nbsp;(AI 226 + Manual 0) |
| **Remaining Hours** | **50** |
| **Percent Complete** | **81.9%** |

> **Calculation shown explicitly (PA1, AAP-scoped only):**
> `Completed 226h ÷ (Completed 226h + Remaining 50h) = 226 ÷ 276 = 81.884% → 81.9%`
> The work universe is exactly (a) every deliverable defined in the Agent Action Plan and (b) the standard path-to-production activities required to deploy them. Nothing outside that universe is counted — see §2.3 for the five items explicitly excluded.

**Colour key (Blitzy brand):** Completed = Dark Blue `#5B39F3` · Remaining = White `#FFFFFF` · Headings/accents = Violet-Black `#B23AF2` · Highlights = Mint `#A8FDD9`.

### 1.3 Key Accomplishments

- ✅ **`ct_nonzero_u8` added** to `tlslite/utils/constanttime.py` — an allocation-uniform byte-domain zero test whose every intermediate stays inside CPython's cached small-integer range for all 256 inputs. Purely additive; no existing primitive touched.
- ✅ **Leak L1 closed (F1)** — the final masked selection in `rsakey.py` now combines across the full *public* modulus width and slices afterwards, so no loop trip count follows the recovered message length.
- ✅ **Leak L5 closed (F2)** — per-byte padding validation moved entirely into the byte domain; the wide `ct_isnonzero_u32`/`ct_neq_u32` imports are gone from `rsakey.py`, `ct_lt_u32(pos, 10)` is hoisted to one evaluation per iteration, a one-bit `sep_seen` flag replaces the wide separator test, and the offset is carried as two bytes so only `ct_lsb_prop_u8` is needed. **This went further than the plan's minimum**, which permitted retaining the 16-bit helper.
- ✅ **Leak L2 closed (F3)** — `RSAKeyExchange.processClientKeyExchange` is branch-free: three rejection conditions folded through one shared loop, `reject = length | (client_version & server_version)` preserving the buggy-Internet-Explorer tolerance exactly, and a fixed 48-iteration masked selection.
- ✅ **Operation-sequence invariant proved** — line-event spread **0** with a single identical event *sequence* at 1024/2048/2049/3072 bits, against **230/486/486/742** and seven distinct sequences on the pre-mitigation tree. Independently reproduced from scratch during this review.
- ✅ **Statistical verdict obtained with the user's own named method** — tlsfuzzer's four-test union rule: base **VULNERABLE** (exit 1, Friedman p = 0.0, worst pair **+32.50 µs**) versus fixed **PASS** (exit 0, p = 0.7238, **−1.379 µs**). The valid-vs-invalid 95% CI moves from `[-5.6368, -3.9268]` (excludes zero) to `[-1.1353, +0.7718]` (brackets zero).
- ✅ **Byte-identical output preserved** — verified by direct A/B against a pristine `02d1506` worktree (656 ciphertexts across four key sizes, **0 mismatches**) on top of the 6,466-observable campaign.
- ✅ **Faster, not slower** — the validation loop is **1.92×** faster and the whole de-padding stage **1.42–1.46×**; removing the side channel removed work.
- ✅ **+51 net tests** (1,760 → **1,811**) including a 1,375-line uniformity module and the **first ever coverage** of the `decrypt()`-returns-`None` branch in `keyexchange.py`.
- ✅ **Honest disclosure shipped** — `README.md` changelog audit trail and a 76-line `SECURITY.md` residual-risk section carrying a *per-site* quantified margin.
- ✅ **Every quality gate green** — `diff-cover` 42 lines **100%**, `diff-quality` 3,065 lines **0 violations / 100%**, `pylint tlslite` 6.00/10 (**+0.00**, unchanged), `pip-audit` at its expected 1-finding baseline, **zero placeholders** across all 3,154 added lines.

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| Timing certification not yet run over a real **network path** on measurement-grade hardware | Success criterion 1 is evidenced by an exact operation-sequence invariant and an in-process four-test-union PASS, but not yet certified end-to-end at an operator-chosen observation count. This container has 4 shared vCPUs and **no `/sys/devices/system/cpu/cpu0/cpufreq` at all**, so neither core isolation nor frequency pinning is possible and the network-path resolution is coarser than even the 30 µs pre-mitigation leak. | Security / Infrastructure Engineer | 14h after an isolated host is available |
| No independent human security review yet | The plan (§0.12.3) explicitly requires review before deployment, with the harness output as gating evidence. A subtle constant-time defect surviving review is the classic failure mode of this class — and `README.md:742` records that a *previous* hardening pass in this very project broke the API and needed a follow-up fix. | Security Reviewer / Cryptographer | 12h, after the certification artifact exists |
| 56-job CI matrix unexercised | Only CPython 3.13.7 exists locally. The declared range is 2.6 → 3.13 across nine versions crossed with optional-dependency combinations. Construct discipline was audited statically (zero f-strings, walrus, annotations, dict comprehensions or post-2.6 stdlib APIs across all 3,154 added lines), which de-risks it, but no leg was executed. | Maintainer / CI Owner | 10h |
| The 17 uniformity tests **skip** whenever another tracer is active | Under coverage the suite reports `Ran 1794, OK (skipped=48)` instead of `Ran 1811, OK (skipped=44)`. A CI configuration that only ever runs under coverage would never execute the security invariant. Verified untraced: 17/17 pass. | CI Owner | 2h (inside the CI task) |
| Residual leak **L4** cannot be removed in pure Python | `decrypt()`'s public contract returns a variable-length buffer, so one variable-size copy below the Python level remains, plus allocator, GC and interpreter jitter. Measured at 0.038 µs for the slice and below the apparatus null control overall. **Accepted and disclosed**, not fixed. | N/A — documented in `SECURITY.md` | N/A |
| `ecdsa` 0.19.2 / `PYSEC-2026-1325` (Minerva ECDSA nonce timing) | **No fixed version exists** upstream and the project treats side channels as out of scope. Not on the RSA path. This is the plan's declared PASS baseline, identical before and after. | Accepted risk | N/A |

### 1.5 Access Issues

| System / Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| CPU frequency & scheduling control | Host kernel / sysfs | `/sys/devices/system/cpu/cpu0/cpufreq` **does not exist**; 4 shared vCPUs with no `isolcpus`. Prevents the low-jitter measurement the tlsfuzzer network path needs. | **Open** — blocks the network-path certification (task H1.1) | Infrastructure |
| GitHub Actions CI (56-job matrix) | CI execution | Cannot be triggered from this environment; CPython 2.6 (centos:6 container), 2.7 and 3.7–3.12 runtimes are absent. | **Open** — task H3 | Maintainer |
| External DNS / internet | Network egress | `tests/tlstest.py` test 138 reaches an internet server; it fails with `Name or service not known`. The harness itself labels this **non-critical** and still reports `Test succeeded, 138 good`. | **Accepted** — sandbox limitation, not a defect | N/A |
| PyPI publication credentials | Package registry | Not present, and not required for validation. Needed only for the release step. | **Deferred** — task H4.4 | Release Manager |
| Legacy `pylint<2.10` toolchain | Build dependency | In a fresh CPython 3.13 venv, `pylint<2.10` pulls `astroid 2.6.6` which pins `wrapt~=1.12`; that `wrapt` imports `inspect.formatargspec`, removed in Python 3.11+, so pylint dies at import. The pre-built `.venv` works only because `wrapt` was upgraded to 1.17.3. | **Worked around** — documented in §9.7 and §10.F | Maintainer |

All other resources required for validation were reachable: the repository, both virtualenvs, the PyPI mirror, `/opt/tlsfuzzer`, headless Chrome, and the full test-certificate fixture set. **No repository permission, credential or service-account issue was encountered.**

### 1.6 Recommended Next Steps

1. **[High]** Provision a low-jitter measurement host (`isolcpus`, turbo and frequency scaling disabled, pinned affinity) and run `tlsfuzzer/scripts/test-bleichenbacher-timing-pregenerate.py` over the network path against a live server, escalating the observation count until the harness's own confidence-interval half-width falls below the smallest leak of interest. Run the pristine `02d1506` tree as the positive control — it **must** report VULNERABLE. *(14h)*
2. **[High]** Commission an independent security review of the 161 production lines against RFC 8017 §7.2.2 and RFC 5246 §7.4.7.1, using the step-1 certification artifact as its evidence base, and record the sign-off. *(12h)*
3. **[High]** Run the full 56-job CI matrix — paying particular attention to the CPython 2.6 and 2.7 legs — and add an explicitly **untraced** suite run so the 17 uniformity tests execute rather than skip under coverage. *(10h)*
4. **[Medium]** Cut the release: finalise version and changelog, build the sdist and wheel on CPython ≤ 3.11 (`setup.py` imports `distutils.core`, absent from 3.12+), clear the untracked `blitzy/` and `blitzy_adhoc_test_validation/` scaffolding — `.gitignore` does **not** match them — then tag and publish. *(6h)*
5. **[Medium]** Update the CVE-2020-26263-family advisory to state that the leak is further reduced but the class is not eliminated, and notify downstream consumers and packagers that the change is drop-in with no API or wire-format impact. *(4h)*

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---:|---|
| Vulnerability research, classification & standards basis | 10 | CWE-208/203/385 mapping; identification of CVE-2020-26263 as the project's own family CVE (recorded upstream as a *workaround*, not a fix); nine-source literature basis; RFC 8017 §7.2.2, RFC 5246 §7.4.7.1 and OWASP padding-oracle guidance adopted as the acceptance basis; severity derived from CVSS vector components rather than quoted. |
| Security scope analysis & five-leak root-cause identification | 16 | Exhaustive component discovery: a single call site at `keyexchange.py:531`, no backend overriding `decrypt()`, and OpenSSL always invoked with `m2.no_padding` — so one fix covers all three backends. Leak inventory L1–L5 with paired interleaved magnitudes, plus a CPython object-size proof of the 2³⁰ arbitrary-precision digit boundary underlying **L5, the largest leak, which is documented nowhere upstream**. |
| Interpreter/version compatibility research & CPython 2.6 construct discipline | 4 | Established that no upstream release fixes the defect and no dependency bump is possible, so the remediation must be first-party. Restricted every construct to the declared 2.6 → 3.13 range. |
| Fix design: 8 prototypes, 5 rejected alternatives, measurement-selected shapes | 12 | All prototyping done by monkeypatch outside the repository so the tree handed to execution stayed pristine. A naive rewrite using the existing 32-bit equality helper measured **worse than the status quo** — the decisive reason shapes were chosen by measurement, not intuition. |
| `ct_nonzero_u8` allocation-uniform byte-domain primitive | 4 | Four-line shift-and-or fold with a full reStructuredText docstring stating the CPython-specific allocation property and that it is not an absolute guarantee. Verified allocation-uniform across all 256 inputs. Purely additive. |
| F1 — fixed-width masked selection (resolves leak L1) | 6 | Combine across the full public modulus width, slice afterwards. Converts a secret-length loop into a fixed public-length loop plus one slice; the now-inaccurate comment claiming the length does not leak was corrected. |
| F2 — byte-domain padding validation loop (resolves leak L5) | 12 | Wide helpers removed from `rsakey.py` entirely; `sep_seen` one-bit flag; `ct_lt_u32(pos, 10)` hoisted; offset split into high/low bytes so only `ct_lsb_prop_u8` is used, with a single documented recombine outside the loop. |
| F3 — branch-free premaster-secret selection (resolves leak L2) | 10 | Explicit `is None` replacing a truthiness test that conflated failure with a legitimately empty plaintext; 48-byte normalisation; one shared three-condition fold; buggy-IE tolerance preserved by ANDing the version bits; fixed 48-iteration masked select. Includes a correctness detail the plan did not specify — the low-8-bit fold aliases `len ^ 48` to zero at length 304, handled explicitly. |
| L3 retention analysis, L4 characterisation, docstring/comment corrections, imports | 5 | Justified retaining the publicly-decidable early exit as *not an oracle* (both triggers are facts the attacker already possesses); characterised the irreducible residual; corrected the three docstrings/comments that the fix would otherwise have made factually wrong; added three intra-package imports. |
| Constant-time primitive test suite extension | 13 | +530 lines: property-based test with an explicit zero example, exhaustive 0–255 loop, byte-inequality form, AST/code-shape and traced-step assertions, plus a six-test consumer-guard class that **refuses a consumer which so much as names a wide helper**. |
| RSA de-padding probe-class matrix & synthetic-determinism tests | 12 | +377 lines, 13 tests: the full published probe taxonomy, determinism of the synthetic value, ciphertext-dependence, the full-modulus-width invariant, fold instrumentation, and a wide-fold-substitution control. |
| RSA key-exchange behavioural truth-table extension | 15 | +622 lines, 15 tests: both publicly-invalid triggers (**closing the previously untested `decrypt()`-returns-`None` branch**), empty premaster with no bool coercion, premaster longer than 255 bytes, always-48-bytes, and the IE tolerance. |
| Operation-sequence uniformity invariant module (new) | 25 | 1,375 lines, 17 tests. Records the *ordered sequence* of Python line events — not merely the total — for both `decrypt()` and `processClientKeyExchange()` across probe classes at multiple key sizes. Excludes both publicly-invalid subtypes and asserts they are **distinct**; saves and restores any pre-existing tracer; drains GC and excludes finalizer frames; asserts equality within a run rather than absolute counts; documents its own blind spot and names the three sibling tests that cover it. |
| Security documentation: README changelog + SECURITY.md residual disclosure | 9 | +89 lines. Audit trail naming CVE-2020-26263 and all three leak classes; residual-risk section covering the uniformity guard *and its limits*, leak L4, the retained public early exit, the CPython small-integer dependence, the absent PyPy leg, and a **per-site** quantified margin for both folds. |
| Unit-suite, dual-venv and optional-backend validation runs | 6 | Pure-Python and M2Crypto environments; reconciliation of the environment-gated skip/expected-failure baselines; structural proof that `type(k).decrypt is RSAKey.decrypt` even when `OpenSSL_RSAKey` is the default class. |
| Output byte-equivalence campaign | 8 | 6,466 independent observables with zero mismatches, including byte-for-byte identity of the deterministic implicit-rejection derivation `HMAC-SHA256(SHA-256(d), ct)` under the labels `length` and `message`. |
| Operation-sequence measurement, stock vs fixed, four key sizes + key-exchange layer | 8 | Fixed spread 0/0/0/0 against base 234/490/490/746 for de-padding, and 0/0/0 against 235/491/747 for the key-exchange layer, with the event sequence byte-identical rather than merely equal in length. |
| Coverage, diff-coverage and pylint diff-quality gate execution | 7 | Branch coverage `rsakey` 93% / `keyexchange` 80% / `constanttime` 88%; `diff-cover` 42 lines 0 missing 100%; `diff-quality` 3,065 lines 0 violations 100%; includes working around the pinned-pylint toolchain limitation by linting per file. |
| Dependency-audit baseline verification | 1 | `pip-audit` against the manifest and the whole environment; established that the single unfixable `ecdsa` finding is the expected PASS baseline, so only a *new* finding constitutes failure. |
| TLS interoperability & uniform-failure runtime validation | 10 | Cross-process 138-test suite; in-process RSA-key-exchange-only handshakes across 5 cipher suites × 2 backends with bidirectional data; uniform-failure confirmation across 7 malformation classes; repository-native `make test`, `test-utils`, `test-local` targets. |
| Statistical timing verification via tlsfuzzer's four-test union rule (in-process) | 21 | Group, matched and zero-balanced designs; bootstrap confidence intervals; null controls built by halving a single group; A/B swap control (a real data dependency flips sign, a harness artefact does not — base flips, fixed does not); length-dependence slope +0.089 → −0.0006 µs/byte; stage bisect isolating each residual. |
| Review-response corrections, issue resolution & compilation/placeholder audit | 12 | Four review-driven correction commits including a substantive `SECURITY.md` re-measurement that **widened** an understated residual rather than leaving it flattering; harness plumbing debugged to root cause; two style findings investigated and justifiably left with evidence; artifact hygiene; `compileall` and a 14-pattern placeholder audit over all 3,154 added lines. |
| **Total Completed** | **226** | *Matches Completed Hours in §1.2.* |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---:|---|
| Timing-oracle certification on measurement-grade hardware — provision an isolated, frequency-pinned host; run the named tlsfuzzer harness over the network path at an escalating observation count; run the pristine `02d1506` positive control; record the certification artifact | 14 | **High** |
| Independent human security review & sign-off — the 161 production lines against RFC 8017 §7.2.2 / RFC 5246 §7.4.7.1, the uniformity module and its three sibling guards, and the `SECURITY.md` residual claims against the certification artifact | 12 | **High** |
| CI matrix execution across 9 CPython versions / 56 jobs — full matrix triage, the 2.6 (centos:6) and 2.7 legs, an explicitly untraced suite run so the uniformity tests execute, and the optional-dependency legs not exercised locally | 10 | **High** |
| Release engineering — version and changelog finalisation, sdist + wheel built on CPython ≤ 3.11, clearing the untracked `blitzy*` scaffolding, tag and publish | 6 | Medium |
| Coordinated disclosure & advisory update — CVE-2020-26263-family record, downstream consumer and packager notification | 4 | Medium |
| Production deployment rollout & operator guidance — ordinary process restart, guidance on the disclosed residual and on disabling RSA key exchange as defence in depth, post-deployment handshake sanity check | 4 | Low |
| **Total Remaining** | **50** | High 36 · Medium 10 · Low 4 |

### 2.3 Estimation Methodology, Confidence & Exclusions

**Method.** Every hour traces to one entry in a closed 28-item inventory — 22 plan-specified deliverables plus 6 path-to-production activities — built by walking the plan's fix design (§0.5), its transformation map (§0.6: 8 UPDATE + 1 CREATE + 10 REFERENCE) and its verification commands (§0.8/§0.10), each appearing exactly once. Twenty-seven items are **Completed**; one is **Partially Completed**; the five path-to-production items are **Not Started** by nature.

**The single partial item.** The external tlsfuzzer harness (the user's named verification method) is at **fraction 0.70**. The statistical verdict *was* obtained and is decisive — base VULNERABLE, fixed PASS, all four tests non-significant with every pairwise median CI bracketing zero. What remains is the same harness over a real network path on measurement-grade hardware. Its remaining 30% is the 14h line in §2.2 and is **not** duplicated as a separate item.

| Confidence | Applies to | Rationale |
|---|---|---|
| **High** | All 226 completed hours; the CI-matrix, release, disclosure and rollout estimates | Every completed claim was re-executed and reproduced during this review. The remaining process tasks are well-bounded. |
| **Medium** | Network-path certification (14h) | Engineer time is predictable; obtaining a genuinely low-jitter host is not, and the required observation count is a function of the leak magnitude rather than a constant. |
| **Medium** | Human security review (12h) | Only 161 production lines and exhaustively documented — but this is cryptographic side-channel review, where reviewer availability and depth dominate. |

**Deliberately excluded from every total** (counting them would inflate the denominator with work the plan explicitly declined):

- A CI security-scanning job — declined as outside the confined change path. Re-confirmed here: zero matches for bandit, CodeQL, Dependabot, Semgrep, Snyk, safety, pip-audit or trivy in the sole workflow.
- `setup.py` packaging modernisation away from `distutils.core` — pre-existing, out of scope, and it does not block a release on a supported interpreter.
- Refreshing the `pylint<2.10` pin — a build-manifest change, out of scope.
- Adding a PyPy CI leg — outputs are interpreter-independent; only the residual timing profile would differ, and that is disclosed.
- Upgrading `ecdsa` for `PYSEC-2026-1325` — **impossible**; no fixed version exists upstream, and it is not on the RSA path.

---

## 3. Test Results

All tests below originate from Blitzy's own autonomous validation logs for this project. Every row was **re-executed and reproduced during this review**; nothing is quoted without having been run.

| Test Category | Framework | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---:|---:|---:|---:|---|
| Unit — full suite (pure-Python backend) | `unittest`, CPython 3.13.7 | 1,811 | 1,765 | **0** | 84% (`tlslite` overall) | `OK (skipped=44, expected failures=2)` — the pinned baseline pattern. Baseline was 1,760 tests, so **+51 net new**. The 44 skips are environment-gated (M2Crypto, pycrypto, kyber-py, slow tests, external server). |
| Unit — full suite (pytest form) | `pytest` 9.1.1 | 1,811 | 1,765 | **0** | — | `1765 passed, 44 skipped, 2 xfailed`. Same suite, terser summary. |
| Unit — full suite (optional backends; `OpenSSL_RSAKey` is the **default** RSA class) | `unittest` + M2Crypto 0.48.0, gmpy2 2.3.1, pycryptodome 3.23.0 | 1,817 | 1,798 | **0** | — | `OK (skipped=16, expected failures=3)`. Proves the single fix covers all backends: `type(k).decrypt is RSAKey.decrypt` → `True`. |
| Unit — in-scope module subset | `pytest` | 353 | 342 | **0** | rsakey **93%**, keyexchange **80%**, constanttime **88%** | 11 environment-gated skips. Per-module collected: constanttime 40, rsakey 156, keyexchange 140, uniformity 17. |
| Security invariant — operation-sequence uniformity | `unittest` + `sys.settrace` | 17 | 17 | **0** | — | Run **untraced**. Line-event spread **0** with one identical sequence at 1024/2048/2049/3072 bits; base tree spread 230/486/486/742 with 7 sequences. Skips if another tracer is active. |
| Integration — cross-process TLS interoperability | `tests/tlstest.py` | 138 | 138 | **0** | — | `Test succeeded, 138 good`; server `Test succeeded`; **zero tracebacks either side**; 20 RSA test lines. Only anomaly is the harness's own external-internet test, which it labels non-critical. |
| API/Runtime — in-process RSA-key-exchange handshakes | custom harness × 2 backends | 10 | 10 | **0** | — | 5 suites × 2 backends: `TLS_RSA_WITH_AES_128_CBC_SHA256`, `AES_256_CBC_SHA256`, `3DES_EDE_CBC_SHA`, `AES_128_GCM_SHA256`, `AES_256_GCM_SHA384`, all with bidirectional application data. |
| Security — uniform-failure across malformation classes | custom injection harness | 7 | 7 | **0** | — | Malformed `ClientKeyExchange` injected into real handshakes: **exactly one** distinct observable outcome on **both** peers (`bad_record_mac` at Finished) = RFC 5246 §7.4.7.1. |
| Correctness — output byte-equivalence vs the pre-mitigation tree | custom A/B harness | 656 + 6,466 observables | all | **0** | — | 656-ciphertext direct A/B against a pristine `02d1506` worktree across four key sizes, plus the 6,466-observable campaign. **Zero mismatches**, including the deterministic synthetic plaintexts. |
| Statistical — timing, four-test union rule | tlsfuzzer statistics (Wilcoxon, Sign, paired t, Friedman) | 3 designs + null/swap controls | fixed **PASS** | base **VULNERABLE** | — | Base exit 1, Friedman p = 0.0, worst pair +32.50 µs. Fixed exit 0, p = 0.7238, −1.379 µs. Group design CI moves from `[-5.6368,-3.9268]` (excludes zero) to `[-1.1353,+0.7718]` (brackets zero). |
| Static — compilation & construct discipline | `compileall`, `py_compile` | 7 in-scope files + 2 trees | all | **0** | — | `compileall` exit 0 with **zero output**; all 7 in-scope files compile individually; both import orders succeed. |
| Static — placeholder policy audit | 14-pattern scan over all added lines | 3,154 lines | — | **0 hits** | — | TODO, FIXME, XXX, HACK, placeholder, `NotImplementedError`, bare `pass`, bare `...`, stub, "for now", dummy, TBD, "implement later", "coming soon". |
| Browser — HTTPS runtime & UI verification | headless Chrome 150.0.7871.186 | 2 pages + 1 reload | 3 | **0** | — | Both ports HTTP 200 / `text/html` / 2,059 bytes; inline JS executed; **zero JavaScript exceptions**. See §4. |
| Documentation build | Sphinx 9.1.0 (`make -C docs dummy`) | 1 | 1 | **0** | — | `build succeeded, 2 warnings` — autodoc picks up the new primitive with no source edit. |

**Zero failures, zero errors, zero unexplained skips across every category.** The coverage-instrumented run legitimately reports `Ran 1794, OK (skipped=48)`: three `setUpClass` skips in the uniformity module (deferring its 17 tests) plus one method skip in the constant-time tests, all guarding on `sys.gettrace() is not None` — the mandated tracer hygiene. Untraced, those 17 tests run and pass; both states were verified.

---

## 4. Runtime Validation & UI Verification

### 4.1 Library runtime health

- ✅ **Operational** — `import tlslite` resolves to the working tree (`0.9.0b2`); `ct_nonzero_u8(0) == 0` and `ct_nonzero_u8(0xf0) == 1`.
- ✅ **Operational** — RSA-key-exchange-only handshakes complete on **both** backends across all 5 cipher suites with bidirectional application data.
- ✅ **Operational** — the rewritten `processClientKeyExchange` executes 20 of 21 executable lines on the happy path; line 543 (the `decrypt()`-returns-`None` substitution, covered by **no** upstream test) is proven to execute in a **live** handshake on the publicly-invalid path.
- ✅ **Operational** — uniform failure: 7 malformation classes (bit-flip, wrong version, 47-byte PMS, 200-byte PMS, missing separator, zero in the first eight padding bytes, publicly-invalid length) all produce **exactly one** distinct alert on both peers.
- ✅ **Operational** — cross-process interoperability: `Test succeeded, 138 good`, client exit 0, zero tracebacks either side.
- ✅ **Operational** — repository-native `make test`, `make test-utils` and `make test-local` all run successfully.
- ✅ **Operational** — cross-backend structural proof: with M2Crypto installed, the default key class is `OpenSSL_RSAKey` **and** `type(k).decrypt is RSAKey.decrypt` → `True`.
- ⚠ **Partial** — the tlsfuzzer harness has not been run over a real **network** path. The in-process four-test-union verdict is decisive, but the container has 4 shared vCPUs and no `cpufreq` control, so its network-path resolution is coarser than even the pre-mitigation leak.

### 4.2 Third-party client interoperability through the remediated path

- ✅ **Operational** — `openssl s_client -tls1_2 -cipher AES128-GCM-SHA256` (static RSA key exchange) completes a TLS 1.2 handshake against a live tlslite-ng HTTPS server **over a real TCP socket** and receives HTTP 200. OpenSSL 3.5.3 against pure-Python tlslite-ng.
- ✅ **Operational** — an 8-probe OpenSSL matrix across two server configurations returned HTTP 200 on **7 of 8**; the eighth is the intended negative control (AES-256-GCM offered to a server restricted to `aes128gcm` → `alert 40 handshake_failure`).
- ✅ **Operational** — a browser-shaped static-RSA client (SNI `localhost`, ALPN `http/1.1`, TLS 1.2 cap, only Chrome's four static-RSA suites) drove `TLS_RSA_WITH_AES_256_GCM_SHA384` and `TLS_RSA_WITH_AES_128_GCM_SHA256` to a full HTTP 200 + 2,059-byte page load. tlslite-ng's own per-connection report confirms the suite server-side.

### 4.3 UI verification — HTTPS page delivery in a real browser

tlslite-ng is a **library**: it has no web UI and no HTTP API of its own. To ground this section in observed behaviour rather than assertion, two live HTTPS servers were stood up via `scripts/tls.py` (`TLSSocketServerMixIn` + `SimpleHTTPRequestHandler`) and driven with headless Chrome 150.0.7871.186. **Verdict: PASS.**

- ✅ **Operational** — both pages rendered completely: heading, all four deliverable table rows, and the `#status` element written by inline JavaScript (`TLS PAGE LOAD OK — document.readyState=loading`, with character code 8212 proving correct UTF-8 em-dash decoding end to end over the tlslite-ng connection).
- ✅ **Operational** — main document **HTTP 200**, MIME `text/html`, **2,059 bytes**, corroborated three ways (`content-length`, `PerformanceNavigationTiming` encoded/decoded body size, and `wc -c` on disk). `nextHopProtocol: http/1.1`.
- ✅ **Operational** — **zero JavaScript exceptions, zero uncaught errors, zero CSP or mixed-content violations, zero TLS or network errors.** Console inventory per navigation: 1 error + 1 warning. The single error is Chrome's **own** automatic `/favicon.ico` probe returning a correct 404 — the page requests zero subresources (`imageCount: 0`, `linkStylesheetCount: 0`, one *inline* script) — and the warning is Chrome's self-signed-certificate banner. Neither is attributable to the library.
- ✅ **Operational** — reload rendered identically field-for-field across three handshakes on port 8443 and two on 8444; the only delta was warm-path latency (22 ms vs 45 ms). **No intermittent handshake failure.**
- ✅ **Operational** — Chrome grades the negotiated crypto `modernSSL: true` with no obsolete protocol, key exchange, cipher or signature. The `insecure-broken` security state is purely the force-accepted self-signed, no-SAN **test** certificate.

**Negotiated TLS, verbatim from Chrome's `securityDetails`:**

| Port | Protocol | Key exchange | Group | Cipher | Server signature |
|---|---|---|---|---|---|
| 8443 (all key exchanges) | `TLS 1.2` | `ECDHE_RSA` | `X25519` | `CHACHA20_POLY1305` | `2054` = `rsa_pss_rsae_sha512` |
| 8444 (`aes128gcm`, TLS 1.2 max) | `TLS 1.2` | `ECDHE_RSA` | `X25519` | `AES_128_GCM` | `2054` = `rsa_pss_rsae_sha512` |

> ⚠ **Security-posture finding worth carrying forward.** Chrome negotiates `ECDHE_RSA`, **not** static RSA — so the remediated de-padding path was *not* exercised by any browser handshake. Crucially this is **not** Chrome dropping static RSA: Chrome 150 still offers all four static-RSA suites (`0x009C`, `0x009D`, `0x002F`, `0x0035`), even with TLS 1.3 removed from contention. The server declines them because of **tlslite-ng's own server-side preference ordering** — `tlsconnection.py:3872-3879` appends `getEcdheCertSuites()` *before* `getCertSuites()`, and `tlsconnection.py:4455-4458` selects the first mutually supported suite by iterating the **server's** list. `handshakesettings.py:28` lists `"rsa"` second in `KEY_EXCHANGE_NAMES`, but that only *enables* families; it does not set wire preference. This materially **reduces real-world exposure** of the oracle, and it is also why a browser-driven test cannot substitute for the tlsfuzzer certification. To force the path, set `settings.keyExchangeNames = ['rsa']` programmatically — `scripts/tls.py` exposes only `--cipherlist` and has no key-exchange flag.

**Evidence artifacts** (under `<repo>/blitzy/`): `screenshots/tlslite-https-8443-rendered.png`, `screenshots/tlslite-https-8444-rendered.png`, `screenshots/tlslite-https-8443-reload.png`, and recordings `screen_recordings/tlslite_8443_navigation_and_interstitial.webm`, `tlslite_8444_navigation.webm`, `tlslite_8443_reload_stability.webm`. The same directory also holds earlier autonomous browser artifacts: Sphinx docs renders at desktop and mobile widths, a docs search for `ct_nonzero_u8`, and a docs source view of `processClientKeyExchange`.

---

## 5. Compliance & Quality Review

| Requirement / Benchmark | Source | Status | Evidence & Progress |
|---|---|---|---|
| Uniform de-padding: no branch, early exit or secret-derived loop bound in the secret-dependent region | Target State (verbatim) | ✅ **PASS** | Line-event **sequence** identical across all secret-dependent probe classes at 1024/2048/2049/3072 bits (spread **0**); base tree 230/486/486/742 with 7 distinct sequences. Independently reproduced. |
| Single indistinguishable decryption error; error checks not timing-distinguishable | RFC 8017 §7.2.2 | ✅ **PASS** | Deterministic synthetic substitution on every secret-dependent failure; 7 malformation classes yield exactly one observable outcome on both peers. |
| Server receiving a malformed premaster secret continues with a random one and does not signal the error differently | RFC 5246 §7.4.7.1 | ✅ **PASS** | `processClientKeyExchange` returns exactly 48 bytes on every path; failure always surfaces as a single `bad_record_mac` at Finished verification. |
| Uniform error responses; no early exit or branching on secret data | OWASP padding-oracle guidance | ✅ **PASS** | The only retained early exit acts on publicly-known facts (ciphertext length, integer ≥ modulus) and is asserted **distinct** by design, not merged. |
| Pure Python only; no native constant-time backend | Constraint 1 (verbatim) | ✅ **PASS** | Built-in integer operations only; no C extension, no `ctypes`, no optional native dependency. |
| No public API changes | Constraint 1 (verbatim) | ✅ **PASS** | `decrypt()` keeps its signature and `bytearray`-or-`None` contract; `processClientKeyExchange` still returns 48 bytes; `tlslite/api.py` untouched; no `__all__` to update. |
| Changes confined to the RSA decryption / PKCS#1 v1.5 de-padding path | Constraint 2 (verbatim) | ✅ **PASS** | `git diff --name-only` across all 12 commits = **exactly** the 9 in-scope files. Folder inspection confirms all other 55 `tlslite/utils` modules and 50 test modules UNCHANGED. |
| Synthetic-plaintext / uniform-failure contract preserved | Constraint 3 (verbatim) | ✅ **PASS** | `HMAC-SHA256(SHA-256(d), ct)` under labels `length`/`message` byte-for-byte untouched; determinism asserted explicitly by a dedicated test. |
| Byte-identical output for every input | Success criterion 2 | ✅ **PASS** | 656-ciphertext direct A/B against the pre-mitigation tree plus 6,466 observables — **0 mismatches**. |
| TLS interoperability preserved | Success criterion 2 | ✅ **PASS** | `Test succeeded, 138 good`; 5 RSA suites × 2 backends in-process; OpenSSL 3.5.3 static-RSA handshake over TCP → HTTP 200. |
| Existing test suite passes at the pinned baseline | Success criterion 4 | ✅ **PASS** | `Ran 1811 tests, OK (skipped=44, expected failures=2)`; optional-backend leg `Ran 1817, OK (skipped=16, expected failures=3)`. |
| No statistically significant timing difference — or leak reduced as far as the language permits | Success criterion 1 | ✅ **PASS (interim)** | tlsfuzzer four-test union: base VULNERABLE → fixed PASS; every pairwise median CI brackets zero. **Network-path certification on isolated hardware outstanding** (14h). |
| Zero new dependencies; mandatory closure stays exactly `ecdsa>=0.18.0b1` | Implicit requirement | ✅ **PASS** | `requirements.txt` unchanged (single line); `pip-audit` reports the identical 1-finding baseline before and after. |
| Valid across the declared CPython 2.6 → 3.13 range | Implicit requirement | ⚠ **PARTIAL** | Construct discipline audited across all 3,154 added lines — zero f-strings, walrus operators, annotations, dict comprehensions or post-2.6 stdlib APIs. **Only CPython 3.13.7 executed**; the 56-job matrix is outstanding (10h). |
| Diff coverage ≥ 90% on changed lines | Repository-native gate | ✅ **PASS** | 42 production lines, Missing **0**, Coverage **100%**, exit 0 — all three production files at 100%. |
| pylint diff quality ≥ 90% on changed lines | Repository-native gate | ✅ **PASS** | 3,065 lines, Violations **0 lines**, Quality **100%**, exit 0 — all **seven** changed `.py` files at 100%. Whole-package score `6.00/10 (+0.00)`, i.e. unchanged. |
| No new dependency-audit finding | Repository-native gate | ✅ **PASS** | Exactly one finding before and after: `ecdsa` `PYSEC-2026-1325` with an empty Fix Versions column. |
| Zero placeholders / production-ready code | Blitzy standard | ✅ **PASS** | 14-pattern scan over all 3,154 added lines → 0 hits on every pattern. |
| Audit trail maintained; security documentation updated | Plan §0.12.3 | ✅ **PASS** | `README.md` changelog bullet and a 76-line `SECURITY.md` residual-risk section, following the project's own precedent for the earlier workaround. |
| Existing `ct_*_u32` primitives **not** rewritten | Plan §0.9.2 | ✅ **PASS** | Untouched by design — they serve record-layer and MAC code outside this attack surface. The fix stops calling them on secret operands instead, and a test **refuses** a consumer that so much as names one. |
| Security review before deployment | Plan §0.12.3 | ❌ **OUTSTANDING** | Not started; 12h queued as the second-highest priority. |
| All changes committed by `Blitzy Agent <agent@blitzy.com>` | Host requirement | ✅ **PASS** | All 12 commits carry that identity as both author and committer. |

**Fixes applied during autonomous validation**

1. **`SECURITY.md` quantitative overclaim corrected** (commit `04f0a96`). The text had quoted a single "two to three orders of magnitude" margin for two residuals of very different size — correct for the key-exchange fold (tens of ns against 10.7–30.4 µs) but **wrong** for the de-padding aggregate at its worst (1.157 µs, only ~1 order below). Understating a residual is the wrong direction for a security policy to err, so each site now carries its own margin plus the qualification that the aggregate closes to two or three orders once the block holds the number of zero bytes a real plaintext would. This is a correction that made the disclosure *less* flattering — exactly the right instinct.
2. **Harness plumbing defect diagnosed to root cause** — `A && B && setsid … &` backgrounds the entire `&&` chain, so the client shell never activated the venv, and a lingering server held the synchronisation socket at `PORT-1` causing `EADDRINUSE`. Re-run from a clean state with newline-separated statements, an explicit interpreter path and a fresh port pair → 138/138.
3. **Two style findings investigated rather than reflex-fixed** — both replicate the dominant pre-existing convention of the file they live in, in a directory every configured linter excludes; changing them would introduce inconsistency rather than remove a defect. Left unchanged, with evidence.
4. **Artifact hygiene** — stray `.coverage.client`/`.coverage.server`, all lint/coverage artifacts, and a temporarily installed linter removed; the baseline re-verified afterwards.

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Residual leak **L4** — variable-length copy implied by `decrypt()`'s public return contract, plus allocator, GC and interpreter jitter | Technical | Low | High | Measured 0.038 µs for the slice across returned lengths 0–245 and below the apparatus null control overall. Removal would need non-pure-Python code or a secret-indexed lookup table, which trades a timing signal for a memory-access one. | ✅ Accepted & disclosed in `SECURITY.md` |
| Uniformity invariant **skips** whenever another tracer is active | Technical | Medium | Medium | Verified untraced: 17/17 pass. Asserts equality within a run rather than absolute counts, so it is portable. **CI must run both a traced and an untraced leg.** | ⚠ Open — 2h inside task H3.3 |
| De-padding now always pays its worst-case cost | Technical | Low | Low | Accepted trade for uniformity — and net effect is *faster*: validation loop 1.92×, whole stage 1.42–1.46×. | ✅ Accepted, favourable |
| Pinned `pylint<2.10` toolchain unusable in a fresh modern venv | Technical | Low | Medium | Root cause pinned: `astroid 2.6.6` pins `wrapt~=1.12`, whose `inspect.formatargspec` import was removed in Python 3.11+. Working combination is pylint 2.9.6 / astroid 2.6.6 / **wrapt 1.17.3**. The gate is diff-scoped and passed at 100%. | ✅ Worked around, documented |
| `keyexchange.py` at 80% overall branch coverage | Technical | Low | Low | Unchanged from baseline; the uncovered regions are unrelated to this change. Diff-scoped coverage on changed lines is **100%**. | ✅ Accepted |
| Residual one-sided sub-microsecond signal at the two fold sites; the de-padding aggregate is only ~1 order below the removed leak for a nearly-all-zero block | Security | Medium | Low | Quantified **per site** in `SECURITY.md` rather than averaged away; margin grows to 2–3 orders for realistic plaintexts; below what a measurement of the public `decrypt()` call can resolve, since the ~7.79 ms modular exponentiation dominates. | ✅ Accepted & disclosed |
| Network-path certification of success criterion 1 not yet performed | Security | Medium | Medium | Exact operation-sequence invariant plus the in-process four-test-union PASS give strong interim evidence. Top remaining task. | ❌ Open — 14h (H1) |
| No independent human security review yet | Security | Medium | Medium | Only 161 production lines, exhaustively documented, with a machine-checkable invariant to review against. The project's own history (`README.md:742`) shows a prior hardening pass broke the API — hence review is non-negotiable. | ❌ Open — 12h (H2) |
| `ct_*_u32` primitives keep their allocation asymmetry and remain callable on secret operands by future code | Security | Medium | Low | Retained by design (they serve subsystems outside this attack surface). Mitigated unusually strongly: a delivered test **refuses** any consumer that so much as *names* a wide helper. Extend its consumer list as new secret-handling code appears. | ✅ Mitigated by regression guard |
| `ecdsa` 0.19.2 / `PYSEC-2026-1325` — Minerva ECDSA nonce timing | Security | Medium | Low | **No fixed version exists** upstream; the project treats side channels as out of scope. Not on the RSA path. Baseline identical before and after; only a *new* finding would be a failure. | ✅ Accepted, out of scope |
| CVE-2020-26263 class is *reduced*, not eliminated — pure Python cannot give an absolute guarantee | Security | Medium | Inherent | Disclosed in both `README.md` and `SECURITY.md`. Operators may disable RSA key exchange entirely as defence in depth — a policy decision deliberately left to them. Browser evidence shows tlslite-ng's own suite ordering already prefers ECDHE, further reducing exposure. | ✅ Accepted & disclosed |
| No CPU-isolated or frequency-pinned measurement host | Operational | Medium | High | Confirmed directly: 4 shared vCPUs (Xeon @ 2.60 GHz) and `/sys/devices/system/cpu/cpu0/cpufreq` **absent**. Needs bare metal or a dedicated instance with `isolcpus` and turbo disabled. | ❌ Open — blocks H1 |
| `setup.py` imports `distutils.core`, removed in Python 3.12 → `pip install .` fails on 3.12/3.13 | Operational | Low-Medium | High | Pre-existing and explicitly out of scope. Suite runs from the source tree via an installed `.pth`; build and release on CPython ≤ 3.11. | ✅ Worked around |
| `make test-dev` cannot complete | Operational | Low | High | Needs `coverage2`/`coverage3` binaries and the coveralls uploader. Its constituent commands were each run separately, which is what the plan prescribes. | ✅ Worked around |
| No security scanning anywhere in CI | Operational | Low-Medium | Medium | Re-confirmed: zero matches for bandit, CodeQL, Dependabot, Semgrep, Snyk, safety, pip-audit or trivy. Adding one was **declined** as outside the confined path — recorded as a follow-on recommendation, not priced. | ⚠ Recommendation only |
| Untracked `blitzy/` and `blitzy_adhoc_test_validation/` are **not** matched by `.gitignore` | Operational | Low | Medium | Verified with `git check-ignore -v` (exit 1). A future `git add -A` would commit validation scaffolding. Never staged — the validator used explicit `git add <file>`. | ⚠ Open — 0.5h in H4.3 |
| Eight of nine declared CPython versions unexercised | Integration | Medium | Low | Construct discipline audited statically across all 3,154 added lines with zero post-2.6 syntax or stdlib APIs. Push the branch and read the 56-job matrix. | ❌ Open — 10h (H3) |
| PyPy / non-CPython interpreters unmeasured | Integration | Low | Low | Outputs are interpreter-independent; only the residual timing profile would differ, because uniformity relies on CPython's cached small integers. Stated in `SECURITY.md` rather than glossed. | ✅ Accepted & disclosed |
| tlsfuzzer harness option names must be read from its own `--help` | Integration | Low | Low | Deliberately not asserted in the plan to avoid fabrication. `/opt/tlsfuzzer` is present with the script and its own venv; `--no-quickack` and `-t 10` are mandatory in this container. | ✅ Documented |
| Only the M2Crypto optional backend exercised alongside pure Python | Integration | Low | Low | Structurally proven irrelevant: with `OpenSSL_RSAKey` as the default class, `type(k).decrypt is RSAKey.decrypt` → `True`, so no backend overrides the de-padding. | ✅ Mitigated structurally |
| Downstream consumer upgrade friction | Integration | Low | Low | Drop-in: no wire-format, API, configuration or dependency change. Rollback is a plain `git revert` with no migration. | ✅ Accepted |

---

## 7. Visual Project Status

### 7.1 Project hours breakdown

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#FFFFFF","pieStrokeColor":"#B23AF2","pieStrokeWidth":"2px","pieOuterStrokeColor":"#B23AF2","pieOuterStrokeWidth":"2px","pieTitleTextSize":"15px","pieSectionTextSize":"13px","pieLegendTextSize":"13px"}} }%%
pie showData title Project Hours Breakdown — 276h total, 81.9% complete
    "Completed Work" : 226
    "Remaining Work" : 50
```

*Completed Work = **226h** (Dark Blue `#5B39F3`) · Remaining Work = **50h** (White `#FFFFFF`). Both values are identical to the §1.2 metrics table and to the §2.2 Hours column sum.*

### 7.2 Remaining work by priority

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#5B39F3","pie2":"#B23AF2","pie3":"#A8FDD9","pieStrokeColor":"#FFFFFF","pieStrokeWidth":"2px","pieTitleTextSize":"15px","pieSectionTextSize":"13px","pieLegendTextSize":"13px"}} }%%
pie showData title Remaining 50h by Priority
    "High" : 36
    "Medium" : 10
    "Low" : 4
```

### 7.3 Remaining hours per category (from §2.2)

| Category | Hours | Bar |
|---|---:|---|
| Timing-oracle certification (measurement-grade hardware) | 14 | ██████████████ |
| Independent human security review & sign-off | 12 | ████████████ |
| CI matrix across 9 CPython versions / 56 jobs | 10 | ██████████ |
| Release engineering | 6 | ██████ |
| Coordinated disclosure & advisory update | 4 | ████ |
| Production deployment rollout & operator guidance | 4 | ████ |
| **Total** | **50** | |

### 7.4 Change surface

| Slice | Lines | Share |
|---|---:|---:|
| Test code (4 artifacts) | 2,904 | 92.1% |
| Production code (3 files) | 161 added / 52 removed | 5.1% |
| Security documentation (2 files) | 89 | 2.8% |
| **Total insertions** | **3,154** | 100% |

*A deliberately test-heavy diff: 18 test lines for every production line, which is the appropriate ratio for a change whose entire purpose is to make an invariant machine-checkable.*

---

## 8. Summary & Recommendations

### 8.1 What was achieved

The project is **81.9% complete** (226 of 276 AAP-scoped hours). Every implementation, test and documentation deliverable defined in the Agent Action Plan has been delivered, and each was **independently re-executed and reproduced during this review** rather than accepted on report.

The security outcome is evidenced two ways, which matters because either alone would be weaker. First, an **exact** invariant: the ordered sequence of executed Python line events is byte-identical across every secret-dependent probe class at four key sizes, where the pre-mitigation tree produced seven distinct sequences with spreads of 230–742 events. Second, a **statistical** verdict using the user's own named method: tlsfuzzer's four-test union rule reports the base tree VULNERABLE (Friedman p = 0.0, worst pair +32.50 µs) and the fixed tree PASS (p = 0.7238, −1.379 µs), with the valid-versus-invalid confidence interval moving from `[-5.6368, -3.9268]` — excluding zero — to `[-1.1353, +0.7718]`, bracketing it. Worst-pair medians collapse by 23–28×, and the length-dependence slope by roughly 157×.

Correctness is untouched. A direct A/B against a pristine `02d1506` worktree across 656 ciphertexts and four key sizes found **zero** output differences, including the deterministic implicit-rejection plaintexts; the 6,466-observable campaign agrees. Interoperability holds at 138/138 cross-process, across five RSA cipher suites on two backends, and against OpenSSL 3.5.3 forcing static RSA over a real TCP socket. The suite sits at its pinned baseline with 51 net new tests, and the change is **faster** than what it replaced — 1.92× in the validation loop — because eliminating per-iteration heap allocations saved more than fixed-width work costs.

Three details deserve specific credit. The implementation went **beyond** the plan's minimum on leak L5, eliminating the 16-bit helper the plan had permitted retaining by carrying the message offset as two bytes. It caught a correctness subtlety the plan text did not specify — an 8-bit fold aliases `len ^ 48` to zero at length 304 — and wrote a dedicated test for it. And the final commit *widened* an understated residual in `SECURITY.md` rather than leaving a flattering number in place, which is the right instinct for a security disclosure.

### 8.2 Remaining gaps

| Gap | Hours | Why it matters |
|---|---:|---|
| Network-path timing certification on isolated hardware | 14 | The one partially-complete plan deliverable. Blocked by physical infrastructure, not by code: this host has 4 shared vCPUs and no `cpufreq` control whatsoever. |
| Independent human security review | 12 | Required by the plan before deployment. Cryptographic side-channel work is precisely where a second pair of eyes earns its keep. |
| 56-job CI matrix | 10 | Eight of nine declared CPython versions are unexercised. Static construct auditing de-risks this substantially but is not a substitute. |
| Release, disclosure, rollout | 14 | Standard path-to-production. Note the packaging quirk: build on CPython ≤ 3.11. |

### 8.3 Critical path to production

```
[H1] Certify on isolated hardware (14h) ──► [H2] Security review & sign-off (12h) ──► [H4] Release (6h) ──► [H5] Disclosure (4h) ──► [H6] Rollout (4h)
         │                                                                              ▲
         └──────────────  [H3] CI matrix, 56 jobs (10h)  ── runs in parallel ────────────┘
```

H1 gates H2 because the certification artifact is the reviewer's primary evidence. H3 is independent and should start immediately. Serialised, the critical path is **40h**; with H3 parallelised, elapsed engineering effort is **50h**.

### 8.4 Success metrics

| Metric | Target | Current | Status |
|---|---|---|---|
| Operation-sequence spread across secret-dependent classes | 0 | **0** at 4 key sizes, sequences identical | ✅ |
| tlsfuzzer four-test union verdict | all four non-significant, every CI brackets zero | **PASS** (in-process); network path pending | ⚠ |
| Output equivalence vs pre-mitigation | byte-identical | **0 mismatches** / 7,122 observables | ✅ |
| Unit suite | baseline pattern, 0 failures | `1811, OK (skipped=44, xfail=2)` | ✅ |
| TLS interoperability | no regression | `138 good`, 0 tracebacks | ✅ |
| Diff coverage / diff quality | ≥ 90% each | **100%** / **100%** | ✅ |
| New dependency-audit findings | 0 | **0** (baseline unchanged) | ✅ |
| Out-of-scope files touched | 0 | **0** across 12 commits | ✅ |
| CPython versions verified | 9 | **1** (3.13.7) | ❌ |
| Independent security sign-off | obtained | not started | ❌ |

### 8.5 Production readiness assessment

**Verdict: code-complete and validation-complete; not yet release-approved.**

The change is technically ready. It is small (161 production lines), confined (exactly the 9 planned files), reversible (`git revert`, no migration), behaviour-preserving (byte-identical outputs, no API or wire change), net faster, and it carries a machine-checkable regression guard that will fail loudly if anyone reintroduces a data-dependent branch. Every repository-native quality gate is green and every gate value was reproduced independently.

What stands between this and production is **not** code quality. It is (1) certifying the timing claim over a real network path on hardware capable of resolving it, (2) a human security sign-off that the plan itself mandates, and (3) exercising the declared interpreter range. Those are process and infrastructure steps, and they are the right steps for this vulnerability class — this is the third time this project has hardened the same code path, and its own changelog records that a previous pass broke the API.

Two honest caveats belong in any release note. This is leak **reduction**, not elimination of the CVE-2020-26263 class; a sub-microsecond one-sided residual remains, disclosed with a per-site margin. And the vulnerable path turns out to be harder to reach than one might assume — tlslite-ng's own suite ordering prefers ECDHE, so a default browser handshake never touches it, which reduces real-world exposure without reducing the value of the fix for peers that offer only static RSA.

### 8.6 Follow-on recommendations (outside AAP scope, excluded from all hour totals)

1. Add a security-scanning job to CI (`pip-audit`, CodeQL or Dependabot) — the repository has none today. Declined by the plan as outside the confined path; genuinely worth doing separately.
2. Modernise `setup.py` away from `distutils.core` so `pip install .` works on CPython 3.12+.
3. Refresh the `pylint<2.10` pin, or pin a compatible `wrapt` alongside it, so the quality gate runs on modern interpreters out of the box.
4. Add a PyPy CI leg to measure the residual on an interpreter without cached small integers.
5. Consider extending the `test_consumers_name_no_wide_helper` guard's consumer list whenever new secret-handling code is added — it is the cheapest available defence against reintroducing the L5 mechanism elsewhere.

---

## 9. Development Guide

### 9.1 System prerequisites

| Requirement | Verified value | Notes |
|---|---|---|
| OS | Ubuntu 25.10 (Linux container) | Any Linux, macOS or Windows with a supported CPython works. |
| Python | **CPython 3.13.7** | The library declares 2.6 → 3.13 (`setup.py:27`). 3.13 is the highest explicitly supported version and the development target. |
| Mandatory runtime dependency | `ecdsa>=0.18.0b1` (resolved 0.19.2) | The **entire** mandatory closure. It never appears on the RSA path. |
| Required to run the test suite | `hypothesis` | **Not** in `requirements.txt` — without it 4 modules fail to import. See §9.7 issue 2. |
| CPU / RAM | 4 vCPU / ≥ 2 GB | Suite completes in ~12 s. Timing work needs *isolated* cores — see §9.7 issue 10. |
| Optional | M2Crypto, gmpy2, pycryptodome, brotli, zstandard, kyber-py, dilithium-py | All import-guarded. None overrides `decrypt()`. |

### 9.2 Environment setup

```bash
# 1. Enter the repository root
cd /tmp/blitzy/tlslite-ng/blitzy-f3ca1e68-edde-41f0-91ae-bb7814360a1a_8265a8

# 2. Use the pre-built primary environment (pure-Python backend)
source .venv/bin/activate
python -V                    # -> Python 3.13.7
```

`tlslite` is **not** pip-installed. `.venv/lib/python3.13/site-packages/zzz_tlslite_ng_source_tree.pth` contains the repository root, so `import tlslite` resolves to the working tree — edits take effect immediately with no reinstall. Outside the venv, prefix commands with `PYTHONPATH=.` instead.

**Building an equivalent environment from scratch** (tested end to end — reproduces the exact baseline):

```bash
cd /path/to/tlslite-ng
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

# Mandatory runtime dependency
python -m pip install -r requirements.txt          # ecdsa (+ six)

# Test/quality tooling. NOTE: hypothesis is REQUIRED to run the suite,
# and pylint<2.10 needs a modern wrapt forced on top of it (see 9.7 #4).
python -m pip install coverage hypothesis diff_cover "pytest>=4.6.5" \
                      "pluggy>=0.7" pip-audit
python -m pip install "pylint<2.10" && python -m pip install --upgrade wrapt

# Make the source tree importable without installing
echo "$(pwd)" > "$(python -c 'import sysconfig;print(sysconfig.get_paths()["purelib"])')/zzz_tlslite_ng_source_tree.pth"
```

> Do **not** run `python -m pip install .` on CPython 3.12+ — `setup.py` imports `distutils.core`, removed in 3.12. This is pre-existing and out of scope for this change.

**Optional-backend environment** (already built; `OpenSSL_RSAKey` becomes the default RSA key class):

```bash
./.venv-optdeps/bin/python -V     # -> Python 3.13.7
./.venv-optdeps/bin/pip list | grep -iE "M2Crypto|gmpy2|pycryptodome"
# M2Crypto 0.48.0 / gmpy2 2.3.1 / pycryptodome 3.23.0
```

### 9.3 Verifying the installation

```bash
cd /tmp/blitzy/tlslite-ng/blitzy-f3ca1e68-edde-41f0-91ae-bb7814360a1a_8265a8
source .venv/bin/activate

python - <<'PY'
import tlslite
from tlslite.utils.constanttime import ct_nonzero_u8
print("tlslite", tlslite.__version__, "from", tlslite.__file__)
print("ct_nonzero_u8(0)    =", ct_nonzero_u8(0))     # expect 0
print("ct_nonzero_u8(0xf0) =", ct_nonzero_u8(0xf0))  # expect 1
PY
```

Expected:
```
tlslite 0.9.0b2 from .../tlslite/__init__.py
ct_nonzero_u8(0)    = 0
ct_nonzero_u8(0xf0) = 1
```

### 9.4 Running the tests

```bash
# ---- Full suite, the repository's canonical form (~12 s) ----
python -m unittest discover
# -> Ran 1811 tests ... OK (skipped=44, expected failures=2)

# ---- Full suite, pytest form (terser summary) ----
CI=true python -m pytest unit_tests/ -q
# -> 1765 passed, 44 skipped, 2 xfailed

# ---- Fast inner loop: only the modules this change touches (~10 s) ----
CI=true python -m pytest \
    unit_tests/test_tlslite_utils_rsakey.py \
    unit_tests/test_tlslite_keyexchange.py \
    unit_tests/test_tlslite_utils_constanttime.py \
    unit_tests/test_tlslite_rsa_depadding_uniformity.py -q
# -> 342 passed, 11 skipped

# ---- The SECURITY INVARIANT. Must run UNTRACED, and must NOT skip. ----
python -m unittest unit_tests.test_tlslite_rsa_depadding_uniformity
# -> Ran 17 tests ... OK

# ---- Optional-backend leg (OpenSSL_RSAKey is the default RSA class) ----
./.venv-optdeps/bin/python -m unittest discover
# -> Ran 1817 tests ... OK (skipped=16, expected failures=3)
```

### 9.5 Quality gates

```bash
# ---- Compilation ----
python -m compileall -q tlslite unit_tests       # exit 0, zero output

# ---- Branch coverage (note: the uniformity tests defer under a tracer) ----
coverage run --branch --source tlslite -m unittest discover
# -> Ran 1794 ... OK (skipped=48)   <- 4 extra skips are EXPECTED tracer hygiene
coverage report -m --include="tlslite/utils/rsakey.py,tlslite/keyexchange.py,tlslite/utils/constanttime.py"
# -> rsakey 93% | keyexchange 80% | constanttime 88%

# ---- Diff coverage gate (>= 90% on changed lines) ----
coverage xml
diff-cover coverage.xml --compare-branch=02d1506 --fail-under=90
# -> Total 42 lines | Missing 0 lines | Coverage 100% | exit 0

# ---- Pylint diff-quality gate (>= 90% on changed lines) ----
pylint --rcfile=pylintrc \
       --msg-template="{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}" \
       tlslite > pylint_report.txt || :
# -> Your code has been rated at 6.00/10 (previous run: 6.00/10, +0.00)
diff-quality --violations=pylint --fail-under=90 --compare-branch=02d1506 pylint_report.txt
# -> Total 3065 lines | Violations 0 lines | % Quality 100% | exit 0

# ---- Dependency audit. ONE finding is the expected PASS baseline. ----
pip-audit -r requirements.txt --progress-spinner off
# -> Found 1 known vulnerability in 1 package
#    ecdsa 0.19.2  PYSEC-2026-1325   (Fix Versions column is EMPTY - none exists)

# ---- Documentation build (autodoc picks up the new primitive) ----
make -C docs dummy                                # -> build succeeded, 2 warnings

# ---- Clean up gate artifacts so the tree stays pristine ----
rm -f coverage.xml pylint_report.txt .coverage
```

### 9.6 Example usage

**A. Exercise the remediated de-padding directly**

```bash
python - <<'PY'
from tlslite.utils.keyfactory import generateRSAKey
from tlslite.utils.cryptomath import numberToByteArray, numBytes

key = generateRSAKey(2048, ['python'])
n_len = numBytes(key.n)

# Well-formed PKCS#1 v1.5 block carrying a 48-byte TLS premaster secret
payload = bytearray([3, 3] + [0x41] * 46)
pad = bytearray(((i % 254) + 1) for i in range(n_len - 3 - len(payload)))
block = bytearray([0x00, 0x02]) + pad + bytearray([0x00]) + payload
ct = numberToByteArray(pow(int.from_bytes(bytes(block), 'big'), key.e, key.n), n_len)
print("valid padding   ->", len(key.decrypt(ct)), "bytes (expect 48)")

# Corrupt the separator: a SYNTHETIC plaintext is returned, never an error
bad = bytearray(block); bad[bad.index(0x00, 2)] = 0x7f
ct2 = numberToByteArray(pow(int.from_bytes(bytes(bad), 'big'), key.e, key.n), n_len)
out = key.decrypt(ct2)
print("invalid padding ->", len(out), "bytes  (synthetic, not None)")

# Deterministic implicit rejection: the same ciphertext yields the same synthetic value
print("deterministic   ->", key.decrypt(ct2) == out)

# Publicly invalid ciphertext (wrong length) is the ONE legitimate None case
print("publicly invalid->", key.decrypt(ct[:-1]))     # expect None
PY
```

**B. Complete a real RSA-key-exchange handshake in-process** (the only check that proves the rewritten `processClientKeyExchange` runs in a live handshake)

```bash
python - <<'PY'
import socket, threading
from tlslite import TLSConnection, HandshakeSettings, X509, X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.constants import CipherSuite

x509 = X509(); x509.parse(open('tests/serverX509Cert.pem').read())
chain = X509CertChain([x509])
privkey = parsePEMKey(open('tests/serverX509Key.pem').read(), private=True)

def settings():
    s = HandshakeSettings()
    s.keyExchangeNames = ["rsa"]          # forces the remediated path
    s.cipherNames = ["aes128gcm"]
    s.maxVersion = (3, 3)                 # RSA key exchange does not exist in TLS 1.3
    return s

srv, cli = socket.socketpair()
def server():
    c = TLSConnection(srv)
    c.handshakeServer(certChain=chain, privateKey=privkey, settings=settings())
    c.write(b"pong:" + bytes(c.read(min=5, max=64))); c.close()
t = threading.Thread(target=server); t.start()

c = TLSConnection(cli)
c.handshakeClientCert(settings=settings())
suite = c.session.cipherSuite
c.write(b"ping!"); echo = bytes(c.read(min=5, max=64)); c.close(); t.join(30)

name = next(a for a in dir(CipherSuite)
            if a.startswith('TLS_') and getattr(CipherSuite, a) == suite)
print("version   :", c.version)          # -> (3, 3)
print("negotiated:", name)               # -> TLS_RSA_WITH_AES_128_GCM_SHA256
print("echo      :", echo)               # -> b'pong:ping!'
PY
```

**C. Cross-process TLS interoperability** — the gate for "interoperability fully preserved". Note the shell details: newline-separated statements, an explicit interpreter path, and never `&&` immediately before a trailing `&`.

```bash
setsid nohup env PYTHONPATH=. ./.venv/bin/python \
    tests/tlstest.py server localhost:4463 tests > /tmp/srv.log 2>&1 </dev/null &
sleep 14
PYTHONPATH=. ./.venv/bin/python tests/tlstest.py client localhost:4463 tests
# -> Test succeeded, 138 good        (client exit 0; server log ends "Test succeeded")
```

**D. Serve HTTPS and force a third-party client onto the remediated path**

```bash
mkdir -p /tmp/www && echo '<h1>tlslite-ng</h1>' > /tmp/www/index.html
setsid nohup env PYTHONPATH=. ./.venv/bin/python scripts/tls.py server \
    -c tests/serverX509Cert.pem -k tests/serverX509Key.pem \
    -d /tmp/www localhost:8443 > /tmp/https.log 2>&1 </dev/null &
sleep 5

# OpenSSL naming: "AES128-GCM-SHA256" IS TLS_RSA_WITH_AES_128_GCM_SHA256 (static RSA)
printf 'GET /index.html HTTP/1.0\r\n\r\n' | \
  openssl s_client -connect 127.0.0.1:8443 -tls1_2 \
                   -cipher 'AES128-GCM-SHA256' -servername localhost 2>&1 \
  | grep -E "^New,|HTTP/1"
# -> New, TLSv1.2, Cipher is AES128-GCM-SHA256      (remediated path exercised)

# Stop the server by its own PID - never pkill
kill "$(ps -ef | grep '[t]ls.py server' | awk '{print $2}')"
```

> Offering *all* suites instead negotiates TLS 1.3 / ECDHE and does **not** touch the remediated path. `scripts/tls.py` has no key-exchange flag; use `settings.keyExchangeNames = ['rsa']` programmatically as in example B.

### 9.7 Troubleshooting — every entry from an actually observed failure

| # | Symptom | Cause & resolution |
|---|---|---|
| 1 | `python -m pip install .` fails on CPython 3.12/3.13 | `setup.py` imports `distutils.core`, removed in 3.12. Run from the source tree (the `.pth`, or `PYTHONPATH=.`), or build on CPython ≤ 3.11. Pre-existing, out of scope. |
| 2 | 4 modules `ERROR` with `ModuleNotFoundError: No module named 'hypothesis'` (suite reports `Ran 1712 ... FAILED (errors=4)`) | `requirements.txt` pins only `ecdsa`. Install `hypothesis` (it is in `build-requirements.txt`). Doing so reproduces the baseline exactly: `Ran 1811 ... OK (skipped=44, expected failures=2)`. |
| 3 | The 17 uniformity tests silently **skip**; suite shows `Ran 1794 ... OK (skipped=48)` | They guard on `sys.gettrace() is not None`, and `coverage` installs a tracer. This is intended hygiene. Always **also** run untraced, or run the module directly: `python -m unittest unit_tests.test_tlslite_rsa_depadding_uniformity` → 17 OK. |
| 4 | `pylint` dies with `ImportError: cannot import name 'formatargspec' from 'inspect'` | `astroid 2.6.6` pins `wrapt~=1.12`, and `inspect.formatargspec` was removed in Python 3.11+. Install `"pylint<2.10"` then `pip install --upgrade wrapt`. The working combination here is pylint 2.9.6 / astroid 2.6.6 / **wrapt 1.17.3**. |
| 5 | `make test-dev` aborts | Requires `coverage2`/`coverage3` binaries and the coveralls uploader. Run its constituent commands individually — §9.4 and §9.5 cover all of them. |
| 6 | Interop client dies with `ModuleNotFoundError: ecdsa` | `A && B && setsid … &` backgrounds the **whole** `&&` chain, so the venv is never activated in the foreground shell. Use newline-separated statements and call `./.venv/bin/python` explicitly. |
| 7 | Interop server fails with `EADDRINUSE` | `tests/tlstest.py` also binds `PORT-1` as a synchronisation socket, and a lingering server holds it. Use a fresh port pair and confirm no old server process survives. |
| 8 | `openssl s_client` aborts with `certificate verify failed`; server logs `TLSRemoteAlert: unknown_ca` | The test certificate is self-signed. Drop `-verify_return_error`. The server-side traceback is the *client's* rejection, not a server fault. |
| 9 | Long-running job killed mid-flight | A 300 s no-activity teardown applies. Use `setsid nohup bash -c '...' </dev/null >/dev/null 2>&1 &` and poll a log that emits at least every ~120 s. |
| 10 | tlsfuzzer network runs are unusably noisy | `--no-quickack` and `-t 10` are mandatory in a container, and the server's stdout/stderr must go to `/dev/null`. Meaningful resolution additionally needs `isolcpus` and disabled frequency scaling — verify `/sys/devices/system/cpu/cpu0/cpufreq` exists first; on this host it does **not**. |
| 11 | The negotiated cipher suite is missing from a redirected server log | tlslite-ng prints its per-connection report (Ciphersuite, SNI, ALPN) to **stdout**, which is block-buffered when redirected, while the HTTP access log goes to **stderr**. The report appears once enough output accumulates to flush. |
| 12 | A tracer-based measurement shows a spurious spread on the **first** probe class | The first traced call also traces lazily executed module-level code. Warm up with a discarded call before measuring. (Observed while independently reproducing the invariant: a bogus 2,582-event spread vanished after a warm-up.) |

---

## 10. Appendices

### Appendix A — Command Reference

| Purpose | Command |
|---|---|
| Activate primary environment | `source .venv/bin/activate` |
| Full suite (canonical) | `python -m unittest discover` |
| Full suite (pytest) | `CI=true python -m pytest unit_tests/ -q` |
| In-scope module subset | `CI=true python -m pytest unit_tests/test_tlslite_utils_rsakey.py unit_tests/test_tlslite_keyexchange.py unit_tests/test_tlslite_utils_constanttime.py unit_tests/test_tlslite_rsa_depadding_uniformity.py -q` |
| **Security invariant (untraced)** | `python -m unittest unit_tests.test_tlslite_rsa_depadding_uniformity` |
| Optional-backend suite | `./.venv-optdeps/bin/python -m unittest discover` |
| Compile check | `python -m compileall -q tlslite unit_tests` |
| Branch coverage | `coverage run --branch --source tlslite -m unittest discover` |
| Coverage report | `coverage report -m --include="tlslite/utils/rsakey.py,tlslite/keyexchange.py,tlslite/utils/constanttime.py"` |
| Diff coverage gate | `coverage xml && diff-cover coverage.xml --compare-branch=02d1506 --fail-under=90` |
| Pylint report | `pylint --rcfile=pylintrc --msg-template="{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}" tlslite > pylint_report.txt \|\| :` |
| Diff quality gate | `diff-quality --violations=pylint --fail-under=90 --compare-branch=02d1506 pylint_report.txt` |
| Dependency audit | `pip-audit -r requirements.txt --progress-spinner off` |
| Docs build | `make -C docs dummy` |
| Interop suite | `make test` — or the explicit two-step form in §9.6C |
| HTTPS utility server | `make test-utils` |
| Interop under coverage | `make test-local` |
| Diff vs base | `git diff 02d1506 HEAD --stat` · `--numstat` · `--name-only` |
| Verify commit authorship | `git log --pretty=format:"%h\|%an <%ae>\|%s" 02d1506..HEAD` |

### Appendix B — Port Reference

| Port | Used by | Notes |
|---|---|---|
| 4433 | `make test`, `make test-utils`, `make test-local` | Repository default. `tests/tlstest.py` **also binds `PORT-1` (4432)** as a synchronisation socket. |
| 4443 / 4463 | Ad-hoc interop runs | Use a fresh pair when a previous server may still hold `PORT-1`. |
| 8443 | HTTPS validation server (all key exchanges) | Chrome negotiated `ECDHE_RSA` / X25519 / `CHACHA20_POLY1305`. |
| 8444 | HTTPS validation server (`--cipherlist aes128gcm --max-ver tls1.2`) | Chrome negotiated `ECDHE_RSA` / X25519 / `AES_128_GCM`. |
| — | Unit tests | Use `socket.socketpair()` or `MockSocket`; **no** listening port required. |

### Appendix C — Key File Locations

| Path | Role | Change |
|---|---|---|
| `tlslite/utils/constanttime.py` | Constant-time primitives | **UPDATED** +21 — adds `ct_nonzero_u8` |
| `tlslite/utils/rsakey.py` | PKCS#1 v1.5 de-padding (`RSAKey.decrypt`) | **UPDATED** +84/−42 — F1 and F2 |
| `tlslite/keyexchange.py` | `RSAKeyExchange.processClientKeyExchange` | **UPDATED** +56/−10 — F3 |
| `unit_tests/test_tlslite_utils_constanttime.py` | Primitive tests + consumer guards | **UPDATED** +530/−1 |
| `unit_tests/test_tlslite_utils_rsakey.py` | Probe-class matrix, determinism, fold instrumentation | **UPDATED** +377 |
| `unit_tests/test_tlslite_keyexchange.py` | Behavioural truth table | **UPDATED** +622 |
| `unit_tests/test_tlslite_rsa_depadding_uniformity.py` | **Operation-sequence invariant** | **CREATED** +1375 |
| `README.md` | Changelog audit trail | **UPDATED** +13 |
| `SECURITY.md` | Residual-risk disclosure | **UPDATED** +76 |
| `tlslite/utils/python_rsakey.py` | Blinded CRT modexp under a lock | reference — already correct |
| `tlslite/utils/openssl_rsakey.py` | OpenSSL backend, always `m2.no_padding` | reference — proves the fix is backend-universal |
| `tlslite/utils/pycrypto_rsakey.py` | PyCrypto backend, raw ops only | reference |
| `tlslite/tlsconnection.py` | Server entry points; **suite preference ordering** at `3872-3879` / `4455-4458` | reference |
| `tlslite/mathtls.py` | Master-secret derivation | reference — already length-uniform |
| `tlslite/api.py` | Public API surface (56 lines) | reference — exports none of the changed modules |
| `.github/workflows/ci.yml` | 56-job matrix, 9 CPython versions | reference — no security scanning today |
| `pylintrc`, `Makefile`, `requirements.txt`, `build-requirements.txt` | Gates and manifests | unchanged |
| `tests/serverX509Cert.pem`, `tests/serverX509Key.pem` | Test credentials (2048-bit RSA, CN=localhost, valid to 2035) | unchanged |

### Appendix D — Technology Versions

| Component | Version |
|---|---|
| CPython (development) | 3.13.7 |
| Declared support range | 2.6, 2.7, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12, 3.13 (56 CI matrix jobs) |
| tlslite-ng | 0.9.0b2 |
| `ecdsa` (only mandatory dependency) | 0.19.2 (`>=0.18.0b1`) |
| `six` (transitive) | 1.17.0 |
| coverage / pytest / hypothesis | 7.15.2 / 9.1.1 / 6.164.0 |
| pylint / astroid / wrapt | 2.9.6 / 2.6.6 / **1.17.3** |
| diff_cover (`diff-cover`, `diff-quality`) | 10.4.1 |
| Sphinx | 9.1.0 |
| pip | 26.2 |
| M2Crypto / gmpy2 / pycryptodome (`.venv-optdeps`) | 0.48.0 / 2.3.1 / 3.23.0 |
| OpenSSL (interop client) | 3.5.3 |
| Chrome (runtime validation) | 150.0.7871.186 headless |
| OS | Ubuntu 25.10, 4 vCPU Intel Xeon @ 2.60 GHz |

### Appendix E — Environment Variable Reference

| Variable | Value | Purpose |
|---|---|---|
| `PYTHONPATH` | `.` | Makes the source tree importable when not using the `.pth`. Required by `tests/tlstest.py` and `scripts/tls.py`. |
| `CI` | `true` | Keeps Node-style and pytest tooling non-interactive. |
| `COVERAGE_FILE` | `.coverage.server` / `.coverage.client` | Used by `make test-local` to keep parallel coverage data apart. |

**No application configuration exists.** There is no `config/`, `.env`, `.env.example`, `Dockerfile`, `docker-compose.yml`, `kubernetes/`, `helm/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`, `tox.ini`, `pytest.ini`, `setup.cfg`, `conftest.py` or `pyproject.toml` anywhere in the repository — verified. The only three YAML files are `.github/workflows/ci.yml`, `.landscape.yaml` and `.readthedocs.yaml`, none of which required modification. **No secret, credential, token or key material is created, rotated or referenced by this change.**

### Appendix F — Developer Tools Guide

| Tool | Role | Notes |
|---|---|---|
| `unittest` / `pytest` | Test runners | `unittest discover` is canonical; pytest gives a terser summary. Same tests. |
| `hypothesis` | Property-based testing | **Required** — 4 modules fail to import without it, despite its absence from `requirements.txt`. |
| `coverage` | Branch coverage | Installs a tracer, which makes the 17 uniformity tests defer by design. Always run an untraced leg too. |
| `diff-cover` | Diff coverage gate (≥ 90%) | `--compare-branch=02d1506`. Result: 42 lines, 100%. |
| `pylint` + `diff-quality` | Diff quality gate (≥ 90%) | Needs a modern `wrapt` forced over `astroid 2.6.6`. Diff-scoped, so the pre-existing 6.00/10 package score is not a blocker. Result: 3,065 lines, 0 violations. |
| `pip-audit` | Dependency audit | **One** finding is the expected PASS baseline; only a *new* finding fails. |
| `sys.settrace` | Operation-sequence invariant | The project's own mechanism for proving uniformity. Warm up before measuring (§9.7 #12). |
| `tlsfuzzer` (`/opt/tlsfuzzer`) | Statistical timing harness | `scripts/test-bleichenbacher-timing-pregenerate.py`. Read option names from its own `--help`. Needs `--no-quickack` and `-t 10` here. |
| `openssl s_client` | Third-party interop | `-cipher AES128-GCM-SHA256` forces static RSA — the remediated path. |
| `tests/tlstest.py` | Cross-process interop harness | 138 tests; also binds `PORT-1`. |
| `scripts/tls.py` | CLI client/server, HTTPS-capable | `--cipherlist` only; **no** key-exchange flag. |
| Sphinx (`make -C docs dummy`) | Docs build | Autodoc picks up `ct_nonzero_u8` with no source edit. |

### Appendix G — Glossary

| Term | Meaning |
|---|---|
| **Bleichenbacher attack** | 1998 adaptive chosen-ciphertext attack against RSA PKCS#1 v1.5 that recovers plaintext using only an oracle telling the attacker whether padding was well formed. |
| **ROBOT** | "Return Of Bleichenbacher's Oracle Threat" — a 2017 revival showing the oracle also acts as a *signing* oracle for the server's long-term key, which is why integrity impact counts toward severity. |
| **Padding / decryption oracle** | Any observable difference — error text, alert, or **timing** — that reveals whether a decrypted block was correctly formatted. |
| **CVE-2020-26263** | This project's own Bleichenbacher-oracle CVE. Its upstream changelog records a *workaround*, not a complete fix, and states a complete fix is not possible in Python. |
| **Implicit rejection** | Substituting a synthetic plaintext instead of signalling a padding error. tlslite-ng's is *deterministic*: derived as `HMAC-SHA256(SHA-256(d), ciphertext)` expanded under the labels `length` and `message`, so resubmitting the same ciphertext yields the same synthetic value and cannot be distinguished from a real one. |
| **De-padding** | Removing PKCS#1 v1.5 padding from a decrypted block to recover the message — the code region hardened here. |
| **Leak L1** | The final masked-selection loop's trip count equalled the *returned message length*. Closed by F1. |
| **Leak L2** | A branch cascade in the key-exchange consumer whose duration depended on plaintext **structure**, including the two version bytes. Closed by F3. |
| **Leak L3** | The publicly-decidable early exit (wrong ciphertext length, or integer ≥ modulus). **Deliberately retained** — both facts are already known to whoever sent the message, so it is not an oracle. |
| **Leak L4** | CPython-inherent residual: one variable-size copy implied by the public variable-length return contract, plus allocator, GC and interpreter jitter. **Not removable in pure Python**; disclosed. |
| **Leak L5** | The largest leak, discovered during this project and documented nowhere upstream: the `ct_*_u32` primitives allocate a multi-digit arbitrary-precision integer only when their operands differ, so the *count* of expensive evaluations depended on the plaintext. Closed by F2. |
| **`ct_nonzero_u8`** | The new byte-domain fold (`val \|= val>>4; \|= val>>2; \|= val>>1; return val & 1`). Every intermediate stays ≤ 255, inside CPython's cached small-integer range, so it allocates nothing for any of the 256 possible inputs. |
| **Operation-sequence invariant** | The deterministic replacement for a flaky wall-clock assertion: record the *ordered* sequence of executed Python line events per probe class and require the sequences to be identical. Exact, noise-free, CI-safe. |
| **Four-test union rule** | tlsfuzzer's decision rule — Wilcoxon signed-rank, Sign, paired t and Friedman — reporting a significant difference if **any one** detects one. Strictly harder to pass than any single test. |
| **A/B swap control** | Reversing probe-class measurement order. A genuine data dependency flips sign; a harness ordering artefact does not. The base tree flips; the fixed tree does not. |
| **Tracer warm-up** | The first traced call also traces lazily executed module-level code, producing a spurious first-class spread. Discard one call before measuring. |
| **Buggy-IE tolerance** | Long-standing behaviour accepting a premaster secret that carries `serverHello.server_version` instead of `clientHello.client_version`. Preserved exactly by ANDing the two version rejection bits rather than ORing them. |
| **Static RSA key exchange** | `TLS_RSA_WITH_*` suites, where the client encrypts the premaster secret to the server's RSA key. The **only** way to reach the remediated path. Absent from TLS 1.3, and not what tlslite-ng's own suite ordering prefers. |

---

## Cross-Section Integrity Validation

| Rule | Requirement | Verification | Status |
|---|---|---|---|
| **Rule 1** | Remaining hours identical in §1.2, the §2.2 Hours sum, and the §7 pie "Remaining Work" | §1.2 = **50** · §2.2 sum = 14+12+10+6+4+4 = **50** · §7.1 pie = **50** · §7.2 priority pie = 36+10+4 = **50** · §7.3 table = **50** · §1.6 + §8.2 task hours = **50** | ✅ **PASS** |
| **Rule 2** | §2.1 completed + §2.2 remaining = Total Project Hours in §1.2 | §2.1 sum = **226** · §2.2 sum = **50** · 226 + 50 = **276** = §1.2 Total Hours | ✅ **PASS** |
| **Rule 3** | All tests in §3 originate from Blitzy's autonomous validation logs | Every row is sourced from Blitzy's autonomous validation and was **re-executed and reproduced** during this review. No external or hypothetical test is listed. | ✅ **PASS** |
| **Rule 4** | Access issues validated against current system permissions | Each §1.5 entry was verified by execution: `/sys/devices/system/cpu/cpu0/cpufreq` absent; only CPython 3.13.7 present; DNS failure observed in the interop log; `pylint`/`wrapt` failure reproduced in a fresh venv. | ✅ **PASS** |
| **Rule 5** | Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF` | Applied via Mermaid `themeVariables` in both §1.2 and §7.1 (`pie1` = `#5B39F3`, `pie2` = `#FFFFFF`), with `#B23AF2` strokes and `#A8FDD9` highlights. | ✅ **PASS** |
| **Consistency** | One completion percentage everywhere | **81.9%** appears in §1.2 (metrics + pie title + shown formula), §7.1 (pie title), §8.1 and §8.5. No other percentage describes completion anywhere in this guide. | ✅ **PASS** |
| **Consistency** | One set of hour figures everywhere | **276 / 226 / 50** in §1.2, §2.1, §2.2, §2.3, §7.1, §7.3 and §8.2. Priority split **36 / 10 / 4** in §2.2, §7.2 and §1.6. | ✅ **PASS** |