# TV Guide 0.1.1: bounded dependency-lane preparation

This is repository adapter and **Nexus/Omega production proposal** preparation,
not a new add-on release, crash fix or publication. The initial adapter/private
qualification commit `339d8f6` retained Nexus-only intake. A subsequent genuine
Codex strict-v2 final package review now supports proposed Nexus/Omega admission.
**Actual Pages remains Nexus-only until separate exact-site owner approval and
promotion.** Matrix is policy-blocked; Piers is excluded. The release ledger,
installer, other packages, existing ZIPs and artwork remain unchanged. No new
native result is produced by these code/intake edits; no add-on code is executed.

## Exact enrollment and independent reconstruction

Only `script.tvguide.fullscreen` **0.1.1**, source
`https://github.com/kcook98765/script.tvguide.fullscreen`, commit
`f936c0a514e0de126e62e24fd3d24b66b0c74097`, tree
`c6d014c332f6d24b219f4976518dcf2221ae6a88`, ZIP SHA-256
`76533fcb570cd813e2deb885c919b59eea21171c6ce344d5a40ef5d8fba287b9`
(1,318,170 bytes, 318 files) is enrolled. No runtime source/version/assets or
dependency bundling changes are made. All six manifest floors remain exact:
`xbmc.python=3.0.0`, `requests=2.31.0`, `dateutil=2.8.2`,
`pytz=2023.3.0+matrix.1`, `pil=5.1.0`, `beautifulsoup4=4.12.2`
(library IDs retain their `script.module.` prefix).

`official_matrix.py` and `audit_official_matrix.py` separately reconstruct exact
Matrix 19.4 closure. The Omega implementations admit only Aura and this exact
TV Guide package, not arbitrary scripts/plugins. Both sides check the TV Guide
entry points and all imports/floors/optional flags. Foreign roots, source/hash
rebinding, provider substitution, malformed/expired inputs, incompatible core ABI,
broken/newest-disallowed providers, ambiguous declarations, cycles and unrelated
packages borrowing external/core admission reject. Auditors never import producers.

Omega adds `root_closures` only for TV Guide enrollment. Each root gets a separate
traversal cache and attributable external/core versions, edges and unavailable
optionals. The full proposed Omega spec retains Aura and its entire **32-provider /
81-edge** closure unchanged. TV Guide adds only `script.module.pytz` to that full
allowlist: the union has **33 providers / 105 root-isolated edges**, including
separately traversed shared dependencies. TV Guide alone has **10 external
providers / 24 edges** on each lane. PIL stays a pinned core provider, not a
mirrored dependency or a newly configured global built-in.

Consumers resolve the configured current-lane adapter first. Only after successful
exact TV Guide reconstruction may inactive adapters defer their wrong-lane TV Guide
prohibition. Only that TV Guide manifest is omitted from inactive calls; Aura and
foreign roots are never hidden. Inactive specs still undergo source, root,
snapshot, hash and expiry checks. Absent/mismatched current-lane enrollment fails
closed. At most one report may be active per lane. Direct adapters stay lane-only.
Toolchain reports pin both new Matrix implementations and same-side Omega parsing
primitives, alongside every other configured resolver implementation.

## Acquisition and separate core bindings

Matrix was acquired from `https://mirrors.kodi.tv/addons/matrix/addons.xml.gz` at
**2026-11-22T09:47:47Z**, redirecting to the official mirror at
`https://ftp.halifax.rwth-aachen.de/xbmc/addons/matrix/addons.xml.gz`.
Both official SHA-256 and MD5 sidecars matched; see the retained
[receipt](official-dependencies/matrix-acquisition-2026-11-22.json).

- Download: **1,315,360 bytes**, SHA-256
  `a3f37b9fbc0e1d0896565311bf4c150d9af55d6e10e0185674c9e13302b28727`.
- XML: **7,810,768 bytes**, SHA-256
  `8473a49bffc64d461ed0fd20b7f28500759d257edfa8634d63cc5f4709565516`.
- Expiry: **2026-11-29T09:47:47Z**, seven days, no timestamp extension.

Exact primary-source tag resolutions and retained manifests bind:

| Lane | Tag / commit | Python provider / ABI | PIL |
| --- | --- | --- | --- |
| Matrix | `19.4-Matrix` / `e12e66e019af29ba9d5f5a2614315b15a138b81a` | `3.0.0` / `3.0.0` | `5.1.0` |
| Nexus, unchanged | `20.5-Nexus` / `4b95737efaddf7c869736e539318f18433413ff1` | `3.0.1` / `3.0.0` | `5.1.0` |
| Omega | `21.3-Omega` / `a3a448d26b8d560a65655dab2cd122994dc4e146` | `3.0.1` / `3.0.0` | `5.1.0` |

Matrix `version.txt` says Kodi 19.4, `ADDON_API 19.1.0`; that is not the Python API
or a reason to change global lane configuration. All provide `xbmc.core` `0.1.0`,
ABI `0.1`; PIL imports Python `3.0.0`. See [Matrix primary-source proof](official-dependencies/matrix-core-provenance.json)
and [Omega TV Guide core proof](official-dependencies/omega-tvguide-core-provenance.json).
Precise `AddonVersion.cpp` URLs/hashes/sizes are recorded; its GPL source is not
redistributed here. Upstream ownership/notices remain applicable.

Nexus and Omega snapshots **were not refreshed**. Nexus XML SHA-256 remains
`32dc7aae6108c633a4ae788500b20ee043ef814af6a22967fdc1e891fc262aa6`, expiry
`2026-11-29T07:21:50Z`. Omega remains
`800fc70454c9e942d83a4e30c12871e0ac603db85a9ad909941dd8ebba70cb2b`, expiry
`2026-11-29T07:21:54Z`. Public enrollment/closure proposals are not production
configuration, approvals or dependency ZIPs. Restore selected XML using the
[hash-checking procedure](official-dependencies/README.md). Builds/audits fetch nothing.

## Matrix policy block versus metadata/smoke success

Codex's separately supplied independent review reports bounded exact-package
Matrix 19.4 and Omega 21.3 disposable smoke observations. Those are attributed
review evidence, not tests run by this adapter change or an owner/human signature.
**Matrix remains production BLOCKED**: the historical same-runtime native SIGSEGV
in the CPython/BeautifulSoup compilation path remains applicable and unclassified.
[Original issue #8](https://github.com/kcook98765/script.tvguide.fullscreen/issues/8)
is unresolved. Smoke nonrecurrence, metadata closure and normal shutdown do not
fix or exclude that risk. Every unresolved runtime finding still blocks strict-v2.
No approval/schema/policy gate changes are made.

Retain historical passed **and failed** observations. Audio stays UNTESTED;
optional notifications and timer-fired AutoPlay stay UNOBSERVED; inherited static
FAIL, non-clean logs, source-delta and finite Linux-only smoke limitations remain.
There is no full legacy parity, upgrade/pruning, repository install/update/UI
discovery or general stability claim. No crash/debug/native campaign runs here.

Owner-authorized partial progression now prepares **Nexus and Omega only** with
Codex's genuine separately scoped strict-v2 final package review, SHA-256
`b1f223586f0402b13365683522ff7bdfce27a188d0eebd4d74c7a3a1926a3850`.
Codex is the independent reviewer, not an owner/human signature. The old Nexus-only
approval and all pending/Matrix-risk records remain immutable. The final two-lane
record excludes Matrix rather than waiving its risk. Matrix metadata support is
unused in production: `official_matrix` is absent from production configuration.

The prepared production intake retains the full Aura-plus-TV-Guide Omega spec,
adding only the exact TV Guide root and pytz provider. Nexus's entire spec is
unchanged. Only the TV Guide item changes lanes/review reference/digest; its ZIP
identity, the other three items, retained installers, global configuration and
all six ledger entries remain exact. The private TV-Guide-only closure is never
substituted for production. Complete real production build/verify/independent
audit/deterministic qualification/source-and-site scans/preflight must pass on
the final clean committed source. Public HTTPS validation must not be run against
unpublished expected bytes. No release/tag/asset/Pages promotion or merge occurs
in this preparation; exact complete-site owner approval remains pending.

## Supported private qualification

The isolated candidate has a separate repository namespace/empty candidate ledger,
never a cleared production ledger. Its only add-on is TV Guide, selected on
Matrix/Nexus/Omega. Candidate Omega uses the exact TV Guide root plus its ten
providers from `root_closures`, with the same valid snapshot/core. Nexus spec is
unchanged; Matrix uses the newly acquired spec.

The completed private-stage procedure kept Codex's genuine three-lane record
immutable and separately called `approval_contract.assess`
using the exact inspected manifest/package/source and real production ledger.
That dated assessment retains its Matrix risk/deferred acceptance and then-pending
final package decision; it is not superseded or rewritten by the final two-lane
decision. The private-stage source remains frozen at `339d8f6`.
The structural namespace candidate uses a **separate all-pending strict-v2
projection**: rights, technical, static, runtime and final decisions pending/false,
with the unresolved Matrix risk retained. This neither revokes genuine evidence
nor issues approval. The existing all-pending candidate gate is unchanged.

Generate the installer honestly with `repository.installer`, keep tracked
source/index and production baseline bindings, then use the real commands:

```sh
python3 -B scripts/repository.py build --profile candidate
python3 -B scripts/repository.py verify --profile candidate
python3 -B scripts/audit_candidate.py --profile candidate
python3 -B scripts/qualify.py --profile candidate
```

Keep stdout/stderr/exit codes, immutable source/input/site inventories, actual
record/projection hashes and every failed attempt private. Run normal source audit
and site byte scans, without bypassing path checks. Structural, deterministic and
ephemeral-loopback qualification is not native acceptance or public HTTPS proof.
No candidate installation/hosting/publication, release/tag/asset write or merge.
Exact complete-site owner approval remains mandatory before publication.

Focused reproducible checks, without add-on execution or broad static suites:

```sh
python3 -B -m unittest discover -s tests -p 'test_official_*.py' -v
python3 -B -m unittest discover -s tests -p 'test_tvguide_lanes.py' -v
```

Retained-metadata tests reconstruct at a fixed in-window time, a historical
repeatability check. Fresh operator build/verify/audit/qualification uses actual
current time and fails after configured metadata expiry.
