# Narrow official Omega dependency adapter

This opt-in adapter supports `skin.aura` **2.1.0**, its reviewed source commit/ZIP,
the `xbmc.gui.skin` extension and the **Omega** catalog, plus only the exact
[TV Guide 0.1.1 enrollment](TVGUIDE-LANE-PREPARATION.md). It
supplies dependency metadata, never dependency ZIPs, installations, built-ins,
package approval or publication authority. Other package/lane admission is
unchanged; a different selected package cannot borrow Aura's allowlist.

`external_dependencies` remains `{}` for ordinary inputs. Aura uses
`{"official_omega": SPEC}`. The separately enrolled exact TV Guide/Nexus adapter
may coexist under `official_nexus`; the closed Matrix preparation adapter may
coexist under `official_matrix`. See [the Nexus contract](OFFICIAL-NEXUS-DEPENDENCIES.md)
and [TV Guide lane preparation](TVGUIDE-LANE-PREPARATION.md).
Unknown keys reject; each configured resolver sees only its own spec and all its
checks run. At most one report can be active per lane. Aura-only report shape is
unchanged; TV Guide enrollment adds independently reconstructed `root_closures`.
Omega SPEC is a closed object with:

- `schema`: integer 1;
- `source_url`: exactly `https://mirrors.kodi.tv/addons/omega/addons.xml.gz`;
- `snapshot`: canonical, regular, nonlinked intake-relative path to the explicitly
  acquired, decompressed official `addons.xml` (maximum 32 MB);
- `snapshot_sha256`: lowercase 64-digit SHA-256 of those exact XML bytes;
- `retrieved_at`, `expires_at`: real UTC-second timestamps. Retrieval cannot be
  future-dated. Expiry follows retrieval by at most seven days and is checked
  freshly by builder, verifier and independent auditor;
- `core_commit`: `a3a448d26b8d560a65655dab2cd122994dc4e146` (Kodi 21.3 source);
- `allowlist`: exact map of every reached official add-on ID to its newest
  published version. Missing, unused or old-provider entries reject;
- `roots`: Aura-only remains `{"skin.aura": {"version": "2.1.0", "package_sha256": HASH,
  "source_commit": COMMIT}}`, bound to independently inspected intake values and
  source repository `https://github.com/kcook98765/skin.aura`. Only the exact
  TV Guide binding documented above may additionally appear (or be selected alone
  for a TV-Guide-only private candidate); foreign roots reject. The allowlist must
  equal the union of selected roots' separately traversed complete closures.

No command in the adapter fetches the source URL or runs add-on code. An operator
acquires authoritative metadata separately, records provenance and reviews its
retained digest and exact allowlist. URL equality is an assertion of acquisition
source, not a signature or automated proof that downloaded bytes are official.
Independent reviewers retain responsibility for verifying that provenance.

Both implementations parse the pinned snapshot and reconstruct required closure,
available optional branches and their required descendants. Missing optional
providers remain explicit diagnostics. Too-old providers, newest-version broken
markers, duplicate imports, conflicting platform declarations, cycles and
substitution with another admitted package reject. XML DTD/entities, unsafe paths,
symlinks, invalid metadata and resource-limit violations reject.

Kodi dependency versions follow the pinned
[AddonVersion.cpp](https://github.com/xbmc/xbmc/blob/a3a448d26b8d560a65655dab2cd122994dc4e146/xbmc/addons/AddonVersion.cpp)
ordering, including epoch, revision, `~` and `+matrix.N`. This does not change the
repository's strict numeric `x.y.z` package identity grammar. Core provider/ABI
versions come from that exact Kodi source's `addons/` manifests, JSON schema
version and `kodi-dev-kit/include/kodi/versions.h`. Supplied configured built-ins
that conflict with these pins reject; external packages are never added to the
built-in configuration.

`scripts/official_omega.py` supplies producer evidence.
`scripts/audit_official_omega.py` loads/reconstructs the same approved inputs
without importing the producer module or trusting its result. Each returns a
JSON-safe closure report with separate external/core versions, all traversed
edges and unavailable optionals. Consumers pin both source files and compare
freshly reconstructed reports. A structural PASS establishes metadata closure,
not successful installation, runtime behavior, dependency redistribution rights
or permission to mirror official packages.

## 2026-11-22 snapshot maintenance

The [retained acquisition](official-dependencies/acquisition-2026-11-22.json)
records a new authoritative download, exact compressed/XML hashes and matching
official SHA-256/MD5 sidecars. New XML SHA-256 is
`800fc70454c9e942d83a4e30c12871e0ac603db85a9ad909941dd8ebba70cb2b`,
retrieved `2026-11-22T07:21:54Z`, expires `2026-11-29T07:21:54Z`. The
[previous spec and bytes](official-dependencies/README.md) remain retained;
`6296b93298117faccab8d97b84c3ad6656f1298660cdf5d031a7a715c503ad0b`
is the previous XML hash. Both independent resolvers reconstructed the previous
closure at its actual original retrieval time (historical only) and the current
closure at actual current time. All **32 external versions, 81 edges, core facts,
root bindings and unavailable-optionals** match; see
[the comparison](official-dependencies/omega-closure-comparison.json).

Only snapshot path/hash and actual acquisition/expiry timestamps changed in
`config/production.json`; its packages, review hashes, allowlist, roots and retained
installers remain unchanged. No production build/publication or unrelated package
change was performed. Restore the selected decompressed XML into ignored intake
using the documented hash-checking procedure; public compressed bytes are tracked
under docs so private-intake source audit stays strict. A new acquisition/review is
needed after expiry, not a timestamp extension.
