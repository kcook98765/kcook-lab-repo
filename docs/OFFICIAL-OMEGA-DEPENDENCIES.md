# Narrow official Omega dependency adapter

This opt-in adapter is enrolled only for `skin.aura` **2.1.0**, its exact reviewed
source commit/ZIP, the `xbmc.gui.skin` extension and the **Omega** catalog. It
supplies dependency metadata, never dependency ZIPs, installations, built-ins,
package approval or publication authority. Other package/lane admission is
unchanged; a different selected package cannot borrow Aura's allowlist.

`external_dependencies` remains `{}` for existing inputs. Its only nonempty form
is `{"official_omega": SPEC}`. SPEC is a closed object with:

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
- `roots`: exactly `{"skin.aura": {"version": "2.1.0", "package_sha256": HASH,
  "source_commit": COMMIT}}`, bound to independently inspected intake values and
  source repository `https://github.com/kcook98765/skin.aura`.

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
