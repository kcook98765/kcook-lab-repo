# Retained official dependency metadata

These are public official catalog bytes, checksum sidecars, acquisition receipts,
exact-root enrollment inputs and core-source proof, **not** dependency ZIPs,
private reviews, native logs or package admission. No package is mirrored.

Official metadata/core-manifest provenance identifies Team Kodi/xbmc upstream;
the repository's MIT license does not relicense third-party materials. Exact
`AddonVersion.cpp` GPL-2.0-or-later source bytes are retained only in private
evidence. Public `nexus-core-provenance.json` records its precise immutable official
source URL, SHA-256, byte count and acquisition headers; no C++ source is copied
here and no MIT relicensing is claimed.

The dated acquisition receipt binds exact compressed and decompressed XML hashes,
authoritative HTTPS URLs, redirect destinations, response headers, actual UTC
retrieval times, matching official SHA-256/MD5 sidecars and maximum seven-day
validity. Sidecars establish transport consistency, not a signature or trust
independent of the official mirror infrastructure. Reacquire after expiry; never
extend an old retrieval timestamp. No build or audit fetches metadata.

`omega-previous-spec.json` retains the old configured record. The previous XML is
retained in a deterministic gzip wrapper; that wrapper is a retention encoding,
**not** a claimed historical HTTP download. Its decompressed SHA-256 must equal
the old record. The fresh gzip files are the exact downloaded bytes.

## Restore an explicitly selected snapshot to ignored intake

Keep public metadata here rather than widening publication source audit's private
`incoming/` boundary. Review the receipt/spec first. For the selected spec only,
decompress the matching retained gzip to the intake-relative `snapshot` path and
verify the XML hash. For example, from the distribution checkout:

```python
import gzip, hashlib, json
from pathlib import Path
root = Path.cwd()
inputs = json.loads((root / 'config/production.json').read_text())
spec = inputs['external_dependencies']['official_omega']
raw = gzip.decompress((root / 'docs/official-dependencies/omega-800fc70454c9.xml.gz').read_bytes())
assert hashlib.sha256(raw).hexdigest() == spec['snapshot_sha256']
target = root / 'incoming' / spec['snapshot']
target.parent.mkdir(parents=True, exist_ok=True)
assert not target.exists() or target.read_bytes() == raw
target.write_bytes(raw)
```

The equivalent Nexus candidate input is `tvguide-nexus-enrollment.json` and
`nexus-32dc7aae6108.xml.gz`. It must be combined with any preserved Omega spec,
not used to replace it. Restore both if both adapters are configured; inactive
adapters still validate current snapshot integrity/expiry. Builds require the
separately retained private approved packages/records as before. No TV Guide ZIP,
review record or new ledger entry belongs in this directory or this maintenance
change. Every candidate decision remains pending until genuinely reviewed.
