# Repository intake and release procedure

Read `docs/RELEASE-WORKFLOW.md`, `docs/APPROVAL-CONTRACT.md`,
`docs/ARCHITECTURE.md` and `incoming/README.md` for their current contracts.
These remain authoritative; this reference routes the native operator through
them without replacing the restricted role adapters or installing a publisher.

## Source handoff

For a new add-on, capture the owner-selected GitHub source URL, immutable commit,
manifest ID/version, license/attribution, runtime-file list, dependencies and
intended lanes. A GitHub source archive normally has a repository-named root;
it is not automatically an installable Kodi ZIP. Freeze a deterministic package
with exactly one runtime root matching the manifest ID. Exclude `.git`, agent
profiles, secrets, tests, reports, caches and development environments. Record
per-file and ZIP hashes plus source provenance. Do not execute downloaded add-on
code as part of distribution intake.

Use matching isolated Toolkit checker/stub environments and actual recorded
native observations for each requested Kodi lane. Consult `docs/SOURCES.md`
and official Kodi references when API/dependency behavior is unclear. Record
unavailable tooling and tests rather than borrowing another lane's PASS.

Production intake uses `config/production.json` entries with `zip`, `sha256`,
`review_record`, `review_record_sha256` and `lanes`. Review records must bind the
exact package and source and satisfy the current approval contract. Never invent
human decisions, broaden old evidence, extend exceptions or claim risk acceptance
is legal clearance. For unapproved input, use the documented isolated private
candidate procedure; keep truthful blockers instead of editing production gates.

For updates, compare the new manifest, runtime changes, dependency floors and
compatibility evidence with the published version. Preserve old package bytes,
review records and `releases/manifest.json` history. Different runtime bytes need
a new version; an unchanged approved package can be restored by exact checksum.
The repository's current version parser accepts numeric `x.y.z`; check actual
tool support before proposing prerelease or alternate version formats.

## Restored Tastemade input

On 2026-11-05 the operator restored these original files into `incoming/`:

| File | SHA-256 | Existing scope |
| --- | --- | --- |
| `plugin.video.tastemade-0.1.0.zip` | `d21af0f89c118c2a4c789b656b27d6211a086cce961dc3501fa4ad00564fce87` | Omega only |
| `tastemade-review-v3-approved-r10.json` | `442db92cb401bf981de89eeebac9be54492a81d97fa57abcf2bb69f4a33df05f` | Frozen review revision 10 |

This is restoration, not a new release approval. Revalidate current configuration,
contract eligibility and expiry during preparation. Do not replace these files
with packages built from current GitHub main under the old version/hash.

## Production verification

From the actual repository root, use current documented commands, recording each
stage independently. Preserve previous output before replacing a failed build.

```sh
python3 -B -m unittest discover -s tests -v
python3 -B scripts/repository.py build --profile production
python3 -B scripts/repository.py verify --profile production
python3 -B scripts/audit_candidate.py --profile production
python3 -B scripts/qualify.py --profile production
python3 -B scripts/check_publication.py
```

The test suite may run by complete, isolated top-level modules if a monolithic
run exceeds session timeouts; prove full test discovery coverage and retain all
failures. A passing suite from before the final edit does not validate that edit.
Do not run tests with publishing secrets injected. Do not run the independent
auditor with optimization enabled.

Review `dist/production/site/`, `dist/production/release-assets/`, SHA256SUMS and
`release-plan.json`. Verify complete inventory, dependency closure, lane selection,
installer copies, bootstrap links, retained historical bytes and whole-site repeat
build determinism. Dry-run authority flags remain false; do not toggle them to
simulate owner authorization. Gates passing does not itself publish.

For the rename, keep ID `repository.ai.kodi`, prepare installer 0.1.1 and retain
0.1.0. Derive intended public URLs from current `config/repository.json`; the
configured root is `https://kcook98765.github.io/kcook-lab-repo/`. Read
`docs/REBRANDING.md` and separate automatic rebuilding of the old Pages branch
from publication of a new local candidate.

## Authorized publication and acceptance

Follow `docs/HOSTING.md` and the actual owner-authorized publication mechanism.
The disposable pilot/simulated publishers are not production deployment tools.
Resolve the exact GitHub identity, source/site digest and destination before a
remote write. Reuse existing native credential storage; never paste secrets into
commands, profiles, logs or Git. Stage and verify release assets before promoting
matching catalogs, preserving historical releases and a coherent complete site.

After an authorized deployment, `python3 -B scripts/check_publication.py --https`
checks the deployed expected production bytes. Running it before deployment is
not local candidate acceptance. Confirm public root/installer/catalog/package
URLs and hashes. Then follow `docs/NATIVE-ACCEPTANCE.md` on an explicitly selected
Kodi client: File manager source, install repository ZIP, browse the compatible
catalog, install the add-on and check updates separately. Report actual tested
Kodi/platform versions. Opening a feed or installing a package does not establish
login/playback/feature acceptance or compatibility on another Kodi version.
