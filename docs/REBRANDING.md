# kcook-lab-repo rebranding

Owner instruction: rename `kcook98765/ai-kodi-repository` to
`kcook98765/kcook-lab-repo`; rebrand current source, docs, installer, bootstrap,
URLs and tests. Retain Kodi ID `repository.ai.kodi`. The owner reports no existing
users and requests no old-URL migration service. Preserve historical artifacts.
Run local tests and production build/verification/independent audit; present the
diff and exact evidence before any source push or Pages deployment.

## Publication outcome (2026-11-06)

The owner authorized publication after presentation of the frozen packet and
explicitly instructed the operator to verify the appended independent reviewer
decision and complete that publication. The reviewer decision was **PASS WITH
WARNINGS**, bound to the exact source map, plan, inputs, installer and complete
site. Its report SHA-256 at execution was
`feed7fbda6a7637aed9a8b8a98753f7d44adeeacd4560974b47b46726767f3fe`.
The operator freshly reconstructed the source/diff binding, rechecked retained
approval validity and ran two builds, verification, the independent production
auditor, deterministic qualification and preflight before remote writes.

- Reviewed source/tag commit:
  [`95d56f38649e5d3c4240b0db075b5a22e6897a31`](https://github.com/kcook98765/kcook-lab-repo/commit/95d56f38649e5d3c4240b0db075b5a22e6897a31).
- Published Pages commit:
  [`31a5a61be5d2b7af1224257f6ee3ae215057074e`](https://github.com/kcook98765/kcook-lab-repo/commit/31a5a61be5d2b7af1224257f6ee3ae215057074e).
- Release: [`repository-0.1.1`](https://github.com/kcook98765/kcook-lab-repo/releases/tag/repository-0.1.1).
- Live File manager source: `https://kcook98765.github.io/kcook-lab-repo/`.
- Original reviewed/published plan SHA-256:
  `fc8d94fa4e1b9cd76eedb40f077d413f8e2c88fcdc97157b22b0db5b01fdda5a`.
- Published complete site-manifest SHA-256:
  `93a163a71af469cb61d04d8c4ae7095ed89a9a31438142182108d8f80db7a83b`.
- Public installer 0.1.1: 2609 bytes, SHA-256
  `e1dda80a7f734681553583592fb993295b60a5457b066aab059dadcc96b39aee`.

All seven Release assets (three ZIPs, their sidecars and SHA256SUMS) were
downloaded and compared byte/hash-for-byte both as a draft and after publication.
The prior Tastemade Release/assets were not replaced. Pages promotion retained
all 22 prior site files and added the four current installer mirrors/sidecars;
the resulting inventory is exactly the reviewed 26 files. Both branch pushes were
normal fast-forwards; no history was removed, settings/security changed or
credentials exposed. No runtime/add-on code was executed.

The documented `check_publication.py --https` then passed: all 26 deployed files
plus the root-directory response matched the expected hashes in 27 HEAD/GET pairs,
with HTML bootstrap MIME and no unexpected redirect. Four excluded fixture and
candidate paths returned HTTP 404. The Pages API reported the exact Pages commit
built successfully. Public byte verification is not native Kodi installation,
refresh/update, playback or other-feature acceptance. Existing provider/runtime
limitations and the optional InputStream Adaptive warning remain unchanged.

The retention ledger now appends the published installer 0.1.1 tuple without
changing or reordering prior tuples. This post-publication ledger/status update
is metadata-only, not part of the earlier independently reviewed source snapshot;
the tag remains bound to the reviewed commit above. Regenerated local plans bind
the updated ledger and therefore have a different plan digest while retaining
the exact published site/artifact bytes. The old plan and review evidence remain
frozen in ignored reports; offline authority flags are not rewritten as approvals.

Execution evidence is retained privately under `reports/publication-approved/`,
including the exact reviewer copy/binding, preflight receipts, upload/download
hash maps, prior/staged Pages inventories and full public HTTPS receipt. Two local
staging details are retained in the session history: the old local Pages branch
was fast-forwarded to the observed remote baseline before staging, and an initial
staging enumeration stopped on an empty trailing path before any site write;
the corrected enumeration verified the complete inventory. Neither is a hidden
production-check or public-verification failure.

The sections below preserve the earlier preparation chronology and its failed
attempts. Their not-published/missing-review statements describe those phases,
not the current published state or a continuing request for owner authorization.

## Observed operator outcome (2026-11-05)

The native GitHub API renamed the existing repository successfully and confirmed
numeric ID **1428864210** at the new name. The local `origin` fetch/push URL is
`https://github.com/kcook98765/kcook-lab-repo.git`. No local commit or source push,
Release upload, Pages configuration write or candidate-site deployment was made.
GitHub reported an automatic Pages rebuild after the repository rename; that is
not deployment of the locally prepared rebrand or proof of its public bytes.

All **421 tests** passed across all 25 `test_*.py` modules using four isolated
unittest-discovery processes. The initial serial run had 63 errors due to the
disposable publisher fixture inheriting the production version; its explicit
0.1.0 transport guard is retained and the fixture now pins its own version.
The corrected serial run timed out after 900 seconds. Both runs are retained;
the passing module-sharded rerun does not erase those outcomes.

During the initial preparation, the production build failed on missing
`incoming/plugin.video.tastemade-0.1.0.zip`. The exact private record
`tastemade-review-v3-approved-r10.json` (SHA-256
`442db92cb401bf981de89eeebac9be54492a81d97fa57abcf2bb69f4a33df05f`)
was also absent. Verification, independent production audit and publication
preflight reject the old local plan as stale; production qualification fails on
the missing ZIP. That attempt produced no current production site manifest/hash.
Those failures are historical; the restored-input rerun below supersedes the
missing-input blocker without deleting its evidence. Freshly reassess all gates before promotion;
do not treat the old plan or reports as evidence for changed bytes.

The standalone proposed `repository.ai.kodi-0.1.1.zip` is **2609 bytes**, SHA-256
`e1dda80a7f734681553583592fb993295b60a5457b066aab059dadcc96b39aee`.
Repeat packaging produced identical bytes and the independent archive parser
matched all runtime members. This is not a production-feed audit, independent
release-review approval, official addon-check result or native acceptance.
The prior installer was restored from this project's local `gh-pages` Git object
only after matching its existing ledger hash; historical ledger entries and
published artifacts were not rewritten.

Local evidence: `reports/rebranding/test-shards/summary.json`, per-command JSON
receipts (including failures), `historical-installer.json`,
`installer-proposal.json`, and the proposed ZIP/sidecar. Source scan, complete
review patch, source hash manifest and remote identity observations are frozen
under that same ignored directory. Private receipts must not be uploaded as
public release assets.

## Restored-input production preparation

The owner restored the original Tastemade ZIP/review pair and requested fresh
local preparation, retaining Tastemade 0.1.0 in **Omega only**, with presentation
before any commit, push or deployment. No new package, lane approval or runtime
test is requested. The current native-operator instructions and maintenance skill
were reread; their role/release restrictions remain unchanged.

Fresh verification matched the ZIP SHA-256
`d21af0f89c118c2a4c789b656b27d6211a086cce961dc3501fa4ad00564fce87`
and frozen r10 review SHA-256
`442db92cb401bf981de89eeebac9be54492a81d97fa57abcf2bb69f4a33df05f`.
The runtime member hashes match the record and the independent archive parser.
Neither file, its decisions, source commit, expiry nor lane scope was changed.
The ledger remains unchanged; repository installer 0.1.0 is retained exactly.

The actual production build, verification, independent audit, deterministic
qualification and local publication preflight all passed with **26 site files**,
four catalogs, 17 lane-selector cases and bootstrap parser replay for Kodi
19/20/21/22. Repeat builds match. The sole bootstrap installer link is 0.1.1;
historical 0.1.0 remains downloadable but has no selected lanes. Only Omega also
contains Tastemade 0.1.0. Root/canonical/Release installer copies and sidecars were
checked; no fixture or private evidence is exported to the site.

- Proposed tag: `repository-0.1.1` (not created).
- Complete site-manifest SHA-256:
  `93a163a71af469cb61d04d8c4ae7095ed89a9a31438142182108d8f80db7a83b`.
- Release-plan SHA-256:
  `fc8d94fa4e1b9cd76eedb40f077d413f8e2c88fcdc97157b22b0db5b01fdda5a`.
- Installer 0.1.1 bytes and digest remain the standalone proposal recorded above.
- Full site/source/release inventory, refreshed diff, final test coverage and
  per-stage receipts are retained under ignored `reports/rebranding-resume/`.
  Prior production output and machine reports were backed up before regeneration;
  earlier failures/timeouts remain under `reports/rebranding/`.

**Warnings and limits:** optional `inputstream.adaptive` remains unresolved, not
a required dependency. The existing provider-only and initial-runtime exceptions
remain active through `2027-10-22T23:59:59Z`; broad rights stay pending, provider
authorization stays unverified, and runtime acceptance stays false/deferred.
R4/R5/R6 remain unobserved and R2-audio unavailable. Public notices preserve these
classifications. The referenced historical rights/native evidence was not
reopened or rehashed, and no new independent release-role approval is asserted.
The separately named external setup report was inaccessible under the installed
directory policy; no alternate path was used to bypass that restriction.

Passing local checks do not authorize publication. There has been no commit,
push, Release upload, Pages settings write or deployment of the new candidate.
Public HTTPS comparison and native acceptance of the renamed feed/installer are
not performed by local qualification and remain unverified.

## Proposed distribution

- GitHub: `https://github.com/kcook98765/kcook-lab-repo`
- Pages: `https://kcook98765.github.io/kcook-lab-repo/`
- Visible installer and File manager label: `kcook-lab-repo`.
- Kodi ID remains `repository.ai.kodi`; proposed installer version is **0.1.1**.
- Existing lane selectors, package approvals and Tastemade 0.1.0 Omega selection
  remain unchanged. No new add-on release or runtime acceptance is asserted.
- Installer 0.1.0 remains pinned to
  `f4ec0c67329e70516baa824606f9133ff95516bea0cfcee6370fa2ac7a0afdad`.
  Production intake explicitly restores it as historical infrastructure, without
  changing its bytes, linking it as current, or inventing review decisions.
- No release-ledger entry for 0.1.1 is added merely by preparing a local proposal.

## Current evidence boundaries

The exact Tastemade ZIP and private review record listed in
`config/production.json` are restored and locally verified. Production generation
still fails closed on altered or missing inputs; do not remove packages,
fabricate records, refresh expired approvals or substitute historical successful
receipts to get a PASS.
Local test controls using synthetic inputs do not qualify production content.
Current machine outputs are under ignored `reports/rebranding-resume/`; the earlier
`reports/rebranding/` output retains its original scope and failures.

No source push, release upload, Pages settings change or site deployment is
authorized by this preparation. A GitHub rename alone does not deploy the new
installer or prove public HTTPS delivery. The renamed endpoint and installer
have not received native acceptance.

## Intentional historical names

Do not globally replace `ai-kodi-repository` or `AI Kodi` in frozen evidence:

- Dated plans, handoffs and historical native observations describe the identities
  and decisions actually observed at that time; their old URLs are historical,
  not current instructions. This record supersedes their current-name references.
- Existing copyright notices retain the original contributor attribution.
- The disposable `simulation/ai-kodi-repository` and
  `https://publication.invalid/ai-kodi-repository/` are fixed inert protocol
  identifiers, not production destinations. Their schema and security controls
  are unchanged. Qualification repository/fixture add-on IDs also remain distinct.
- OpenCode profiles, adapters and model/provider settings are not reconfigured by
  this task. The canonical local directory remains `ai-kodi-repository` because
  existing containment bindings use that path. Only the Git remote is renamed.

Tester/reviewer role restrictions, independent review requirements and production
approval gates remain intact. Missing machine evidence or independent role review
is a blocker, not inferred approval.
