# Restore the OpenCode cross-repository operator

This optional integration targets OpenCode **1.19.3 / v1 configuration**. It
reproduces the reviewed `github-operator`, `/kodi-release-prepare`, exact source/
distribution enrollment, and the existing `kodi-repository-maintenance` skill.
It supplies no credentials, publisher, native-testing authority or release
approval. The manager, tester, reviewer, Toolkit and release contracts are unchanged.

## Tracked sources and private installation

`integrations/opencode/` is the version-controlled source for the installed
operator integration. `local-templates/skills/kodi-repository-maintenance/` holds
the existing maintenance skill, not a second implementation or a Toolkit copy.
Rendered copies under ignored `.opencode/` are installation artifacts. Templates
use named path variables; no Claw home directory, token, provider configuration,
target identity or session data is committed.

The canonical distribution is `kcook98765/kcook-lab-repo`, immutable GitHub ID
`1428864210`. Its retained local directory name may be `ai-kodi-repository`.
The enrolled example source is `kcook98765/script.channelsdvr.hub`. Keep these
origins distinct. Verify actual Git roots, origins, HEADs, worktrees and changes
before choosing paths. The renderer does not clone, change remotes or authenticate.
Replacing the distribution checkout requires restoring the rendered ignored
files too; a Git checkout alone does not install OpenCode integration.

## Stage a restoration

Use the existing owner-maintained restricted foundation profiles as bases. The
renderer preserves unrelated agents, models, providers, MCP connections, defaults,
instructions and skill paths. It merges only the reviewed operator integration.
Review any additional existing operator overrides; it does not erase owner rules.
Do not substitute these additive templates for an entire restricted foundation.

From the distribution checkout, use absolute canonical paths, with no symlinks or
permission wildcards. Replace the illustrative paths below with the chosen roots:

```sh
python3 -B scripts/opencode/stage_operator.py \
  --home-root /home/OWNER \
  --development-root /home/OWNER/development \
  --source-root /home/OWNER/development/addons/script.channelsdvr.hub \
  --distribution-root /home/OWNER/development/repository/kcook-lab-repo \
  --toolkit-root /home/OWNER/development/toolkit \
  --global-base /private/existing-service-overlay.json \
  --source-base /private/existing-source-opencode.json \
  --distribution-base /private/existing-distribution-opencode.json \
  --output /private/new-opencode-restore-stage
```

The output directory must not exist. The tool only writes private staging files;
it never installs, runs OpenCode, contacts GitHub or touches services. Base profile
arguments are optional only when staging a genuinely new corresponding profile.
Without bases, outputs reproduce this operator layer, not the rest of the host
or its restricted foundation. Outputs can carry private values from supplied
bases: keep the staging directory private and out of Git.

After reviewing the staged diff and retaining private backups, install only:

| Staged file | Installation destination |
| --- | --- |
| `global-profile.json` | The existing overlay selected by `OPENCODE_CONFIG` |
| `source-profile.json` | The enrolled source Git root's ignored `opencode.json` |
| `distribution-profile.json` | The distribution Git root's ignored `opencode.json` |
| `distribution-local/.opencode/GITHUB-OPERATOR.md` | Distribution `.opencode/GITHUB-OPERATOR.md` |
| `distribution-local/.opencode/skills/kodi-repository-maintenance/` | The same distribution `.opencode/skills/` skill directory |
| `source-instructions.md` | Append the distribution section to source `AGENTS.md`, preserving its development/security instructions |

Merge the source instruction section once; do not duplicate it or replace the
source's other instructions. Keep profiles private. The templates reproduce the
operator layer from the 2026-11-14 setup; dated historical statements in the
supplement are not evidence of a newly performed restore or approval.

Both service and CLI must select the same overlay. The existing Web service uses
its owner-configured `OPENCODE_CONFIG` environment. For a standalone CLI process,
set that variable to the restored global profile; do not print resolved provider
configuration or credential values. A fresh installation separately needs the
same supported OpenCode version, Git/gh, owner authentication, configured providers,
and the existing Toolkit checkout/environments if static checks are requested.
No service unit or credential file is supplied here.

## Verify and preserve boundaries

Use a fresh session in the enrolled source project and invoke
`/kodi-release-prepare`. Confirm the command selects `github-operator` as primary,
loads the maintenance skill, discovers the canonical destination, and inspects
both local origins/HEADs/dirty states without changing selected projects. Confirm
policy reads and a harmless new evidence write at the destination. Native shell
normally asks; exact command approval is distinct from publication authority.

Unrelated external roots must remain denied. The reverse distribution context
permits source inspection but denies source edits. Restricted roles must still
be denied destination access/maintenance skill outside their existing scopes.
Do not use shell to bypass a denial. These application permissions are not an OS
sandbox. No home-wide external-directory allow is installed.

Warm instances may retain cached configuration. Only when that exact directory
has no active sessions, PTYs, pending questions or permissions, the existing
supported scoped instance-disposal mechanism can refresh it. Do not restart the
service as an implicit restoration step; preserve historical sessions.

Preparation may retain pending rights/native/release decisions and qualify an
isolated private candidate. It cannot convert missing evidence into PASS or
authorize production admission/publication. Follow current RELEASE-WORKFLOW.md
and APPROVAL-CONTRACT.md, obtain independent frozen-byte/site review and exact
owner authorization before any publication. Schema shape or fixture success
does not supply material rights, provider-risk acceptance or native observations.
