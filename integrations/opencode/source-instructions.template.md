## Distribution preparation from this project

The canonical distribution repository is `kcook98765/kcook-lab-repo`, GitHub
repository ID `1428864210`, origin
`https://github.com/kcook98765/kcook-lab-repo.git`. Its verified existing checkout
is `${DISTRIBUTION_ROOT}`; the old local
folder name is retained. This add-on's source origin remains
`https://github.com/kcook98765/script.channelsdvr.hub.git`.

For requests to add/release this add-on to the distribution repository, use the
`github-operator` primary or `/kodi-release-prepare` in this same selected project.
The command selects the operator; it does not switch projects or delegate to a
restricted fixture role. Ordinary `kodi-develop`/test/inspect roles keep their
existing permissions. Do not try to turn them into distribution operators.

The operator is enrolled for this source and exact distribution checkout. Load
`kodi-repository-maintenance` and explicitly read the destination's AGENTS.md,
`.opencode/GITHUB-OPERATOR.md`, docs/AGENT-INTEGRATION.md, docs/RELEASE-WORKFLOW.md
and docs/APPROVAL-CONTRACT.md before preparation. Resolve distribution-relative
paths there. Inspect both HEADs, remotes and dirty state; a remote snapshot alone
cannot account for local changes. Do not edit source merely to prepare intake.
Use ignored `.local/reports/` here or `reports/intake/` there for new evidence.
Missing native acceptance, rights/technical review or final approval blocks
production admission, not truthful isolated candidate preparation. Preserve
version immutability, current policies and independent review. New release
authorization must bind exact reviewed bytes and destination. This configuration
repair and preparation command authorize no publication or runtime testing.
