# Reviewed package intake

Private intake is ignored; a clean checkout does not contain its ZIPs or review
records. Restore only the exact approved inputs named in config/production.json;
do not substitute unreleased Tastemade or Aura inspection packages.
See docs/RELEASE-WORKFLOW.md for the explicit reviewed-input schema and gates.
Only packages and retained installers named in config/production.json can be consumed. Never discover
or fetch source archives automatically. Frozen previous inputs must remain
available for clean restoration and agree with releases/manifest.json.
