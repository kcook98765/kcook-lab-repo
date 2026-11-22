"""Independent Nexus 20.5/TV Guide reconstruction. Never imports the producer."""
from datetime import datetime, timezone
from functools import cmp_to_key
import hashlib
import xml.etree.ElementTree as XML
import audit_official_omega as parsing

ORIGIN = 'https://mirrors.kodi.tv/addons/nexus/addons.xml.gz'
REVISION = '4b95737efaddf7c869736e539318f18433413ff1'
ADDON = 'script.tvguide.fullscreen'
ENROLLED = {'version': '0.1.0', 'package_sha256': 'da5f38eed4707aa6de9ac7d9648008565ac332f51e93dc6cc5dab6f11f00f82e',
            'source_commit': 'c19f256333efbe7af12418312f17e00f99792dc2'}
# Independently checked exact 20.5 tag/commit manifests; no Omega ABI borrowing.
PROVIDED = {'xbmc.core': ('0.1.0', '0.1'), 'xbmc.python': ('3.0.1', '3.0.0'),
            'script.module.pil': ('5.1.0', None)}


def check(ok, reason):
    if not ok: raise ValueError('Audit official Nexus: ' + reason)


def resolve(manifests, builtins, external_dependencies, incoming_root, lane, bindings, now=None):
    inactive = {'active': False, 'external_versions': {}, 'edges': [], 'unavailable_optional': [], 'warnings': []}
    check(isinstance(external_dependencies, dict), 'external dependencies must be an object')
    if not external_dependencies: return inactive
    check(set(external_dependencies) == {'official_nexus'}, 'unsupported external provider')
    data = external_dependencies['official_nexus']
    check(isinstance(data, dict) and set(data) == parsing.FIELDS, 'malformed snapshot specification')
    check(type(data['schema']) is int and data['schema'] == 1 and data['source_url'] == ORIGIN and
          data['core_commit'] == REVISION, 'unsupported snapshot source/schema/core')
    import re
    check(isinstance(data['snapshot_sha256'], str) and re.fullmatch('[0-9a-f]{64}', data['snapshot_sha256']), 'invalid snapshot hash')
    retrieved, expires = parsing.timestamp(data['retrieved_at']), parsing.timestamp(data['expires_at'])
    check(retrieved <= (now or datetime.now(timezone.utc)) < expires and
          0 < (expires - retrieved).total_seconds() <= 604800, 'snapshot expired, future-dated or validity exceeds seven days')
    listed = data['allowlist']
    check(isinstance(listed, dict) and 0 < len(listed) <= 128, 'invalid official allowlist')
    for aid, ver in listed.items():
        check(isinstance(aid, str) and re.fullmatch(parsing.IDENTIFIER, aid) and aid not in PROVIDED, 'invalid official allowlist')
        parsing.parse_version(ver)
    check(data['roots'] == {ADDON: ENROLLED}, 'only exact frozen TV Guide beta is enrolled')
    raw = parsing.file_bytes(incoming_root, data['snapshot'])
    check(hashlib.sha256(raw).hexdigest() == data['snapshot_sha256'], 'snapshot checksum mismatch')
    check(b'\0' not in raw, 'only UTF-8 snapshot XML is accepted')
    raw.decode('utf-8-sig')
    check(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'snapshot entities forbidden')
    index = XML.fromstring(raw)
    check(index.tag == 'addons' and len(index) <= 10000 and all(n.tag == 'addon' for n in index), 'invalid official index')
    catalog = {}
    for node in index:
        check(node.get('id') and node.get('version'), 'index identity/version missing')
        catalog.setdefault(node.get('id'), []).append(node)
    selected = {n.get('id'): n for n in manifests}
    check(len(selected) == len(manifests) and not set(selected).intersection(listed), 'ambiguous or substituted selected package')
    if lane != 'nexus':
        check(ADDON not in selected, 'TV Guide adapter is Nexus 20.5-only')
        return inactive
    if ADDON not in selected: return inactive
    root = selected[ADDON]
    expected_imports = (('script.module.beautifulsoup4', '4.12.2', False), ('script.module.dateutil', '2.8.2', False),
                        ('script.module.pil', '5.1.0', False), ('script.module.pytz', '2023.3.0+matrix.1', False),
                        ('script.module.requests', '2.31.0', False), ('xbmc.python', '3.0.0', False))
    extensions = [(e.get('point'), e.get('library')) for e in root.findall('extension') if e.get('point') != 'xbmc.addon.metadata']
    check(root.get('version') == '0.1.0' and parsing.imports(root) == expected_imports and
          sorted(extensions) == [('xbmc.python.script', 'addon.py'), ('xbmc.service', 'service.py')], 'enrolled root manifest mismatch')
    binding = bindings.get(ADDON, {})
    check(set(binding) == {'source_commit', 'package_sha256', 'source_repository'} and
          binding['source_commit'] == ENROLLED['source_commit'] and binding['package_sha256'] == ENROLLED['package_sha256'] and
          binding['source_repository'] == 'https://github.com/kcook98765/script.tvguide.fullscreen', 'TV Guide artifact/source binding mismatch')
    for aid in set(builtins).intersection(PROVIDED):
        check(builtins[aid] == PROVIDED[aid][0], 'configured built-in differs from pinned Nexus core')
    for aid, node in selected.items():
        if aid != ADDON:
            check(not any(a in listed or a in PROVIDED and a not in builtins
                          for a, _, opt in parsing.imports(node) if not opt), 'unrelated package attempts TV Guide-only admission')
    ext, core, edges, missing, finished = {}, {}, [], [], set()

    def walk(parent, aid, floor, optional, branch, ancestry):
        branch = branch or optional
        edge = dict(parent=parent, addon=aid, minimum=floor, optional=optional, optional_branch=branch)
        if aid in PROVIDED:
            ver, abi = PROVIDED[aid]
            check(parsing.compare_versions(floor, ver) <= 0 and (abi is None or
                  parsing.compare_versions(floor, abi) >= 0), 'core version/ABI unavailable: ' + aid)
            core[aid] = ver
            edge['provider'], edge['version'] = 'Kodi 20.5 core', ver
            descendants = () if aid == 'xbmc.core' else (('xbmc.python', '3.0.0', False),) if aid == 'script.module.pil' else (('xbmc.core', '0.1.0', False),)
        else:
            providers = catalog.get(aid, [])
            if not providers and optional:
                missing.append(edge)
                return
            check(providers, 'required official dependency absent: ' + aid)
            versions = sorted({n.get('version') for n in providers}, key=cmp_to_key(parsing.compare_versions))
            newest = versions[-1]
            check(sum(parsing.compare_versions(v, newest) == 0 for v in versions) == 1, 'ambiguous equivalent official version: ' + aid)
            copies = [n for n in providers if n.get('version') == newest]
            check(listed.get(aid) == newest, 'official dependency outside exact newest-version allowlist: ' + aid)
            check(parsing.compare_versions(floor, newest) <= 0, 'official dependency version too old: ' + aid)
            check(not any((b.text or '').strip() for n in copies for b in n.findall('./extension/broken')), 'official dependency marked broken: ' + aid)
            choices = {parsing.imports(n) for n in copies}
            check(len(choices) == 1, 'ambiguous platform dependency declarations: ' + aid)
            descendants = next(iter(choices))
            ext[aid] = newest
            edge['provider'], edge['version'] = 'official Nexus repository', newest
        edges.append(edge)
        check(aid not in ancestry, 'dependency cycle: ' + aid)
        if (aid, branch) not in finished:
            for child, ver, opt in descendants: walk(aid, child, ver, opt, branch, ancestry + (aid,))
            finished.add((aid, branch))

    for aid, floor, optional in parsing.imports(root): walk(ADDON, aid, floor, optional, False, ())
    check(set(ext) == set(listed), 'unused or incomplete exact official allowlist')
    return {'active': True, 'source_url': ORIGIN, 'snapshot_sha256': data['snapshot_sha256'],
            'retrieved_at': data['retrieved_at'], 'expires_at': data['expires_at'], 'core_commit': REVISION,
            'version_comparison_source': 'https://github.com/xbmc/xbmc/blob/' + REVISION + '/xbmc/addons/AddonVersion.cpp',
            'roots': data['roots'], 'external_versions': dict(sorted(ext.items())), 'core_versions': dict(sorted(core.items())),
            'edges': sorted(edges, key=lambda e: (e['parent'], e['addon'], e['optional_branch'], e['minimum'])),
            'unavailable_optional': sorted(missing, key=lambda e: (e['parent'], e['addon'])),
            'warnings': ['Official snapshot dependency evidence only; no dependency installation or native acceptance is asserted.']}
