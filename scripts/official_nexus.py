"""Offline official Nexus metadata for ONE frozen TV Guide beta, never approval.

Same-side Omega parsing primitives are reused, not Aura enrollment or core pins.
The auditor uses only its own independently implemented primitives/resolver.
"""
from datetime import datetime, timedelta, timezone
from functools import cmp_to_key
import hashlib
import xml.etree.ElementTree as ET
import official_omega as parsing

SOURCE_URL = 'https://mirrors.kodi.tv/addons/nexus/addons.xml.gz'
CORE_COMMIT = '4b95737efaddf7c869736e539318f18433413ff1'
ROOT_ID = 'script.tvguide.fullscreen'
ROOT_BINDING = {'version': '0.1.1', 'source_commit': 'f936c0a514e0de126e62e24fd3d24b66b0c74097',
                'package_sha256': '76533fcb570cd813e2deb885c919b59eea21171c6ce344d5a40ef5d8fba287b9'}
TVGUIDE_012 = {'version': '0.1.2',
               'source_commit': '8fe6ede7c84cabd4d7d699335ed4e739a542b7d4',
               'package_sha256': 'cc2df0ccc16f2b5c8323723598153fb3f8afd490af206091c26b4f8075fce90b'}
TVGUIDE_013 = {'version': '0.1.3',
               'source_commit': '079b1cff0e5385c2a5f79ec288519a737ac5add0',
               'package_sha256': 'b5d9e9e6a402a051f6b4e59b904973a87ff715bff5567abe1a75fb8acb7bc339'}
# From exact 20.5-Nexus addons/ manifests, acquired with provenance.
CORE = {'xbmc.core': ('0.1.0', '0.1'), 'xbmc.python': ('3.0.1', '3.0.0'),
        'script.module.pil': ('5.1.0', None)}
REQUIRED = [('script.module.beautifulsoup4', '4.12.2', False),
            ('script.module.dateutil', '2.8.2', False), ('script.module.pil', '5.1.0', False),
            ('script.module.pytz', '2023.3.0+matrix.1', False),
            ('script.module.requests', '2.31.0', False), ('xbmc.python', '3.0.0', False)]


def require(ok, reason):
    if not ok: raise ValueError('Official Nexus: ' + reason)


def resolve(manifests, builtins, external_dependencies, incoming_root, lane, bindings, now=None):
    empty = {'active': False, 'external_versions': {}, 'edges': [], 'unavailable_optional': [], 'warnings': []}
    require(isinstance(external_dependencies, dict), 'external dependencies must be an object')
    if not external_dependencies: return empty
    require(set(external_dependencies) == {'official_nexus'}, 'unsupported external provider')
    spec = external_dependencies['official_nexus']
    require(isinstance(spec, dict) and set(spec) == parsing.KEYS, 'malformed snapshot specification')
    require(type(spec['schema']) is int and spec['schema'] == 1 and spec['source_url'] == SOURCE_URL and
            spec['core_commit'] == CORE_COMMIT, 'unsupported snapshot source/schema/core')
    require(isinstance(spec['snapshot_sha256'], str) and parsing.HEX.fullmatch(spec['snapshot_sha256']), 'invalid snapshot hash')
    retrieved, expiry = parsing._stamp(spec['retrieved_at']), parsing._stamp(spec['expires_at'])
    require(retrieved <= (now or datetime.now(timezone.utc)) < expiry and
            timedelta(0) < expiry - retrieved <= timedelta(days=7), 'snapshot expired, future-dated or validity exceeds seven days')
    allow = spec['allowlist']
    require(isinstance(allow, dict) and 0 < len(allow) <= 128 and all(
        isinstance(k, str) and parsing.ID.fullmatch(k) and k not in CORE for k in allow), 'invalid official allowlist')
    for version in allow.values(): parsing._parts(version)
    release = spec['roots'].get(ROOT_ID) if isinstance(spec['roots'], dict) else None
    require(spec['roots'] == {ROOT_ID: release} and release in (ROOT_BINDING, TVGUIDE_012, TVGUIDE_013), 'only exact frozen TV Guide beta is enrolled')
    raw = parsing._read_snapshot(incoming_root, spec['snapshot'])
    require(hashlib.sha256(raw).hexdigest() == spec['snapshot_sha256'], 'snapshot checksum mismatch')
    require(b'\0' not in raw, 'only UTF-8 snapshot XML is accepted')
    raw.decode('utf-8-sig')
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'snapshot entities forbidden')
    index = ET.fromstring(raw)
    require(index.tag == 'addons' and len(index) <= 10000 and all(n.tag == 'addon' for n in index), 'invalid official index')
    catalog = {}
    for node in index:
        require(node.get('id') and node.get('version'), 'index identity/version missing')
        catalog.setdefault(node.get('id'), []).append(node)
    selected = {m.get('id'): m for m in manifests}
    require(len(selected) == len(manifests) and not set(selected) & set(allow), 'ambiguous or substituted selected package')
    if lane != 'nexus':
        require(ROOT_ID not in selected, 'TV Guide adapter is Nexus 20.5-only')
        return empty
    if ROOT_ID not in selected: return empty
    root = selected[ROOT_ID]
    require(root.get('version') == release['version'] and parsing._requirements(root) == REQUIRED and
            sorted((n.get('point'), n.get('library')) for n in root.findall('extension') if n.get('point') != 'xbmc.addon.metadata') ==
            [('xbmc.python.script', 'addon.py'), ('xbmc.service', 'service.py')], 'enrolled root manifest mismatch')
    require(bindings.get(ROOT_ID) == {k: release[k] for k in ('source_commit', 'package_sha256')} |
            {'source_repository': 'https://github.com/kcook98765/script.tvguide.fullscreen'}, 'TV Guide artifact/source binding mismatch')
    for aid in set(builtins) & set(CORE): require(builtins[aid] == CORE[aid][0], 'configured built-in differs from pinned Nexus core')
    for aid, manifest in selected.items():
        if aid != ROOT_ID:
            require(not any(dep in allow or dep in CORE and dep not in builtins
                            for dep, _, optional in parsing._requirements(manifest) if not optional),
                    'unrelated package attempts TV Guide-only admission')
    external, core, edges, missing, done, active = {}, {}, [], [], set(), set()

    def visit(parent, aid, minimum, optional=False, branch=False):
        branch = branch or optional
        edge = dict(parent=parent, addon=aid, minimum=minimum, optional=optional, optional_branch=branch)
        if aid in CORE:
            version, abi = CORE[aid]
            require(parsing.compare_versions(minimum, version) <= 0 and (abi is None or
                    parsing.compare_versions(minimum, abi) >= 0), 'core version/ABI unavailable: ' + aid)
            core[aid] = version
            edge.update(provider='Kodi 20.5 core', version=version)
            children = [] if aid == 'xbmc.core' else [('xbmc.python', '3.0.0', False)] if aid == 'script.module.pil' else [('xbmc.core', '0.1.0', False)]
        else:
            providers = catalog.get(aid, [])
            if not providers and optional:
                missing.append(edge)
                return
            require(providers, 'required official dependency absent: ' + aid)
            newest = max((n.get('version') for n in providers), key=cmp_to_key(parsing.compare_versions))
            copies = [n for n in providers if parsing.compare_versions(n.get('version'), newest) == 0]
            require(all(n.get('version') == newest for n in copies), 'ambiguous equivalent official version: ' + aid)
            require(allow.get(aid) == newest, 'official dependency outside exact newest-version allowlist: ' + aid)
            require(parsing.compare_versions(minimum, newest) <= 0, 'official dependency version too old: ' + aid)
            require(not any((n.text or '').strip() for c in copies for n in c.findall('./extension/broken')), 'official dependency marked broken: ' + aid)
            variants = {tuple(parsing._requirements(n)) for n in copies}
            require(len(variants) == 1, 'ambiguous platform dependency declarations: ' + aid)
            children = next(iter(variants))
            external[aid] = newest
            edge.update(provider='official Nexus repository', version=newest)
        edges.append(edge)
        require(aid not in active, 'dependency cycle: ' + aid)
        if (aid, branch) in done: return
        active.add(aid)
        for child, floor, opt in children: visit(aid, child, floor, opt, branch)
        active.remove(aid)
        done.add((aid, branch))

    for aid, floor, optional in parsing._requirements(root): visit(ROOT_ID, aid, floor, optional)
    require(set(external) == set(allow), 'unused or incomplete exact official allowlist')
    return dict(active=True, source_url=SOURCE_URL, snapshot_sha256=spec['snapshot_sha256'],
                retrieved_at=spec['retrieved_at'], expires_at=spec['expires_at'], core_commit=CORE_COMMIT,
                version_comparison_source='https://github.com/xbmc/xbmc/blob/' + CORE_COMMIT + '/xbmc/addons/AddonVersion.cpp',
                roots=spec['roots'], external_versions=dict(sorted(external.items())), core_versions=dict(sorted(core.items())),
                edges=sorted(edges, key=lambda e: (e['parent'], e['addon'], e['optional_branch'], e['minimum'])),
                unavailable_optional=sorted(missing, key=lambda e: (e['parent'], e['addon'])),
                warnings=['Official snapshot dependency evidence only; no dependency installation or native acceptance is asserted.'])
