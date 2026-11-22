"""Pinned official Omega evidence for Aura and the exact enrolled TV Guide beta.

No download, add-on execution, package mirroring, built-in reclassification or
release authority. Consumers retain their own ordinary dependency/approval gates.
"""
from datetime import datetime, timedelta, timezone
from functools import cmp_to_key
import hashlib
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ET

SOURCE_URL = 'https://mirrors.kodi.tv/addons/omega/addons.xml.gz'
CORE_COMMIT = 'a3a448d26b8d560a65655dab2cd122994dc4e146'
CORE_SOURCE = 'https://github.com/xbmc/xbmc/blob/' + CORE_COMMIT
VERSION_SOURCE = CORE_SOURCE + '/xbmc/addons/AddonVersion.cpp'
# Provider version and compatible ABI lower bound from that exact Kodi source.
CORE = {
    'xbmc.core': ('0.1.0', '0.1'),
    'xbmc.gui': ('5.17.0', '5.17.0'),
    'xbmc.python': ('3.0.1', '3.0.0'),
    'xbmc.json': ('13.5.0', '6.0.0'),
    'kodi.resource': ('1.0.0', '1.0'),
    'script.module.pil': ('5.1.0', None),
    'kodi.binary.global.main': ('2.0.2', '2.0.0'),
    'kodi.binary.global.general': ('1.0.5', '1.0.4'),
    'kodi.binary.global.gui': ('5.15.0', '5.15.0'),
    'kodi.binary.global.filesystem': ('1.1.9', '1.1.7'),
    'kodi.binary.global.tools': ('1.0.4', '1.0.0'),
    'kodi.binary.instance.inputstream': ('3.3.0', '3.3.0'),
    'kodi.binary.instance.videocodec': ('2.1.0', '2.1.0'),
}
KEYS = {'schema', 'source_url', 'snapshot', 'snapshot_sha256', 'retrieved_at',
        'expires_at', 'core_commit', 'allowlist', 'roots'}
ID = re.compile(r'[a-z0-9]+(?:[._-][a-z0-9]+)+\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
TVGUIDE = 'script.tvguide.fullscreen'
TV_BINDING = {'version': '0.1.1', 'source_commit': 'f936c0a514e0de126e62e24fd3d24b66b0c74097',
              'package_sha256': '76533fcb570cd813e2deb885c919b59eea21171c6ce344d5a40ef5d8fba287b9'}


def require(ok, reason):
    if not ok:
        raise ValueError('Official Omega: ' + reason)


def _parts(value):
    require(isinstance(value, str) and len(value) <= 128 and re.fullmatch(
        r'(?:[0-9]+:)?[0-9][A-Za-z0-9]*(?:[.+_@~][A-Za-z0-9]+)*'
        r'(?:-[A-Za-z0-9]+(?:[.+_@~][A-Za-z0-9]+)*)?', value), 'invalid Kodi dependency version')
    require(all(len(n) <= 10 and int(n) <= 2147483647 for n in re.findall('[0-9]+', value)),
            'Kodi dependency numeric component out of range')
    epoch, _, rest = value.partition(':')
    if not _:
        epoch, rest = '0', value
    upstream, _, revision = rest.lower().partition('-')
    return int(epoch), upstream, revision


def _component(left, right):
    # Kodi compares alternating literal spans and integer spans; '~' sorts first.
    i = j = 0
    while i < len(left) and j < len(right):
        a, b = left[i], right[j]
        if not a.isdigit() and not b.isdigit():
            if a != b:
                return -1 if a == '~' else 1 if b == '~' else (-1 if a < b else 1)
            i += 1; j += 1
        elif a.isdigit() and b.isdigit():
            ai, bj = i, j
            while i < len(left) and left[i].isdigit(): i += 1
            while j < len(right) and right[j].isdigit(): j += 1
            x, y = int(left[ai:i]), int(right[bj:j])
            if x != y: return -1 if x < y else 1
        else:
            if a == '~': return -1
            if b == '~': return 1
            return -1 if a.isdigit() else 1
    if i < len(left): return -1 if left[i] == '~' else 1
    if j < len(right): return 1 if right[j] == '~' else -1
    return 0


def compare_versions(left, right):
    a, b = _parts(left), _parts(right)
    return (-1 if a[0] < b[0] else 1) if a[0] != b[0] else _component(a[1], b[1]) or _component(a[2], b[2])


def _stamp(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value), 'invalid snapshot time')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('Official Omega: invalid snapshot date') from None


def _read_snapshot(base, name):
    require(isinstance(name, str) and len(name) < 256, 'invalid snapshot path')
    p = PurePosixPath(name)
    require(p.parts and p.as_posix() == name and not p.is_absolute() and '..' not in p.parts and
            all(not part.startswith('.') and not part.endswith((' ', '.')) and
                re.fullmatch(r'[A-Za-z0-9_.-]+', part) for part in p.parts), 'unsafe snapshot path')
    root = Path(base)
    require(root.is_absolute() and root == root.resolve(), 'noncanonical incoming root')
    path = root.joinpath(*p.parts)
    require(not any(x.is_symlink() for x in (path, *path.parents)), 'linked snapshot path')
    require(path.is_file() and path.stat().st_size <= 32_000_000, 'snapshot absent or too large')
    raw = path.read_bytes()
    require(len(raw) <= 32_000_000, 'snapshot grew beyond size limit')
    return raw


def _requirements(node):
    groups = node.findall('requires')
    require(len(groups) <= 1, 'multiple requires blocks')
    dependencies = []
    for group in groups:
        for item in group:
            require(item.tag == 'import' and set(item.attrib) <= {'addon', 'version', 'optional'}, 'malformed official dependency')
            aid, version = item.get('addon', ''), item.get('version', '0.0.0')
            require(ID.fullmatch(aid), 'invalid dependency ID')
            _parts(version)
            require(item.get('optional', 'false') in ('true', 'false'), 'invalid optional flag')
            dependencies.append((aid, version, item.get('optional') == 'true'))
    require(len({a for a, _, _ in dependencies}) == len(dependencies), 'duplicate dependency')
    return sorted(dependencies)


def resolve(manifests, builtins, external_dependencies, incoming_root, lane, bindings, now=None):
    """Reconstruct the entire pinned official closure; return explicit providers.

    bindings comes from independently verified package/review inputs, keyed by ID,
    containing package_sha256 and source_commit. No report is a runtime receipt.
    """
    empty = {'active': False, 'external_versions': {}, 'edges': [], 'unavailable_optional': [], 'warnings': []}
    require(isinstance(external_dependencies, dict), 'external dependencies must be an object')
    if external_dependencies == {}:
        return empty
    require(set(external_dependencies) == {'official_omega'}, 'unsupported external provider')
    spec = external_dependencies['official_omega']
    require(isinstance(spec, dict) and set(spec) == KEYS, 'malformed snapshot specification')
    require(type(spec['schema']) is int and spec['schema'] == 1 and spec['source_url'] == SOURCE_URL and
            spec['core_commit'] == CORE_COMMIT, 'unsupported snapshot source/schema/core')
    require(isinstance(spec['snapshot_sha256'], str) and HEX.fullmatch(spec['snapshot_sha256']), 'invalid snapshot hash')
    retrieved, expiry = _stamp(spec['retrieved_at']), _stamp(spec['expires_at'])
    current = now or datetime.now(timezone.utc)
    require(retrieved <= current < expiry and timedelta(0) < expiry - retrieved <= timedelta(days=7), 'snapshot expired, future-dated or validity exceeds seven days')
    allow = spec['allowlist']
    require(isinstance(allow, dict) and 0 < len(allow) <= 128 and all(isinstance(k, str) and ID.fullmatch(k) and k not in CORE for k in allow), 'invalid official allowlist')
    for version in allow.values(): _parts(version)
    require(isinstance(spec['roots'], dict) and spec['roots'] and
            set(spec['roots']) <= {'skin.aura', TVGUIDE}, 'only Aura and exact TV Guide are enrolled')
    if 'skin.aura' in spec['roots']:
        binding = spec['roots']['skin.aura']
        require(isinstance(binding, dict) and set(binding) == {'version', 'package_sha256', 'source_commit'} and
                binding['version'] == '2.1.0' and isinstance(binding['package_sha256'], str) and HEX.fullmatch(binding['package_sha256']) and
                isinstance(binding['source_commit'], str) and re.fullmatch(r'[0-9a-f]{40}', binding['source_commit']), 'invalid Aura artifact binding')
    if TVGUIDE in spec['roots']:
        require(spec['roots'][TVGUIDE] == TV_BINDING, 'only exact frozen TV Guide beta is enrolled')
    raw = _read_snapshot(incoming_root, spec['snapshot'])
    require(hashlib.sha256(raw).hexdigest() == spec['snapshot_sha256'], 'snapshot checksum mismatch')
    require(b'\0' not in raw, 'only UTF-8 snapshot XML is accepted')
    raw.decode('utf-8-sig')
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'snapshot entities forbidden')
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError('Official Omega: invalid snapshot XML') from exc
    require(root.tag == 'addons' and len(root) <= 10000 and all(n.tag == 'addon' for n in root), 'invalid official index')
    index = {}
    for node in root:
        require(node.get('id') and node.get('version'), 'index identity/version missing')
        index.setdefault(node.get('id'), []).append(node)
    selected = {m.get('id'): m for m in manifests}
    require(len(selected) == len(manifests), 'ambiguous selected package ID')
    require(not set(selected) & set(allow), 'official provider may not be replaced by admitted package')
    if lane != 'omega':
        require('skin.aura' not in selected, 'Aura official adapter is Omega-only')
        require(TVGUIDE not in selected, 'TV Guide adapter is Omega 21.3-only')
        return empty
    require(TVGUIDE not in selected or TVGUIDE in spec['roots'], 'TV Guide requires its own exact Omega enrollment')
    enrolled = set(selected) & set(spec['roots'])
    if not enrolled: return empty
    if 'skin.aura' in enrolled:
        aura = selected['skin.aura']
        require(aura.get('version') == '2.1.0' and aura.find("extension[@point='xbmc.gui.skin']") is not None, 'enrolled root is not Aura 2.1.0 skin')
        binding, actual = spec['roots']['skin.aura'], bindings.get('skin.aura', {})
        require(actual.get('package_sha256') == binding['package_sha256'] and actual.get('source_commit') == binding['source_commit'] and actual.get('source_repository') == 'https://github.com/kcook98765/skin.aura', 'Aura artifact/source binding mismatch')
    if TVGUIDE in enrolled:
        tv = selected[TVGUIDE]
        require(tv.get('version') == '0.1.1' and _requirements(tv) == [
            ('script.module.beautifulsoup4', '4.12.2', False), ('script.module.dateutil', '2.8.2', False),
            ('script.module.pil', '5.1.0', False), ('script.module.pytz', '2023.3.0+matrix.1', False),
            ('script.module.requests', '2.31.0', False), ('xbmc.python', '3.0.0', False)] and
            sorted((n.get('point'), n.get('library')) for n in tv.findall('extension') if n.get('point') != 'xbmc.addon.metadata') ==
            [('xbmc.python.script', 'addon.py'), ('xbmc.service', 'service.py')], 'enrolled root manifest mismatch')
        require(bindings.get(TVGUIDE) == {k: TV_BINDING[k] for k in ('source_commit', 'package_sha256')} |
                {'source_repository': 'https://github.com/kcook98765/script.tvguide.fullscreen'}, 'TV Guide artifact/source binding mismatch')
    for aid, version in builtins.items():
        if aid in CORE: require(version == CORE[aid][0], 'configured built-in differs from pinned Omega core')
    # A separate selected add-on cannot borrow either root's external/core admission.
    for aid, node in selected.items():
        if aid not in enrolled:
            require(not any(dep in allow or dep in CORE and dep not in builtins
                            for dep, _, optional in _requirements(node) if not optional), 'unrelated package attempts Aura-only or TV Guide external admission')
    external = {}; core = {}; edges = []; unavailable = []; done = set(); active = set()

    def visit(parent, aid, minimum, optional=False, via_optional=False):
        branch = optional or via_optional
        edge = {'parent': parent, 'addon': aid, 'minimum': minimum, 'optional': optional, 'optional_branch': branch}
        if aid in CORE:
            version, abi = CORE[aid]
            require(compare_versions(minimum, version) <= 0 and (abi is None or compare_versions(minimum, abi) >= 0), 'core version/ABI unavailable: ' + aid)
            core[aid] = version
            edge.update(provider='Kodi 21.3 core', version=version)
            children = [] if aid == 'xbmc.core' else [('xbmc.python', '3.0.0', False)] if aid == 'script.module.pil' else [('xbmc.core', '0.1.0', False)]
        else:
            candidates = index.get(aid, [])
            if not candidates and optional:
                unavailable.append(edge)
                return
            require(bool(candidates), 'required official dependency absent: ' + aid)
            newest = max((n.get('version') for n in candidates), key=cmp_to_key(compare_versions))
            same = [n for n in candidates if compare_versions(n.get('version'), newest) == 0]
            require(all(n.get('version') == newest for n in same), 'ambiguous equivalent official version: ' + aid)
            require(aid in allow and allow[aid] == newest, 'official dependency outside exact newest-version allowlist: ' + aid)
            require(compare_versions(minimum, newest) <= 0, 'official dependency version too old: ' + aid)
            require(not any((n.text or '').strip() for c in same for n in c.findall('./extension/broken')), 'official dependency marked broken: ' + aid)
            graphs = {_requirements_signature(c) for c in same}
            require(len(graphs) == 1, 'ambiguous platform dependency declarations: ' + aid)
            children = list(graphs.pop())
            external[aid] = newest
            edge.update(provider='official Omega repository', version=newest)
        edges.append(edge)
        require(aid not in active, 'dependency cycle: ' + aid)
        if (aid, branch) in done: return
        active.add(aid)
        for child, floor, opt in children: visit(aid, child, floor, opt, branch)
        active.remove(aid)
        done.add((aid, branch))

    closures = {}
    all_external, all_core, all_edges, all_unavailable = {}, {}, [], []
    for root_id in sorted(enrolled):
        # Do not share traversal caches between roots, including optional branches.
        external, core, edges, unavailable, done, active = {}, {}, [], [], set(), set()
        for aid, minimum, optional in _requirements(selected[root_id]): visit(root_id, aid, minimum, optional)
        closures[root_id] = dict(external_versions=dict(sorted(external.items())), core_versions=dict(sorted(core.items())),
                                edges=sorted(edges, key=lambda e: (e['parent'], e['addon'], e['optional_branch'], e['minimum'])),
                                unavailable_optional=sorted(unavailable, key=lambda e: (e['parent'], e['addon'])))
        all_external.update(external); all_core.update(core)
        all_edges.extend(edges); all_unavailable.extend(unavailable)
    external, core, edges, unavailable = all_external, all_core, all_edges, all_unavailable
    require(set(external) == set(allow), 'unused or incomplete exact official allowlist')
    report = {'active': True, 'source_url': SOURCE_URL, 'snapshot_sha256': spec['snapshot_sha256'],
            'retrieved_at': spec['retrieved_at'], 'expires_at': spec['expires_at'], 'core_commit': CORE_COMMIT,
            'version_comparison_source': VERSION_SOURCE, 'roots': spec['roots'],
            'external_versions': dict(sorted(external.items())), 'core_versions': dict(sorted(core.items())),
            'edges': sorted(edges, key=lambda e: (e['parent'], e['addon'], e['optional_branch'], e['minimum'])),
            'unavailable_optional': sorted(unavailable, key=lambda e: (e['parent'], e['addon'])),
            'warnings': ['Official snapshot dependency evidence only; no dependency installation or native acceptance is asserted.']}
    if TVGUIDE in spec['roots']: report['root_closures'] = closures
    return report


def _requirements_signature(node):
    return tuple(_requirements(node))

# Export dependency comparison without changing the repository's strict package
# identity/version grammar. '+' is Kodi upstream text, not SemVer build metadata.
version_key = cmp_to_key(compare_versions)


def version_ge(provided, required):
    return compare_versions(provided, required) >= 0
