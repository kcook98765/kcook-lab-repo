"""Independent offline reconstruction of the approved official Omega dependency gate.

Does not import the producer resolver or accept producer closure reports.
"""
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path, PurePosixPath
import hashlib
import re
import xml.etree.ElementTree as XML

ORIGIN = 'https://mirrors.kodi.tv/addons/omega/addons.xml.gz'
REVISION = 'a3a448d26b8d560a65655dab2cd122994dc4e146'
# Independently retained source pins: Kodi source at REVISION/addons and versions.h.
PROVIDED = {
    'xbmc.core': ('0.1.0', '0.1'), 'xbmc.gui': ('5.17.0', '5.17.0'),
    'xbmc.python': ('3.0.1', '3.0.0'), 'xbmc.json': ('13.5.0', '6.0.0'),
    'kodi.resource': ('1.0.0', '1.0'), 'script.module.pil': ('5.1.0', None),
    'kodi.binary.global.main': ('2.0.2', '2.0.0'),
    'kodi.binary.global.general': ('1.0.5', '1.0.4'),
    'kodi.binary.global.gui': ('5.15.0', '5.15.0'),
    'kodi.binary.global.filesystem': ('1.1.9', '1.1.7'),
    'kodi.binary.global.tools': ('1.0.4', '1.0.0'),
    'kodi.binary.instance.inputstream': ('3.3.0', '3.3.0'),
    'kodi.binary.instance.videocodec': ('2.1.0', '2.1.0'),
}
FIELDS = {'schema', 'source_url', 'snapshot', 'snapshot_sha256', 'retrieved_at',
          'expires_at', 'core_commit', 'allowlist', 'roots'}
IDENTIFIER = r'[a-z0-9]+(?:[._-][a-z0-9]+)+'
TVGUIDE = 'script.tvguide.fullscreen'
TV_ENROLLED = {'version': '0.1.1', 'package_sha256': '76533fcb570cd813e2deb885c919b59eea21171c6ce344d5a40ef5d8fba287b9',
               'source_commit': 'f936c0a514e0de126e62e24fd3d24b66b0c74097'}
TVGUIDE_012 = {'version': '0.1.2',
               'source_commit': '8fe6ede7c84cabd4d7d699335ed4e739a542b7d4',
               'package_sha256': 'cc2df0ccc16f2b5c8323723598153fb3f8afd490af206091c26b4f8075fce90b'}


def check(value, message):
    if not value:
        raise ValueError('Audit official Omega: ' + message)


def parse_version(value):
    check(isinstance(value, str) and len(value) <= 128 and re.fullmatch(
        r'(?:[0-9]+:)?[0-9][a-zA-Z0-9]*(?:[.+_@~][a-zA-Z0-9]+)*'
        r'(?:-[a-zA-Z0-9]+(?:[.+_@~][a-zA-Z0-9]+)*)?', value), 'invalid Kodi dependency version')
    check(all(len(n) <= 10 and int(n) <= 2147483647 for n in re.findall('[0-9]+', value)),
          'Kodi dependency numeric component out of range')
    colon = value.find(':')
    epoch = int(value[:colon]) if colon >= 0 else 0
    value = value[colon + 1:] if colon >= 0 else value
    upstream, _, revision = value.lower().partition('-')
    return epoch, re.findall(r'[0-9]+|[^0-9]', upstream), re.findall(r'[0-9]+|[^0-9]', revision)


def compare_versions(a, b):
    x, y = parse_version(a), parse_version(b)
    if x[0] != y[0]: return -1 if x[0] < y[0] else 1
    for left, right in zip(x[1:], y[1:]):
        offset = 0
        while offset < min(len(left), len(right)):
            l, r = left[offset], right[offset]
            ld, rd = l[0].isdigit(), r[0].isdigit()
            if ld and rd:
                if int(l) != int(r): return -1 if int(l) < int(r) else 1
            elif l != r:
                if l == '~': return -1
                if r == '~': return 1
                if ld != rd: return -1 if ld else 1
                return -1 if l < r else 1
            offset += 1
        if len(left) != len(right):
            if offset < len(left): return -1 if left[offset] == '~' else 1
            return 1 if right[offset] == '~' else -1
    return 0


def timestamp(value):
    check(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value), 'invalid snapshot time')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('Audit official Omega: invalid snapshot date') from None


def imports(node):
    groups = node.findall('requires')
    check(len(groups) <= 1, 'multiple requires blocks')
    out = []
    if groups:
        for child in groups[0]:
            check(child.tag == 'import' and set(child.attrib) <= {'addon', 'version', 'optional'}, 'malformed official dependency')
            aid, ver, option = child.get('addon', ''), child.get('version', '0.0.0'), child.get('optional', 'false')
            check(bool(re.fullmatch(IDENTIFIER, aid)) and option in ('false', 'true'), 'invalid dependency ID or optional flag')
            parse_version(ver)
            out.append((aid, ver, option == 'true'))
    check(len(out) == len({x[0] for x in out}), 'duplicate dependency')
    return tuple(sorted(out))


def file_bytes(root, relative):
    check(isinstance(relative, str) and len(relative) < 256, 'invalid snapshot path')
    path = PurePosixPath(relative)
    check(path.parts and not path.is_absolute() and path.as_posix() == relative and '..' not in path.parts and
          all(not c.startswith('.') and not c.endswith((' ', '.')) and re.fullmatch('[A-Za-z0-9_.-]+', c) for c in path.parts), 'unsafe snapshot path')
    base = Path(root)
    check(base.is_absolute() and base.resolve() == base, 'noncanonical incoming root')
    location = base / relative
    check(not any(p.is_symlink() for p in [location, *location.parents]), 'linked snapshot path')
    check(location.is_file() and location.stat().st_size <= 32_000_000, 'snapshot absent or too large')
    result = location.read_bytes()
    check(len(result) <= 32_000_000, 'snapshot grew beyond size limit')
    return result


def resolve(manifests, builtins, external_dependencies, incoming_root, lane, bindings, now=None):
    inactive = {'active': False, 'external_versions': {}, 'edges': [], 'unavailable_optional': [], 'warnings': []}
    check(isinstance(external_dependencies, dict), 'external dependencies must be an object')
    if not external_dependencies: return inactive
    check(set(external_dependencies) == {'official_omega'}, 'unsupported external provider')
    data = external_dependencies['official_omega']
    check(isinstance(data, dict) and set(data) == FIELDS, 'malformed snapshot specification')
    check(type(data['schema']) is int and data['schema'] == 1 and data['source_url'] == ORIGIN and data['core_commit'] == REVISION, 'unsupported snapshot source/schema/core')
    check(isinstance(data['snapshot_sha256'], str) and re.fullmatch('[0-9a-f]{64}', data['snapshot_sha256']), 'invalid snapshot hash')
    retrieved, expires = timestamp(data['retrieved_at']), timestamp(data['expires_at'])
    check(retrieved <= (now or datetime.now(timezone.utc)) < expires and 0 < (expires - retrieved).total_seconds() <= 604800, 'snapshot expired, future-dated or validity exceeds seven days')
    listed = data['allowlist']
    check(isinstance(listed, dict) and 0 < len(listed) <= 128, 'invalid official allowlist')
    for aid, ver in listed.items():
        check(isinstance(aid, str) and re.fullmatch(IDENTIFIER, aid) and aid not in PROVIDED, 'invalid official allowlist')
        parse_version(ver)
    check(isinstance(data['roots'], dict) and data['roots'] and
          set(data['roots']) <= {'skin.aura', TVGUIDE}, 'only Aura and exact TV Guide are enrolled')
    if 'skin.aura' in data['roots']:
        bind = data['roots']['skin.aura']
        check(isinstance(bind, dict) and set(bind) == {'version', 'package_sha256', 'source_commit'} and
              (bind['version'] == '2.1.0' or bind == {
                  'version':'2.1.1',
                  'package_sha256':'a5dc17aadfc5f14ed4807a2c16d55e23e3dd5fb5320fb9eb93885d3a0cbddb92',
                  'source_commit':'bf4f74a2a0d4b80670213f0b6fdb8728b33dd5ab'}) and
              isinstance(bind['package_sha256'], str) and re.fullmatch('[0-9a-f]{64}', bind['package_sha256']) and
              isinstance(bind['source_commit'], str) and re.fullmatch('[0-9a-f]{40}', bind['source_commit']), 'invalid Aura artifact binding')
    if TVGUIDE in data['roots']:
        check(data['roots'][TVGUIDE] in (TV_ENROLLED, TVGUIDE_012), 'only exact frozen TV Guide beta is enrolled')
    raw = file_bytes(incoming_root, data['snapshot'])
    check(hashlib.sha256(raw).hexdigest() == data['snapshot_sha256'], 'snapshot checksum mismatch')
    check(b'\0' not in raw, 'only UTF-8 snapshot XML is accepted')
    raw.decode('utf-8-sig')
    check(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'snapshot entities forbidden')
    try:
        index = XML.fromstring(raw)
    except XML.ParseError as exc:
        raise ValueError('Audit official Omega: invalid snapshot XML') from exc
    check(index.tag == 'addons' and len(index) <= 10000 and all(n.tag == 'addon' for n in index), 'invalid official index')
    catalog = {}
    for node in index:
        check(node.get('id') and node.get('version'), 'index identity/version missing')
        catalog.setdefault(node.get('id'), []).append(node)
    selected = {n.get('id'): n for n in manifests}
    check(len(manifests) == len(selected) and not set(selected).intersection(listed), 'ambiguous or substituted selected package')
    if lane != 'omega':
        check('skin.aura' not in selected, 'Aura official adapter is Omega-only')
        check(TVGUIDE not in selected, 'TV Guide adapter is Omega 21.3-only')
        return inactive
    check(TVGUIDE not in selected or TVGUIDE in data['roots'], 'TV Guide requires its own exact Omega enrollment')
    roots = sorted(set(selected).intersection(data['roots']))
    if not roots: return inactive
    for root_id in roots:
        node, actual = selected[root_id], bindings.get(root_id, {})
        if root_id == 'skin.aura':
            bind = data['roots'][root_id]
            check(node.get('version') == data['roots']['skin.aura']['version'] and node.find("extension[@point='xbmc.gui.skin']") is not None, 'enrolled root is not the exact enrolled Aura skin')
            check(actual.get('package_sha256') == bind['package_sha256'] and actual.get('source_commit') == bind['source_commit'] and actual.get('source_repository') == 'https://github.com/kcook98765/skin.aura', 'Aura artifact/source binding mismatch')
        else:
            release = data['roots'][TVGUIDE]
            expected = (('script.module.beautifulsoup4', '4.12.2', False), ('script.module.dateutil', '2.8.2', False),
                        ('script.module.pil', '5.1.0', False), ('script.module.pytz', '2023.3.0+matrix.1', False),
                        ('script.module.requests', '2.31.0', False), ('xbmc.python', '3.0.0', False))
            extensions = sorted((e.get('point'), e.get('library')) for e in node.findall('extension') if e.get('point') != 'xbmc.addon.metadata')
            check(node.get('version') == release['version'] and imports(node) == expected and
                  extensions == [('xbmc.python.script', 'addon.py'), ('xbmc.service', 'service.py')], 'enrolled root manifest mismatch')
            check(set(actual) == {'source_commit', 'package_sha256', 'source_repository'} and
                  actual['source_commit'] == release['source_commit'] and actual['package_sha256'] == release['package_sha256'] and
                  actual['source_repository'] == 'https://github.com/kcook98765/script.tvguide.fullscreen', 'TV Guide artifact/source binding mismatch')
    for aid in set(builtins).intersection(PROVIDED): check(builtins[aid] == PROVIDED[aid][0], 'configured built-in differs from pinned Omega core')
    for aid, node in selected.items():
        if aid not in roots:
            check(not any(a in listed or a in PROVIDED and a not in builtins for a, _, optional in imports(node) if not optional),
                  'unrelated package attempts Aura-only or TV Guide external admission')
    ext, core, edges, missing, finished = {}, {}, [], [], set()

    def walk(parent, aid, floor, optional, branch, ancestry):
        branch = branch or optional
        edge = dict(parent=parent, addon=aid, minimum=floor, optional=optional, optional_branch=branch)
        if aid in PROVIDED:
            ver, abi = PROVIDED[aid]
            check(compare_versions(floor, ver) <= 0 and (abi is None or compare_versions(floor, abi) >= 0), 'core version/ABI unavailable: ' + aid)
            core[aid] = ver
            edge['provider'], edge['version'] = 'Kodi 21.3 core', ver
            descendants = () if aid == 'xbmc.core' else (('xbmc.python', '3.0.0', False),) if aid == 'script.module.pil' else (('xbmc.core', '0.1.0', False),)
        else:
            providers = catalog.get(aid, [])
            if not providers and optional:
                missing.append(edge)
                return
            check(providers, 'required official dependency absent: ' + aid)
            versions = sorted({n.get('version') for n in providers}, key=cmp_to_key(compare_versions))
            newest = versions[-1]
            check(sum(compare_versions(v, newest) == 0 for v in versions) == 1, 'ambiguous equivalent official version: ' + aid)
            copies = [n for n in providers if n.get('version') == newest]
            check(listed.get(aid) == newest, 'official dependency outside exact newest-version allowlist: ' + aid)
            check(compare_versions(floor, newest) <= 0, 'official dependency version too old: ' + aid)
            check(not any((b.text or '').strip() for n in copies for b in n.findall('./extension/broken')), 'official dependency marked broken: ' + aid)
            choices = {imports(n) for n in copies}
            check(len(choices) == 1, 'ambiguous platform dependency declarations: ' + aid)
            descendants = next(iter(choices))
            ext[aid] = newest
            edge['provider'], edge['version'] = 'official Omega repository', newest
        edges.append(edge)
        check(aid not in ancestry, 'dependency cycle: ' + aid)
        if (aid, branch) not in finished:
            for child, ver, opt in descendants: walk(aid, child, ver, opt, branch, ancestry + (aid,))
            finished.add((aid, branch))

    closures, combined_ext, combined_core, combined_edges, combined_missing = {}, {}, {}, [], []
    for root_id in roots:
        ext, core, edges, missing, finished = {}, {}, [], [], set()
        for aid, floor, optional in imports(selected[root_id]): walk(root_id, aid, floor, optional, False, ())
        closures[root_id] = {'external_versions': dict(sorted(ext.items())), 'core_versions': dict(sorted(core.items())),
                             'edges': sorted(edges, key=lambda e: (e['parent'], e['addon'], e['optional_branch'], e['minimum'])),
                             'unavailable_optional': sorted(missing, key=lambda e: (e['parent'], e['addon']))}
        combined_ext.update(ext); combined_core.update(core)
        combined_edges += edges; combined_missing += missing
    ext, core, edges, missing = combined_ext, combined_core, combined_edges, combined_missing
    check(set(ext) == set(listed), 'unused or incomplete exact official allowlist')
    report = {'active': True, 'source_url': ORIGIN, 'snapshot_sha256': data['snapshot_sha256'],
            'retrieved_at': data['retrieved_at'], 'expires_at': data['expires_at'], 'core_commit': REVISION,
            'version_comparison_source': 'https://github.com/xbmc/xbmc/blob/' + REVISION + '/xbmc/addons/AddonVersion.cpp',
            'roots': data['roots'], 'external_versions': dict(sorted(ext.items())), 'core_versions': dict(sorted(core.items())),
            'edges': sorted(edges, key=lambda x: (x['parent'], x['addon'], x['optional_branch'], x['minimum'])),
            'unavailable_optional': sorted(missing, key=lambda x: (x['parent'], x['addon'])),
            'warnings': ['Official snapshot dependency evidence only; no dependency installation or native acceptance is asserted.']}
    if TVGUIDE in data['roots']: report['root_closures'] = closures
    return report

version_key = cmp_to_key(compare_versions)


def version_ge(provided, required):
    return compare_versions(provided, required) >= 0
