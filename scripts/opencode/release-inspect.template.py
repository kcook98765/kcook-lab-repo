"""Read-only inspection of a frozen release packet; never execute project code."""
import argparse
import hashlib
import io
import json
import subprocess
from pathlib import Path, PurePosixPath
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]

SOURCE_ROOTS = {'.gitignore', 'AGENTS.md', 'README.md', 'LICENSE', 'CONTRIBUTING.md',
                'config', 'docs', 'fixtures', 'incoming', 'packages', 'plans',
                'releases', 'scripts', 'tests'}
INTEGRATION_SOURCES = {
    'integrations/opencode/global.template.json',
    'integrations/opencode/source.template.json',
    'integrations/opencode/distribution.template.json',
    'integrations/opencode/source-instructions.template.md',
    'integrations/opencode/local-templates/GITHUB-OPERATOR.md',
    'integrations/opencode/local-templates/skills/kodi-repository-maintenance/SKILL.md',
    'integrations/opencode/local-templates/skills/kodi-repository-maintenance/references/intake-and-release.md',
}


def tracked_integrations():
    # Fixed read-only Git selection; disable the optional fsmonitor hook.
    raw = subprocess.check_output(
        ['/usr/bin/git', '-c', 'core.fsmonitor=false', 'ls-files', '--cached', '-z',
         '--', *sorted(INTEGRATION_SOURCES)], cwd=ROOT)
    return set(raw.decode().split('\0')) - {''}


def source_allowed(name, tracked):
    parts = PurePosixPath(name).parts
    return bool(parts) and (parts[0] in SOURCE_ROOTS or
                            (name in INTEGRATION_SOURCES and name in tracked))


def require(value, message):
    if not value:
        raise ValueError(message)


def path(base, name):
    require(base.resolve().is_relative_to(ROOT), 'Inspection root escapes project')
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name,
            'Non-relative inspection path')
    candidate = base.joinpath(*relative.parts)
    require(candidate.resolve().is_relative_to(base.resolve()), 'Inspection path escapes its root')
    for parent in [candidate, *candidate.parents]:
        if parent == base:
            break
        require(not parent.is_symlink(), 'Symlink in inspection path')
    return candidate


def blob(file, maximum=20_000_000):
    require(file.resolve().is_relative_to(ROOT) and not file.is_symlink(), 'Inspection file escapes project')
    require(file.is_file() and file.stat().st_size <= maximum, 'Missing or oversized inspection file')
    return file.read_bytes()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def document(file):
    return json.loads(blob(file, 3_000_000))


def inventory(base):
    result = {}
    for file in sorted(base.rglob('*')):
        require(not file.is_symlink(), 'Symlink in frozen inventory')
        if file.is_file():
            result[file.relative_to(base).as_posix()] = sha(blob(file))
    return result


parser = argparse.ArgumentParser()
parser.add_argument('--role', required=True, choices=['kodi-release-reviewer'])
parser.add_argument('--packet', default='reports/rebranding-resume/final')
parser.add_argument('--view', default='summary', choices=[
    'summary', 'profile', 'adapter', 'inspector', 'archive-entry', 'review-record'])
parser.add_argument('--package-id')
parser.add_argument('--package-version')
parser.add_argument('--entry')
parser.add_argument('--offset', type=int, default=1)
parser.add_argument('--limit', type=int, default=120)
args = parser.parse_args()
require(1 <= args.offset and 1 <= args.limit <= 200, 'Invalid text page')
require(PurePosixPath(args.packet).parts[0:1] == ('reports',), 'Packet must be under project reports')
packet = path(ROOT, args.packet)
require(packet.is_dir(), 'Frozen packet not found')
summary = document(path(packet, 'review-summary.json'))
source = document(path(packet, 'source-audit.json'))['files']
require(sha(canonical(source)) == summary['source_manifest_sha256'], 'Source manifest identity mismatch')
tracked = tracked_integrations()
for name, expected in source.items():
    parts = PurePosixPath(name).parts
    require(source_allowed(name, tracked), 'Unapproved source root')
    require(not any(p.startswith('.') and p != '.gitignore' for p in parts), 'Private source path')
    require(parts[0] != 'incoming' or name == 'incoming/README.md', 'Private intake in source manifest')
    require(not any(p in {'auth.json', 'web.env', 'opencode.json', 'opencode.jsonc'} or
                    p.startswith('credentials') for p in parts), 'Credential/configuration source path')
    require(sha(blob(path(packet / 'frozen-source', name))) == expected, 'Frozen source mismatch: ' + name)
    require(sha(blob(path(ROOT, name))) == expected, 'Current source differs from reviewed source: ' + name)

production = packet / 'frozen-production'
plan_bytes = blob(path(production, 'release-plan.json'))
require(sha(plan_bytes) == summary['release_plan_sha256'], 'Release plan identity mismatch')
plan = json.loads(plan_bytes)
require(plan['profile'] == 'production', 'Not a production packet')
sites = document(path(packet, 'site-manifest.json'))
require(sha(canonical(sites)) == summary['site_manifest_sha256'], 'Site manifest identity mismatch')
require(sites == plan['site_files'] == inventory(production / 'site'), 'Frozen site inventory mismatch')
require(sites == inventory(ROOT / 'dist/production/site'), 'Current site differs from frozen site')
for name in sites:
    if name.endswith('.sha256'):
        require(blob(path(production / 'site', name)).decode().strip() == sites[name[:-7]],
                'Invalid SHA-256 sidecar: ' + name)

intake = document(path(packet / 'frozen-source', 'config/production.json'))
config = document(path(packet / 'frozen-source', 'config/repository.json'))
ledger = document(path(packet / 'frozen-source', 'releases/manifest.json'))
records = {}
for item in intake['packages']:
    require(PurePosixPath(item['zip']).name == item['zip'], 'Non-basename intake ZIP')
    require(PurePosixPath(item['review_record']).name == item['review_record'], 'Non-basename review record')
    raw = blob(path(ROOT / 'incoming', item['review_record']))
    require(sha(raw) == item['review_record_sha256'], 'Original review record hash mismatch')
    record = json.loads(raw)
    require(record['package_sha256'] == item['sha256'], 'Review/package binding mismatch')
    require(sha(blob(path(ROOT / 'incoming', item['zip']))) == item['sha256'], 'Original intake ZIP mismatch')
    records[item['sha256']] = (record, raw, item)

archives = []
selected_files = None
selected_record = None
for package in plan['packages']:
    data = blob(path(production / 'site', package['path']))
    require(sha(data) == package['sha256'], 'Archive hash mismatch')
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        require(len(infos) <= 5000 and sum(i.file_size for i in infos) <= 20_000_000,
                'Oversized archive inventory')
        for info in infos:
            name = PurePosixPath(info.filename)
            require(not name.is_absolute() and '..' not in name.parts and '\\' not in info.filename,
                    'Unsafe archive path')
            require(name.parts and name.parts[0] == package['id'], 'Wrong archive root')
            require(not info.flag_bits & 1 and (info.external_attr >> 16) & 0o170000 != 0o120000,
                    'Encrypted/symlink archive entry')
            if info.is_dir():
                continue
            relative = '/'.join(name.parts[1:])
            require(relative and relative not in files, 'Duplicate/empty archive entry')
            files[relative] = archive.read(info)
        require(archive.testzip() is None, 'Archive CRC failure')
    manifest = ET.fromstring(files['addon.xml'])
    require((manifest.get('id'), manifest.get('version')) == (package['id'], package['version']),
            'Archive manifest identity mismatch')
    hashes = {name: sha(value) for name, value in files.items()}
    record_info = records.get(package['sha256'])
    if record_info:
        require(hashes == record_info[0]['runtime_files'], 'Original review/runtime file mismatch')
        require(record_info[2]['lanes'] == package['lanes'], 'Original intake lane mismatch')
        require(package['provenance'] == record_info[0], 'Original review differs from frozen provenance')
    archives.append({'id': package['id'], 'version': package['version'], 'sha256': sha(data),
                     'bytes': len(data), 'lanes': package['lanes'], 'runtime_files': hashes,
                     'manifest_xml': files['addon.xml'].decode('utf-8'),
                     'original_review_bytes_verified': bool(record_info)})
    if package['id'] == args.package_id and (args.package_version is None or package['version'] == args.package_version):
        require(selected_files is None, 'Select an unambiguous package ID')
        selected_files = files
        selected_record = record_info

for old in ledger['packages']:
    require(any((p['id'], p['version'], p['sha256']) == (old['id'], old['version'], old['sha256'])
                for p in plan['packages']), 'Historical artifact missing or changed')

profile_file = ROOT / '.opencode/agents/kodi-release-reviewer.md'
adapter_file = ROOT / '.opencode/tools/kodi.ts'
if args.view == 'summary':
    result = {'status': 'PASS', 'scope': 'Independent read-only byte/profile inspection, not release approval',
              'packet': args.packet, 'source_manifest_sha256': summary['source_manifest_sha256'],
              'release_plan_sha256': sha(plan_bytes), 'site_manifest_sha256': summary['site_manifest_sha256'],
              'source_file_count': len(source), 'site_file_count': len(sites), 'archives': archives,
              'original_review_records': [{'filename': item['review_record'], 'sha256': sha(raw),
                                           'package_sha256': record['package_sha256']}
                                          for record, raw, item in records.values()],
              'profile_sha256': sha(blob(profile_file)), 'adapter_sha256': sha(blob(adapter_file)),
              'inspector_sha256': sha(blob(Path(__file__))), 'repository_id': config['addon_id'],
              'limitations': ['External historical evidence is not reopened by this tool.',
                              'No native Kodi test, network check or publication is performed.',
                              'Current native permissions remain enforced by OpenCode.']}
else:
    if args.view == 'profile':
        raw = blob(profile_file)
    elif args.view == 'adapter':
        raw = blob(adapter_file)
    elif args.view == 'inspector':
        raw = blob(Path(__file__))
    elif args.view == 'review-record':
        require(selected_record is not None, 'Select a package with an original review record')
        raw = selected_record[1]
    else:
        require(selected_files is not None and args.entry in selected_files, 'Select a known archive entry')
        raw = selected_files[args.entry]
    lines = raw.decode('utf-8').splitlines()
    result = {'status': 'PASS', 'view': args.view, 'bytes_sha256': sha(raw), 'total_lines': len(lines),
              'offset': args.offset, 'lines': lines[args.offset - 1:args.offset - 1 + args.limit],
              'more_lines': args.offset - 1 + args.limit < len(lines)}
print(json.dumps(result, indent=2, sort_keys=True))
