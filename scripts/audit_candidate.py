#!/usr/bin/env python3
"""Independent stdlib audit against reviewed intake, source and retention inputs.

Never imports the builder, executes add-ons or treats generated plan inventories
as approval. Candidate results describe structural qualification only.
"""
import argparse
import approval_contract
import copy
from datetime import datetime, timezone
import hashlib
from html import escape
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
ID = re.compile(r'[a-z0-9]+(?:[._-][a-z0-9]+)+\Z')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\Z')
DENIED = {'.git', '.opencode', '.agents', 'test', 'tests', 'docs', 'tools', 'reports',
          'node_modules', 'venv', '.venv', '__pycache__', 'profile', 'profiles'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()


def structure(element):
    return (element.tag, sorted(element.attrib.items()), (element.text or '').strip(),
            [structure(c) for c in element])


def path(base, name):
    p = PurePosixPath(name)
    assert p.parts and not p.is_absolute() and p.as_posix() == name
    assert not any(c in name for c in ('\\', ':', '\0')) and '..' not in p.parts
    for part in p.parts:
        assert not part.endswith((' ', '.')) and not any(ord(c) < 32 or c in '<>"|?*' for c in part)
        assert part.split('.')[0].upper() not in {'CON', 'PRN', 'AUX', 'NUL',
            *('COM'+str(i) for i in range(1, 10)), *('LPT'+str(i) for i in range(1, 10))}
    result = base.joinpath(*p.parts)
    assert result.resolve().is_relative_to(base.resolve())
    assert not any(item.is_symlink() for item in [result, *result.parents])
    return result


def xml(data):
    assert len(data) <= 2_000_000
    text = data.decode('utf-8-sig')
    assert '\0' not in text and '<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper()
    return ET.fromstring(data)


def numeric(value):
    assert isinstance(value, str) and VERSION.fullmatch(value)
    return tuple(map(int, value.split('.')))


def dependency_version(value):
    """Independent bounded Kodi grammar; numeric x.y.z package rules stay intact.

    Source: Kodi a3a448d26b8d560a65655dab2cd122994dc4e146,
    xbmc/addons/AddonVersion.cpp. Invalid/fallback and overflowing inputs are
    unsupported, not normalized into apparently valid dependency floors.
    """
    assert isinstance(value, str) and 0 < len(value) <= 128
    assert re.fullmatch(r'(?:[0-9]+:)?[0-9][a-zA-Z0-9]*(?:[.+_@~][a-zA-Z0-9]+)*'
                        r'(?:-[a-zA-Z0-9]+(?:[.+_@~][a-zA-Z0-9]+)*)?', value)
    assert all(len(n) <= 10 and int(n) <= 2147483647 for n in re.findall('[0-9]+', value))
    pieces = value.lower().split(':')
    epoch, body = (int(pieces[0]), pieces[1]) if len(pieces) == 2 else (0, pieces[0])
    upstream, _, revision = body.partition('-')
    return epoch, re.findall('[0-9]+|[^0-9]', upstream), re.findall('[0-9]+|[^0-9]', revision)


def dependency_ge(provided, minimum):
    a, b = dependency_version(provided), dependency_version(minimum)
    if a[0] != b[0]: return a[0] > b[0]
    for left, right in zip(a[1:], b[1:]):
        offset = 0
        while offset < min(len(left), len(right)):
            x, y = left[offset], right[offset]
            xd, yd = x[0].isdigit(), y[0].isdigit()
            if xd and yd:
                if int(x) != int(y): return int(x) > int(y)
            elif x != y:
                if x == '~': return False
                if y == '~': return True
                return not xd if xd != yd else x > y
            offset += 1
        if len(left) != len(right):
            return left[offset] != '~' if offset < len(left) else right[offset] == '~'
    return True


def configuration(profile):
    """Independent candidate identity/retention selection; never imports builder."""
    production_file = path(ROOT, 'config/repository.json')
    production = json.loads(production_file.read_text())
    assert production['addon_id'] == 'repository.ai.kodi' and 'candidate_context' not in production
    candidate_file = ROOT/'config/candidate-repository.json'
    if profile != 'candidate' or not candidate_file.exists():
        return production, production_file, path(ROOT, 'releases/manifest.json')
    candidate_file = path(ROOT, 'config/candidate-repository.json')
    config = json.loads(candidate_file.read_text()); context = config['candidate_context']
    assert set(context) == {'task_id', 'production_config_sha256', 'production_ledger_sha256'}
    assert re.fullmatch('[0-9a-f]{32}', context['task_id'])
    assert config['addon_id'] == 'repository.ai.kodi.candidate.'+context['task_id']
    assert context['production_config_sha256'] == digest(production_file.read_bytes())
    assert context['production_ledger_sha256'] == digest(path(ROOT, 'releases/manifest.json').read_bytes())
    assert config['lanes'] == production['lanes'] and config['publication_authorized'] is False
    url = urlsplit(config['base_url'])
    assert url.scheme == 'https' and url.hostname and not url.username and not url.password
    assert not url.query and not url.fragment and url.path.endswith('/') and '%' not in config['base_url']
    production_url = urlsplit(production['base_url'])
    assert '..' not in url.path.split('/')
    assert (url.hostname.lower().rstrip('.'),url.port or 443) != (production_url.hostname.lower().rstrip('.'),production_url.port or 443)
    ledger = path(ROOT, 'releases/candidate-manifest.json')
    assert json.loads(ledger.read_text()).get('repository_id') == config['addon_id']
    return config, candidate_file, ledger


def archive_files(blob):
    assert len(blob) <= 64_000_000
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        infos = z.infolist(); names = z.namelist()
        assert 0 < len(names) <= 10000 and names == sorted(names)
        folded = {n.casefold() for n in names}
        assert len(names) == len(folded) and sum(i.file_size for i in infos) <= 256_000_000
        roots = set(); files = {}
        for info in infos:
            p = PurePosixPath(info.filename); path(ROOT, info.filename)
            assert len(p.parts) >= 2
            assert not any(parent.as_posix().casefold() in folded for parent in p.parents)
            assert not info.is_dir() and not info.flag_bits & 1
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            mode = info.external_attr >> 16
            assert stat.S_ISREG(mode) and mode & 0o777 == 0o644
            roots.add(p.parts[0]); name = '/'.join(p.parts[1:])
            assert not any(x.lower() in DENIED or x.startswith('.') for x in p.parts[1:])
            assert not name.lower().endswith(('.pyc', '.pyo', '.log', '.toml', '.lock'))
            assert p.name.lower() not in {'agents.md', 'development.md', 'contributing.md',
                'opencode.json', 'requirements.txt', 'pyproject.toml', 'credentials.json', 'auth.json'}
            files[name] = z.read(info)
        assert z.testzip() is None
    manifest = xml(files['addon.xml'])
    assert manifest.tag == 'addon' and ID.fullmatch(manifest.get('id', ''))
    numeric(manifest.get('version'))
    assert roots == {manifest.get('id')} and manifest.get('name') and manifest.get('provider-name')
    metas = manifest.findall("extension[@point='xbmc.addon.metadata']")
    assert len(metas) == 1
    assert any(e.get('point') and e.get('point') != 'xbmc.addon.metadata' for e in manifest.findall('extension'))
    for tag in ['summary', 'description', 'platform', 'license']: assert metas[0].findtext(tag)
    assert any(PurePosixPath(n).name.lower().startswith(('license', 'copying')) for n in files)
    for extension in manifest.findall('extension'):
        if extension.get('library'): assert extension.get('library') in files
    for asset in metas[0].findall('assets/*'): assert asset.text in files
    groups = manifest.findall('requires')
    assert len(groups) <= 1 and all(d.tag == 'import' for group in groups for d in group)
    seen = set()
    for dep in manifest.findall('requires/import'):
        name = dep.get('addon', '')
        assert ID.fullmatch(name) and name not in seen
        seen.add(name); dependency_version(dep.get('version'))
        assert dep.get('optional', 'false') in ('true', 'false')
    return manifest, files


def initial_runtime_gate(record, lanes, manifest, history):
    """Independent production predicates, even if shared assessment is permissive."""
    value = record['runtime_acceptance_exception']
    assert set(value) == {'scope', 'addon_id', 'addon_version', 'package_sha256', 'source_commit',
                          'lanes', 'expires_at', 'scenarios', 'owner_decision', 'independent_verification'}
    identity = (manifest.get('id'), manifest.get('version'))
    assert value['scope'] == 'initial_release_runtime_coverage_only'
    assert (value['addon_id'], value['addon_version'], value['package_sha256'], value['source_commit']) == (
        *identity, record['package_sha256'], record['source_commit'])
    assert lanes and len(value['lanes']) == len(set(value['lanes'])) and set(value['lanes']) == set(lanes)
    prior = [old for old in history if old['id'] == identity[0]]
    assert not prior or (prior[0]['version'], prior[0]['sha256']) == (identity[1], record['package_sha256'])
    scenarios = value['scenarios']; assert isinstance(scenarios, list) and scenarios
    ids = []; runtime_ids = set()
    for s in scenarios:
        assert set(s) == {'id', 'lane', 'risk_id', 'kind', 'observation', 'description', 'supporting_evidence'}
        assert all(isinstance(s[k], str) and s[k].strip() for k in ('id', 'risk_id', 'description'))
        assert s['lane'] in lanes
        assert (s['kind'], s['observation']) in (('unobserved_functionality', 'not_observed'),
                                               ('environment_limitation', 'unavailable'))
        assert isinstance(s['supporting_evidence'], list) and s['supporting_evidence']
        for e in s['supporting_evidence']:
            assert set(e) == {'method', 'status', 'scope', 'evidence'}
            assert e['method'] in ('offline', 'native', 'environment')
            assert e['status'] in ('passed', 'not_observed', 'unavailable')
            assert isinstance(e['scope'], str) and e['scope'].strip()
            assert audit_pinned_evidence(e['evidence'])
        if s['kind'] == 'environment_limitation':
            assert any(e['method'] == 'environment' and e['status'] == 'unavailable' for e in s['supporting_evidence'])
        ids.append(s['id']); runtime_ids.add(s['risk_id'])
    assert len(ids) == len(set(ids))
    assert runtime_ids and runtime_ids == {r['id'] for r in record['unresolved_risks'] if r['category'] == 'runtime'}
    for lane in lanes:
        item = record['compatibility'][lane]; test = item['runtime_test']
        assert item['static_accepted'] is True and item['evidence'] and audit_pinned_evidence(test['evidence'])
        expected = [s['id'] for s in scenarios if s['lane'] == lane]
        assert all(test[k].strip() for k in ('actor', 'role', 'platform', 'kodi_version', 'scope', 'recorded_at', 'rationale'))
        assert isinstance(test['outstanding_tests'], list)
        if expected:
            assert item['runtime_accepted'] is False and test['status'] == 'deferred'
            assert len(test['outstanding_tests']) == len(set(test['outstanding_tests']))
            assert set(test['outstanding_tests']) == set(expected)
        else:
            assert item['runtime_accepted'] is True and test['status'] == 'passed' and test['outstanding_tests'] == []
    owner = value['owner_decision']; review = value['independent_verification']; ack = record['owner_acknowledgment']
    assert owner['status'] == 'accepted' and owner['role'] == 'owner' and review['status'] == 'verified'
    assert review['no_known_security_defects'] is True
    assert ack['status'] == 'acknowledged' and ack['role'] == 'owner'
    assert owner['actor'].strip().casefold() == ack['actor'].strip().casefold()
    assert owner['actor'].strip().casefold() == record['unofficial_integration']['owner_distribution_decision']['actor'].strip().casefold()
    assert review['actor'].strip().casefold() != owner['actor'].strip().casefold()
    core = review['core_evidence']; assert isinstance(core, list) and core
    for e in core:
        assert set(e) == {'method', 'status', 'scope', 'evidence'}
        assert e['method'] in ('native', 'offline') and e['status'] == 'passed'
        assert isinstance(e['scope'], str) and e['scope'].strip() and audit_pinned_evidence(e['evidence'])
    assert {e['method'] for e in core} == {'native', 'offline'}
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value['expires_at'])
    expiry = datetime.strptime(value['expires_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    for action, extras in ((owner, {'scenario_ids', 'risk_ids'}),
                           (review, {'scenario_ids', 'risk_ids', 'no_known_security_defects', 'core_evidence'})):
        assert set(action) == {'status', 'actor', 'role', 'recorded_at', 'rationale', 'evidence'} | extras
        assert all(isinstance(action[k], str) and action[k].strip() for k in ('actor', 'role', 'rationale'))
        assert audit_pinned_evidence(action['evidence'])
        for field, expected in (('scenario_ids', set(ids)), ('risk_ids', runtime_ids)):
            assert len(action[field]) == len(set(action[field])) and set(action[field]) == expected
        assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', action['recorded_at'])
        assert datetime.strptime(action['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc) < expiry
    final = record['release_decision']
    assert final['role'] == 'owner' and final['actor'].strip().casefold() == owner['actor'].strip().casefold()
    assert final['runtime_exception_sha256'] == digest(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8'))
    assert audit_pinned_evidence(final['evidence'])
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', final['recorded_at'])
    assert all(a['recorded_at'] <= final['recorded_at'] for a in (owner, review))
    assert datetime.strptime(final['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)


def audit_pinned_evidence(value):
    if not isinstance(value, list) or not value:
        return False
    for ref in value:
        match = re.fullmatch(r'(.+) sha256:([0-9a-f]{64})', ref) if isinstance(ref, str) else None
        if not match:
            return False
        name = match[1]
        if (not PurePosixPath(name).parts or PurePosixPath(name).is_absolute() or PurePosixPath(name).as_posix() != name or
                '..' in PurePosixPath(name).parts or any(c in name for c in ('\\', ':')) or
                any(ord(c) < 32 for c in name)):
            return False
    return True


def verify_skin_evidence_files(record):
    if record.get('schema_version') not in (4, 5):
        return
    pending = [record]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ('evidence', 'static_package_evidence'):
                    assert audit_pinned_evidence(child), 'Skin-alpha evidence must be pinned'
                    for ref in child:
                        name, expected = ref.rsplit(' sha256:', 1)
                        assert digest(path(ROOT/'incoming', name).read_bytes()) == expected, 'Skin-alpha evidence bytes changed'
                else:
                    pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)


def original_assets_gate(record, config):
    """Independent exact-package rule; never delegates material rights to assess()."""
    base = Path(__file__).resolve().parents[1]
    policy_name = 'policies/aura-original-assets-2.1.0.json'
    approval_name = 'policies/aura-original-assets-owner-approval.json'
    policy_hash = 'fa0a5e73758fff3cc3d092683a34a82f103a2f66465b6f59afa58da8a27ac40f'
    approval_hash = '326791dc0bf7884f3561d028cc9e394569c47b9d9df99e297358aca2981f613e'
    assert digest((base/policy_name).read_bytes()) == policy_hash
    assert digest((base/approval_name).read_bytes()) == approval_hash
    policy = json.loads((base/policy_name).read_text()); receipt = json.loads((base/approval_name).read_text())
    assert record['schema_version'] == 5 and record['approval_policy'] == 'aura-original-assets-alpha-v1'
    assert record['source_commit'] == '88564fd2883d2d286bdf0e887dc0bee634fd8c4e'
    assert record['package_sha256'] == '7309fc3f60429e4ba638d36046565ae48fa2b75f56f653df5200a960aa3ce9c0'
    assert record['source_repository'] == 'https://github.com/kcook98765/skin.aura'
    assert record['fixture_only'] is False and len(record['runtime_files']) == 1806
    assert record['rights_approved'] is False and record['rights_review'] == {'status':'pending'}
    assert [r for r in record['unresolved_risks'] if r['category']=='rights'] == policy['proposed_policy_change']['rights_risks_must_remain_unresolved']
    actual = json.loads((ROOT/'config/repository.json').read_text()) if 'candidate_context' in config else config
    assert (actual['github_repository'],actual.get('github_repository_id'),actual['base_url'],actual['addon_id']) == (
        'kcook98765/kcook-lab-repo',1428864210,'https://kcook98765.github.io/kcook-lab-repo/','repository.ai.kodi')
    value = record['original_assets_admission']
    assert set(value) == {'scope','addon_id','addon_version','source_commit','package_sha256','lanes',
                         'destination','expires_at','policy_request_sha256','owner_policy_decision','independent_review','technical_findings'}
    assert value['scope'] == 'exact_original_assets_aura_alpha_admission_only'
    assert (value['addon_id'],value['addon_version']) == ('skin.aura','2.1.0')
    assert (value['source_commit'],value['package_sha256']) == (record['source_commit'],record['package_sha256'])
    assert value['destination'] == policy['proposed_policy_change']['destination']
    assert value['expires_at'] == '2026-12-15T02:11:01Z' and value['policy_request_sha256'] == policy_hash
    assert value['lanes'] == ['omega'] and record['approval_lanes'] in (['omega'], [])
    assert record['skin_alpha_evidence']['expires_at'] <= value['expires_at']
    owner = value['owner_policy_decision']; review = value['independent_review']
    assert owner['status'] == 'approved' and owner['actor'] == 'kcook98765' and owner['role'] == 'owner'
    assert owner['recorded_at'] == receipt['recorded_at'] and owner['policy_request_sha256'] == policy_hash
    assert {policy_name+' sha256:'+policy_hash,approval_name+' sha256:'+approval_hash} <= set(owner['evidence'])
    assert receipt['owner_message'] == 'Approve Aura policy decision '+policy_hash
    assert receipt['policy_request_sha256'] == policy_hash and receipt['status'] == 'approved'
    assert receipt['actor'] == owner['actor'] and receipt['role'] == 'owner'
    assert receipt['scope'] == 'implementation_and_independent_qualification_only'
    assert all(receipt[k] is False for k in ('package_admission_authorized','publication_authorized','third_party_permissions_granted'))
    assert record['skin_alpha_evidence']['owner_native_use']['actor'] == owner['actor']
    assert review['status'] in ('pending','verified','rejected','revoked')
    if review['status'] != 'pending':
        assert review['actor'].strip().casefold() != owner['actor'].casefold() and review['role'] == 'independent_reviewer'
        assert review['scope'] == 'retained_material_findings_and_policy_implementation_only' and review['recorded_at'] >= owner['recorded_at']
        assert len(review['risk_ids']) == 5 and set(review['risk_ids']) == {r['id'] for r in record['unresolved_risks'] if r['category']=='rights'}
        assert review['rights_verified'] is False and review['permissions_granted'] is False
        assert review['implementation_verified'] is True and review['findings_retained'] is True
        assert audit_pinned_evidence(review['evidence'])
    if record['release_approved']:
        assert review['status'] == 'verified'
    technical = value['technical_findings']
    assert set(technical) == {'id','status','official_checker_status','official_checker_errors','official_checker_warnings',
                             'toolkit_overall_passed','original_dimensions','paths','evidence'}
    assert technical['id'] == 'STATIC-SCREENSHOTS' and technical['status'] == 'accepted_unofficial_distribution_limitation'
    assert technical['official_checker_status'] == 'failed' and technical['toolkit_overall_passed'] is False
    assert type(technical['official_checker_errors']) is int and technical['official_checker_errors'] == 5
    assert type(technical['official_checker_warnings']) is int and technical['official_checker_warnings'] == 3
    assert technical['original_dimensions'] == '1366x768'
    assert technical['paths'] == ['resources/screenshot-%02d.jpg' % i for i in range(1,6)]
    assert {'evidence/aura-restored/omega-validation.json sha256:2b13b6d7821e0bb17260b319e38540895722d8f5491ced4f8cd9414ae37b5f88',
            'evidence/aura-restored/INDEPENDENT-DISPOSITION.md sha256:46f0dd424e020790eeb9fe9b20dcf729541b411d37c80cd4e43c1850028e4d3a'} <= set(technical['evidence'])
    now = datetime.now(timezone.utc)
    expiry = datetime.strptime(value['expires_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    assert now < expiry
    for action in (owner,review):
        if action['status'] == 'pending':
            continue
        assert audit_pinned_evidence(action['evidence'])
        stamp = datetime.strptime(action['recorded_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        assert stamp <= now and stamp < expiry
    if record['release_approved']:
        final = record['release_decision']
        assert final['original_assets_admission_sha256'] == digest(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
        assert all(action['recorded_at'] <= final['recorded_at'] for action in (owner,review))
    return [owner,review]


def skin_alpha_gate(record, manifest, history, approval, material_actions=None):
    """Independent production conjunction; no native test is synthesized."""
    assert record['approval_lanes'] in (['omega'], [])
    if not record['approval_lanes']:
        assert any((old['id'],old['version'],old['sha256']) ==
                   (manifest.get('id'),manifest.get('version'),record['package_sha256']) for old in history)
    assert manifest.get('id').startswith('skin.') and len(manifest.findall("extension[@point='xbmc.gui.skin']")) == 1
    assert all(e.get('point') in ('xbmc.gui.skin','xbmc.addon.metadata') for e in manifest.findall('extension'))
    assert manifest.find("requires/import[@addon='xbmc.gui']").get('version') == '5.17.0'
    if material_actions is None:
        assert record['rights_approved'] and record['rights_review']['status'] == 'verified'
    rights_actions = [record['rights_review']] if material_actions is None else material_actions
    assert record['technical_release']['status'] == 'approved'
    value = record['skin_alpha_evidence']; native = value['owner_native_use']
    assert value['lanes'] == ['omega'] and value['scope'] == 'initial_release_skin_alpha_coverage_only'
    assert (value['addon_id'],value['addon_version'],value['package_sha256'],value['source_commit']) == (
        manifest.get('id'),manifest.get('version'),record['package_sha256'],record['source_commit'])
    assert native['status'] == 'owner_reported' and native['role'] == 'owner'
    assert native['addon_id'] == manifest.get('id') and native['formal_scripted_acceptance'] is False
    assert all(isinstance(native[k],str) and native[k].strip() for k in ('reported_version','platform','duration','identity_limitation'))
    assert native['cleaned_package_native_accepted'] is False and native['kodi_major'] == 21
    assert native['result'] == 'stable_regular_use'
    assert native['identity_disposition'] in ('verified','unverified')
    if native['identity_disposition'] == 'unverified':
        assert native['installed_package_sha256'] is None and native['identity_limitation'].strip()
    else:
        assert native['installed_package_sha256'] == record['package_sha256']
    delta = value['reviewed_package_delta']; independent = value['independent_verification']; owner = value['owner_coverage_decision']
    assert delta['status'] == independent['status'] == 'verified' and owner['status'] == 'accepted'
    assert delta['source_provenance_verified'] is True and delta['static_package_evidence']
    for action in (delta, independent):
        assert action['no_known_security_defects'] is True and action['no_known_functionality_failures'] is True
        assert action['actor'].strip().casefold() != owner['actor'].strip().casefold()
    assert all(action['actor'].strip().casefold() != native['actor'].strip().casefold()
               for action in ([record['rights_review'],record['technical_release']] if material_actions is None else [record['technical_release']]))
    assert independent['owner_report_scope_verified'] is True and owner['acknowledges_package_delta'] is True
    assert native['actor'].strip().casefold() == owner['actor'].strip().casefold()
    assert owner['role'] == 'owner'
    assert owner['accepts_unverified_installed_identity'] is (native['identity_disposition']=='unverified')
    scenarios = value['scenarios']; ids = {v['id'] for v in scenarios}
    risk_ids = {r['id'] for r in record['unresolved_risks'] if r['category']=='runtime'}
    assert scenarios and all(r['category'] == 'runtime' or (material_actions is not None and r['category']=='rights') for r in record['unresolved_risks'])
    assert all((v['kind'],v['observation']) in (
        ('unobserved_functionality','not_observed'), ('environment_limitation','unavailable'),
        ('cosmetic_layout_limitation','owner_reported_minor_layout')) for v in scenarios)
    for scenario in scenarios:
        assert scenario['supporting_evidence'] and scenario['lane'] == 'omega'
        for evidence in scenario['supporting_evidence']:
            assert set(evidence) == {'method','status','scope','evidence'}
            assert (evidence['method'],evidence['status']) in (
                ('offline','passed'),('offline','not_observed'),('environment','unavailable'),
                ('owner_reported','not_observed'),('owner_reported','reported_minor_layout'))
            assert isinstance(evidence['scope'],str) and evidence['scope'].strip()
            assert audit_pinned_evidence(evidence['evidence'])
        if scenario['kind'] == 'environment_limitation':
            assert any(e['method']=='environment' and e['status']=='unavailable' for e in scenario['supporting_evidence'])
        if scenario['kind'] == 'cosmetic_layout_limitation':
            assert any(e['method']=='owner_reported' and e['status']=='reported_minor_layout' for e in scenario['supporting_evidence'])
    assert len(ids) == len(scenarios)
    if native['known_limitations']:
        assert any(s['kind']=='cosmetic_layout_limitation' for s in scenarios)
    assert {v['risk_id'] for v in scenarios} == risk_ids
    for action in (owner, independent):
        assert set(action['scenario_ids']) == ids and set(action['risk_ids']) == risk_ids
    ack = record['owner_acknowledgment']
    assert ack['status'] == 'acknowledged' and set(ack['risk_ids']) == {r['id'] for r in record['unresolved_risks']}
    assert ack['actor'].strip().casefold() == owner['actor'].strip().casefold()
    accepted = record['compatibility']['omega']
    assert accepted['static_accepted'] is True and accepted['runtime_accepted'] is False
    assert accepted['runtime_test']['status'] == 'deferred' and set(accepted['runtime_test']['outstanding_tests']) == ids
    prior = [r for r in history if r['id'] == manifest.get('id')]
    assert not prior or (prior[0]['version'],prior[0]['sha256']) == (manifest.get('version'),record['package_sha256'])
    now = datetime.now(timezone.utc)
    expiry = datetime.strptime(value['expires_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    assert now < expiry
    use_time = datetime.strptime(native['recorded_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    assert 0 < (expiry-use_time).total_seconds() <= 90*86400
    for action in [native, delta, owner, independent, ack, accepted['runtime_test'], record['technical_release'],record['release_decision'],*rights_actions]:
        assert datetime.strptime(action['recorded_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) <= now
    final = record['release_decision']
    assert final['role'] == 'owner' and final['actor'].strip().casefold() == owner['actor'].strip().casefold()
    assert all(action['recorded_at'] <= final['recorded_at'] and action['recorded_at'] < value['expires_at']
               for action in [native,delta,owner,independent,ack,accepted['runtime_test'],record['technical_release'],*rights_actions])
    assert owner['recorded_at'] >= native['recorded_at'] and independent['recorded_at'] >= native['recorded_at']
    assert final['skin_alpha_evidence_sha256'] == digest(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
    assert approval['skin_alpha_policy_active'] is True and approval['package_distribution_eligible'] is True
    assert approval['skin_alpha_evidence'] == value and approval['cleaned_package_native_accepted'] is False


def aura_patch_gate(record, manifest, history, config, files, production):
    """Independent finite successor conjunction; never imports aura_patch producer."""
    raw_policy = (ROOT/'policies/aura-cast-fix-2.1.1.json').read_bytes()
    policy_hash = '49c684aaee6651fc8430bfec9498af02869adea201bf1d4a0dc291a914ebae7e'
    assert digest(raw_policy) == policy_hash
    policy = json.loads(raw_policy)
    assert set(record) == {'schema_version','approval_policy','approval_lanes','package_sha256',
        'source_repository','source_commit','fixture_only','runtime_files','rights_approved',
        'rights_review','release_approved','release_decision','technical_release','owner_acknowledgment',
        'unresolved_risks','compatibility','aura_patch_admission','limitations'}
    assert (manifest.get('id'), manifest.get('version')) == ('skin.aura', '2.1.1')
    assert record['source_commit'] == 'bf4f74a2a0d4b80670213f0b6fdb8728b33dd5ab'
    assert record['package_sha256'] == 'a5dc17aadfc5f14ed4807a2c16d55e23e3dd5fb5320fb9eb93885d3a0cbddb92'
    assert record['source_repository'] == 'https://github.com/kcook98765/skin.aura'
    assert record['schema_version'] == 5 and record['approval_policy'] == 'aura-cast-fix-2.1.1-v1'
    assert record['rights_approved'] is False and record['rights_review'] == {'status':'pending'}
    assert record['owner_acknowledgment'] == {'status':'not_recorded'}
    assert not any(k in record for k in ('skin_alpha_evidence', 'original_assets_admission',
                                       'unofficial_integration', 'runtime_acceptance_exception'))
    assert record['approval_lanes'] in (['omega'], []) and set(record['compatibility']) == {'omega'}
    assert {k:config.get(k) for k in policy['destination']} == policy['destination']
    assert any(p == {'id':'skin.aura','version':'2.1.0','sha256':policy['baseline_package_sha256']} for p in history)
    if not record['approval_lanes']:
        assert any(p == {'id':'skin.aura','version':'2.1.1','sha256':record['package_sha256']} for p in history)
    value = record['aura_patch_admission']
    assert set(value) == {'scope','policy_sha256','expires_at','baseline_review','source_audit',
                         'independent_artifact_review','historical_native_use','scenarios','technical_findings',
                         'actor_fix_native_accepted','evidence'}
    assert value['scope'] == 'exact_aura_2.1.1_cast_fix_successor_only'
    assert value['policy_sha256'] == policy_hash and value['expires_at'] == '2026-12-15T02:11:01Z'
    assert value['actor_fix_native_accepted'] is False

    def load(ref, expected):
        assert audit_pinned_evidence([ref])
        name, checksum = ref.rsplit(' sha256:', 1)
        assert checksum == expected
        raw = path(ROOT/'incoming', name).read_bytes()
        assert digest(raw) == expected
        return json.loads(raw)

    old = load(value['baseline_review'], '3129f77ab37dacbd8be6421025a1ff4e66fe92d8b714a3704b7c060948a61720')
    source = load(value['source_audit'], '88a23e280dd081a8606bedc5a7e48a2875b53b45810426c59812229df5eb6f70')
    independent = load(value['independent_artifact_review'], '8b93ef096d9023f096b912d28b6cb0c639b9d5c6177ac811c4c6522dfcbcdc61')
    assert old['package_sha256'] == policy['baseline_package_sha256']
    assert len(files) == 1806 and set(files) == set(old['runtime_files'])
    expected_files = old['runtime_files'] | policy['allowed_runtime_changes']
    assert {n:digest(data) for n,data in files.items()} == record['runtime_files'] == expected_files
    assert {n:data['sha256'] for n,data in source['files'].items()} == expected_files
    assert source['merged_main_commit'] == independent['main'] == record['source_commit']
    assert source['zip']['sha256'] == independent['zip_sha256'] == record['package_sha256']
    assert independent['all_members_match_actual_merged_git_blobs'] is True
    assert independent['all_published_fonts_artwork_and_supplemental_notices_retained_identically'] is True
    assert independent['native_acceptance'] is False and independent['rights_verified'] is False
    assert record['unresolved_risks'] == old['unresolved_risks']
    assert value['scenarios'] == old['skin_alpha_evidence']['scenarios']
    assert value['historical_native_use'] == old['skin_alpha_evidence']['owner_native_use']
    assert value['technical_findings'] == old['original_assets_admission']['technical_findings']
    assert len(manifest.findall("extension[@point='xbmc.gui.skin']")) == 1
    assert all(n.get('point') in ('xbmc.gui.skin','xbmc.addon.metadata') for n in manifest.findall('extension'))
    assert manifest.find("requires/import[@addon='xbmc.gui']").get('version') == '5.17.0'
    accepted = record['compatibility']['omega']; test = accepted['runtime_test']
    assert accepted['static_accepted'] is True and accepted['runtime_accepted'] is False
    assert test['status'] == 'deferred'
    assert test['outstanding_tests'] == [s['id'] for s in value['scenarios']] + ['AURA-CAST-2.1.1']
    now = datetime.now(timezone.utc)
    assert now < datetime.strptime(value['expires_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    assert datetime.strptime(test['recorded_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) <= now
    assert test['recorded_at'] < value['expires_at']
    for key in ('technical_release','release_decision'):
        action = record[key]
        assert action['status'] in ('pending','approved','rejected','revoked')
        if action['status'] == 'approved':
            assert set(action) == {'status','actor','role','recorded_at','rationale','evidence'}
            assert action['role'] == ('independent_reviewer' if key == 'technical_release' else 'operator')
            assert action['actor'].strip().casefold() != 'kcook98765'
            assert audit_pinned_evidence(action['evidence'])
            assert datetime.strptime(action['recorded_at'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) <= now
            assert action['recorded_at'] < value['expires_at']
        if production:
            assert action['status'] == 'approved', 'Exact successor technical/operator recording incomplete'
    assert record['release_approved'] is (record['release_decision']['status']=='approved')
    if all(record[k]['status'] == 'approved' for k in ('technical_release','release_decision')):
        assert record['technical_release']['actor'].strip().casefold() != record['release_decision']['actor'].strip().casefold(), 'Reviewer and operator must be independent'
        assert record['technical_release']['recorded_at'] <= record['release_decision']['recorded_at']


def aura_patch_public(record):
    """Independently reconstruct the exact public factual subset, not private paths."""
    value = record['aura_patch_admission']
    return {'alpha':True, 'admission':'owner_task_directed_exact_2.1.1_patch',
        'rights_approved':False, 'rights_review':'pending', 'third_party_permission_established':False,
        'native_candidate_accepted':False, 'actor_fix_native_accepted':False,
        'historical_owner_use':'Previous general-use report is not native acceptance of this successor.',
        'testing':'Owner requested no further testing; formal scenarios and actor-fix native bad-library route remain deferred.',
        'outstanding_scenarios':[{k:s[k] for k in ('id','lane','kind','observation','description')} for s in value['scenarios']],
        'additional_outstanding_scenario':'AURA-CAST-2.1.1: native actor-art bad-library-route acceptance not performed',
        'material_findings':[{k:r[k] for k in ('id','category','description')} for r in record['unresolved_risks'] if r['category']=='rights'],
        'technical_findings':{k:v for k,v in value['technical_findings'].items() if k != 'evidence'},
        'notice':'This bounded repository admission grants no third-party rights, legal clearance or license override.',
        'expires_at':'2026-12-15T02:11:01Z'}


def reviewed_inputs(config, profile):
    expected = {}
    if profile == 'fixture':
        for ver, lanes in [('1.0.0', ['matrix', 'nexus']), ('1.1.0', ['omega', 'piers'])]:
            source = ROOT/'fixtures'/ver/'script.toolkit.sample'
            files = {n:path(source, n).read_bytes() for n in ['addon.xml', 'default.py', 'LICENSE.txt', 'resources/icon.png']}
            expected[('script.toolkit.sample', ver)] = {'files': files, 'lanes': lanes, 'fixture_only': True}
        return expected
    inputs = json.loads((ROOT/f'config/{profile}.json').read_text())
    assert isinstance(inputs['external_dependencies'], dict)
    assert set(inputs['external_dependencies']) <= {'official_omega', 'official_nexus', 'official_matrix'}
    for item in inputs['packages']:
        blob = path(ROOT/'incoming', item['zip']).read_bytes()
        assert digest(blob) == item['sha256']
        raw = path(ROOT/'incoming', item['review_record']).read_bytes()
        assert digest(raw) == item['review_record_sha256']
        record = json.loads(raw)
        patch_policy = record.get('schema_version') == 5 and record.get('approval_policy') == 'aura-cast-fix-2.1.1-v1'
        if 'candidate_context' in config:
            old_pending = (record.get('schema_version') == 2 and record.get('approval_policy') == 'strict-v1' and
                record['rights_approved'] is False and record['release_approved'] is False and
                all(record.get(k) == {'status':'pending'} for k in ('rights_review','technical_release','release_decision')) and
                all(v['static_accepted'] is False and v['runtime_accepted'] is False for v in record['compatibility'].values()))
            skin_pending = (((record.get('schema_version') == 4 and record.get('approval_policy') == 'initial-release-skin-alpha-v1') or
                (record.get('schema_version') == 5 and record.get('approval_policy') == 'aura-original-assets-alpha-v1')) and
                record['release_approved'] is False and record['release_decision'] == {'status':'pending'} and
                record['owner_acknowledgment'] == {'status':'not_recorded'} and
                record.get('skin_alpha_evidence', {}).get('owner_coverage_decision') == {'status':'pending'})
            assert old_pending or skin_pending, 'Candidate must retain pending owner decisions'
        assert record['package_sha256'] == digest(blob) and record['fixture_only'] is False
        assert re.fullmatch('[0-9a-f]{40}', record['source_commit'])
        assert record['source_repository'].startswith('https://github.com/')
        assert all(type(record[k]) is bool for k in ['rights_approved', 'release_approved'])
        assert len(item['lanes']) == len(set(item['lanes']))
        for lane in item['lanes']:
            assert lane in config['lanes']
            acceptance = record['compatibility'][lane]
            assert all(type(acceptance[k]) is bool for k in ['static_accepted', 'runtime_accepted'])
            assert isinstance(acceptance['evidence'], list)
            assert all(isinstance(e, str) and e.strip() for e in acceptance['evidence'])
        manifest, files = archive_files(blob)
        assert {n:digest(b) for n,b in files.items()} == record['runtime_files']
        history = json.loads(configuration(profile)[2].read_text())['packages']
        verify_skin_evidence_files(record)
        assert record.get('schema_version') == 5 or 'original_assets_admission' not in record
        if record.get('schema_version') == 5 and not patch_policy:
            assert (manifest.get('id'),manifest.get('version')) == ('skin.aura','2.1.0')
        if patch_policy:
            aura_patch_gate(record, manifest, history, config, files, profile == 'production')
        material_actions = original_assets_gate(record, config) if record.get('schema_version') == 5 and not patch_policy else None
        approval = approval_contract.assess(record, item['lanes'],
            package_identity=(manifest.get('id'), manifest.get('version')), release_history=history, package_manifest=manifest)
        approval['review_record_sha256'] = digest(raw)
        approval['package_sha256'] = digest(blob)
        if record.get('schema_version') == 5 and not patch_policy:
            material = record['original_assets_admission']
            assert approval['rights_approved'] is False and approval['rights_status'] == 'pending'
            assert approval['third_party_permission_established'] is False
            assert approval['original_assets_admission'] == material
            assert approval['original_assets_admission_sha256'] == digest(json.dumps(
                material,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
            assert approval['original_assets_policy_active'] is (material['independent_review']['status'] == 'verified')
        # Independently enforce every strict production gate, even if a plan lies.
        if profile == 'production':
            initial_policy = record.get('schema_version') == 3 and record.get('approval_policy') == 'unofficial-integration-initial-release-v1'
            skin_policy = ((record.get('schema_version') == 4 and record.get('approval_policy') == 'initial-release-skin-alpha-v1') or
                (record.get('schema_version') == 5 and record.get('approval_policy') == 'aura-original-assets-alpha-v1'))
            assert initial_policy or 'runtime_acceptance_exception' not in record
            assert record['release_approved']
            assert not approval['release_blockers'], 'Outstanding approval gates'
            for lane in item['lanes']:
                accepted = record['compatibility'][lane]
                assert accepted['static_accepted'] and (accepted['runtime_accepted'] or initial_policy or skin_policy or patch_policy) and accepted['evidence']
            if record.get('schema_version', 1) not in (3, 5):
                assert record['rights_approved']
            if record.get('schema_version', 1) in (2, 3, 4, 5):
                assert record['technical_release']['status'] == 'approved'
                assert record['release_decision']['status'] == 'approved'
            if record.get('schema_version', 1) == 2:
                assert record['rights_review']['status'] == 'verified'
                assert not record['unresolved_risks']
                assert all(record['compatibility'][lane]['runtime_test']['status'] == 'passed' for lane in item['lanes'])
            if skin_policy:
                skin_alpha_gate(record, manifest, history, approval, material_actions=material_actions)
            if record.get('schema_version') == 3:
                assert record['approval_policy'] in ('unofficial-integration-v1', 'unofficial-integration-initial-release-v1')
                assert set(record['approval_lanes']) == set(item['lanes'])
                assert record['rights_approved'] is False and record['rights_review'] == {'status': 'pending'}
                risks = record['unresolved_risks']
                ids = {r['id'] for r in risks if r['category'] == 'provider_terms'}
                assert ids and all(r['category'] == 'provider_terms' or (initial_policy and r['category'] == 'runtime') for r in risks)
                value = record['unofficial_integration']
                package = value['package_distribution_review']; service = value['service_use_review']
                owner = value['owner_distribution_decision']; ack = record['owner_acknowledgment']
                assert package['status'] == 'verified' and package['scope'] == 'all_distributed_materials'
                assert service['scope'] == 'runtime_service_content_and_marks'
                exception = owner.get('provider_authorization_exception')
                if service['status'] == 'authorization_unverified':
                    assert isinstance(exception, dict)
                if exception is not None:
                    assert service['status'] == 'authorization_unverified'
                    assert set(exception) == {'scope', 'upstream_provider', 'addon_id', 'addon_version',
                        'package_sha256', 'provider_authorization_verified', 'provider_terms_concern',
                        'owner_accepts_risk', 'expires_at'}
                    assert exception['scope'] == 'repository_provider_authorization_gate_only'
                    assert exception['provider_authorization_verified'] is False and exception['owner_accepts_risk'] is True
                    assert exception['upstream_provider'] == service['upstream_provider']
                    assert all(isinstance(exception[k], str) and exception[k].strip() and
                               exception[k] == exception[k].strip() for k in ('upstream_provider', 'provider_terms_concern'))
                    assert (exception['addon_id'], exception['addon_version'], exception['package_sha256']) == (
                        manifest.get('id'), manifest.get('version'), digest(blob))
                    assert ack['actor'].strip().casefold() == owner['actor'].strip().casefold()
                    assert all(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp)
                               for stamp in (owner['recorded_at'], exception['expires_at']))
                    recorded = datetime.strptime(owner['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                    expiry = datetime.strptime(exception['expires_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                    assert recorded <= datetime.now(timezone.utc) < expiry
                else:
                    assert service['status'] == 'terms_unresolved'
                assert service['provider_permission_obtained'] is False
                assert service['provider_content_authorization'] == 'not_established'
                assert owner['status'] == 'accepted' and owner['role'] == 'owner' and owner['authorization_claimed'] is False
                assert ack['status'] == 'acknowledged' and ack['role'] == 'owner'
                for action in (service, owner):
                    assert len(action['risk_ids']) == len(ids) and set(action['risk_ids']) == ids
                assert len(ack['risk_ids']) == len(risks) and set(ack['risk_ids']) == {r['id'] for r in risks}
                assert all(review['actor'].strip().casefold() != owner['actor'].strip().casefold()
                           for review in (package, service))
                scope = item['lanes'] or list(record['compatibility'])
                assert scope
                if initial_policy:
                    initial_runtime_gate(record, scope, manifest, history)
                    assert approval['runtime_exception_active'] is True
                    assert approval['runtime_admission'] == 'owner_accepted_runtime_limitations'
                    assert approval['runtime_acceptance_exception'] == record['runtime_acceptance_exception']
                for lane in ([] if initial_policy else scope):
                    accepted = record['compatibility'][lane]; test = accepted['runtime_test']
                    assert accepted['static_accepted'] and accepted['runtime_accepted'] and accepted['evidence']
                    assert test['status'] == 'passed' and test['outstanding_tests'] == []
                    assert all(test[k].strip() for k in ('actor', 'role', 'platform', 'kodi_version', 'scope', 'recorded_at', 'rationale'))
                    assert test['evidence']
                assert approval['package_distribution_eligible'] is True
                assert approval['accepted_terms_risks'] == [r for r in risks if r['category'] == 'provider_terms'] and approval['rights_status'] == 'pending'
        if record.get('schema_version') == 3:
            notice = record['unofficial_integration']['disclosure']
            path(ROOT/'incoming', notice['package_path'])
            assert digest(files[notice['package_path']]) == notice['package_sha256']
            assert files[notice['package_path']].decode('utf-8').strip()
            if not item['lanes']:
                assert any((old['id'], old['version'], old['sha256']) ==
                           (manifest.get('id'), manifest.get('version'), digest(blob))
                           for old in json.loads(configuration(profile)[2].read_text())['packages'])
        key = (manifest.get('id'), manifest.get('version'))
        assert key not in expected
        expected[key] = {'blob': blob, 'files': files, 'lanes': item['lanes'],
                         'fixture_only': False, 'provenance': record, 'approval': approval}
    # Independently restore historical infrastructure against the immutable
    # ledger, without importing the builder or inventing add-on approvals.
    history = json.loads(configuration(profile)[2].read_text())['packages']
    for item in inputs.get('retained_installers', []):
        assert set(item) == {'id', 'version', 'sha256', 'zip'}
        key = (item['id'], item['version'])
        assert key not in expected and key[0] == config['addon_id']
        assert numeric(key[1]) < numeric(config['version'])
        assert item['zip'] == f'{key[0]}-{key[1]}.zip'
        assert sum(old == {k: item[k] for k in ('id', 'version', 'sha256')} for old in history) == 1
        blob = path(ROOT/'incoming', item['zip']).read_bytes()
        assert digest(blob) == item['sha256']
        manifest, files = archive_files(blob)
        assert (manifest.get('id'), manifest.get('version')) == key
        assert manifest.find("extension[@point='xbmc.addon.repository']") is not None
        expected[key] = {'blob': blob, 'files': files, 'lanes': [], 'fixture_only': False,
                         'provenance': {'source': 'ledger-pinned historical repository installer',
                                        'runtime_files': {n: digest(v) for n, v in files.items()}}}
    for old in history:
        if (old['id'], old['version']) == (config['addon_id'], config['version']):
            continue  # Generated installer is checked with the complete inventory below.
        assert digest(expected[(old['id'], old['version'])]['blob']) == old['sha256']
    return expected


def external_dependency_report(profile, manifests, builtins, lane, bindings):
    if profile == 'fixture':
        return {}
    inputs = json.loads((ROOT/f'config/{profile}.json').read_text())
    spec = inputs['external_dependencies']
    assert isinstance(spec, dict)
    if not spec:
        return {}
    assert set(spec) <= {'official_omega', 'official_nexus', 'official_matrix'}
    results = []
    import importlib
    own = {'matrix': 'official_matrix', 'nexus': 'official_nexus', 'omega': 'official_omega'}.get(lane)
    providers = sorted(spec, key=lambda key: (key != own, key))
    exact_current_root = False
    for provider in providers:
        visible = manifests
        if provider != own and exact_current_root:
            visible = [node for node in manifests if node.get('id') != 'script.tvguide.fullscreen']
        result = importlib.import_module('audit_' + provider).resolve(visible, builtins, {provider: spec[provider]}, ROOT/'incoming', lane, bindings)
        results.append(result)
        if provider == own and result['active']:
            root = result.get('roots', {}).get('script.tvguide.fullscreen')
            exact_current_root = root is not None and root == spec[provider]['roots'].get('script.tvguide.fullscreen')
    enabled = [result for result in results if result['active']]
    assert len(enabled) <= 1, 'Conflicting active exact-root dependency adapters'
    return enabled[0] if enabled else results[0]


def check_dependencies(manifests, builtins, external_versions=None):
    external_versions = external_versions or {}
    available = {**external_versions, **builtins, **{m.get('id'):m.get('version') for m in manifests}}
    edges = {}
    for manifest in manifests:
        aid = manifest.get('id'); edges[aid] = []
        for dep in manifest.findall('requires/import'):
            name = dep.get('addon')
            dependency_version(dep.get('version'))
            satisfied = name in available and dependency_ge(available[name], dep.get('version'))
            if dep.get('optional') == 'true': continue
            assert satisfied, 'Required dependency unavailable/too old: '+name
            if name not in builtins: edges[aid].append(name)
    def visit(node, active, done):
        assert node not in active, 'Dependency cycle'
        if node in done: return
        for child in edges.get(node, []): visit(child, active | {node}, done)
        done.add(node)
    done = set()
    for node in edges: visit(node, set(), done)


def audit(profile='fixture'):
    if not __debug__:
        raise RuntimeError('Run without -O; audit assertions are required')
    assert profile in ('fixture', 'production', 'candidate')
    prefix = {'fixture':'qualification/', 'production':'', 'candidate':'candidate/'}[profile]
    out = ROOT/'dist'/profile; site = out/'site'
    config, config_file, ledger_file = configuration(profile)
    plan = json.loads((out/'release-plan.json').read_text())
    assert plan['profile'] == profile and plan['publication_authorized'] is False
    assert plan['fixture_only'] is (profile == 'fixture') and plan['remote_actions_executed'] == []
    assert plan['config_sha256'] == digest(config_file.read_bytes())
    intake_path = 'config/candidate.json' if profile == 'candidate' else 'config/production.json'
    assert plan['input_config_sha256'] == digest((ROOT/intake_path).read_bytes())
    assert plan['retention_ledger_sha256'] == digest(ledger_file.read_bytes())
    if 'candidate_context' in config:
        assert plan.get('candidate_context') == config['candidate_context']
        assert plan['proposed_actions'] == ['Local candidate feed preparation only; no remote writes']
    assert plan['toolchain']['approval_contract_sha256'] == digest(Path(approval_contract.__file__).read_bytes())
    for name,filename in [('builder', 'repository.py'), ('auditor', 'audit_candidate.py'),
                          ('qualifier', 'qualify.py'), ('preflight', 'check_publication.py')]:
        assert plan['toolchain'][name+'_sha256'] == digest((Path(__file__).parent/filename).read_bytes())
    assert plan['toolchain']['review_schema_sha256'] == digest((Path(__file__).parents[1]/'docs/REVIEW-RECORD-SCHEMA.json').read_bytes())
    if profile != 'fixture' and json.loads((ROOT/f'config/{profile}.json').read_text())['external_dependencies']:
        adapters = json.loads((ROOT/f'config/{profile}.json').read_text())['external_dependencies']
        assert set(adapters) <= {'official_omega', 'official_nexus', 'official_matrix'}
        names = ['official_omega', 'audit_official_omega']
        if 'official_nexus' in adapters:
            names += ['official_nexus', 'audit_official_nexus']
        if 'official_matrix' in adapters:
            names += ['official_matrix', 'audit_official_matrix']
        for name in names:
            assert plan['toolchain'].get(name+'_sha256') == digest((Path(__file__).parent/(name+'.py')).read_bytes())
    expected = reviewed_inputs(config, profile)
    if any(item.get('provenance', {}).get('schema_version') == 5 for item in expected.values()):
        for key,filename in [('original_assets_module_sha256','scripts/original_assets.py'),
                             ('original_assets_policy_sha256','policies/aura-original-assets-2.1.0.json'),
                             ('original_assets_owner_approval_sha256','policies/aura-original-assets-owner-approval.json')]:
            assert plan['toolchain'][key] == digest((Path(__file__).resolve().parents[1]/filename).read_bytes())
    if any(item.get('provenance', {}).get('approval_policy') == 'aura-cast-fix-2.1.1-v1' for item in expected.values()):
        assert plan['toolchain']['aura_patch_module_sha256'] == digest((ROOT/'scripts/aura_patch.py').read_bytes())
        assert plan['toolchain']['aura_patch_policy_sha256'] == digest((ROOT/'policies/aura-cast-fix-2.1.1.json').read_bytes())
    installer_version = config['fixture_version'] if profile == 'fixture' else config['version']
    installer_source = ROOT/'packages'/config['addon_id']
    installer_files = {p.relative_to(installer_source).as_posix():p.read_bytes() for p in installer_source.rglob('*') if p.is_file()}
    assert set(installer_files) == {'addon.xml', 'LICENSE.txt', 'resources/icon.png', 'resources/ICON-LICENSE.txt'}
    assert installer_files['LICENSE.txt'] == (ROOT/'LICENSE').read_bytes()
    installer_manifest = xml(installer_files['addon.xml'])
    if profile == 'fixture':
        installer_manifest.set('version', config['fixture_version'])
        installer_manifest.set('name', installer_manifest.get('name')+' LOCAL FIXTURE')
        installer_manifest.find("extension[@point='xbmc.addon.metadata']/description").text = 'Local qualification only. Not published.'
    for directory in installer_manifest.findall("extension[@point='xbmc.addon.repository']/dir"):
        for tag in ('info', 'checksum', 'datadir', 'artdir'):
            node = directory.find(tag); node.text = node.text.replace(config['base_url'], config['base_url']+prefix, 1)
    assert (config['addon_id'], installer_version) not in expected, 'Duplicate generated installer'
    expected[(config['addon_id'], installer_version)] = {'files': installer_files,
        'manifest': installer_manifest, 'lanes': list(config['lanes']), 'fixture_only': profile == 'fixture'}
    keys = [(p['id'], p['version']) for p in plan['packages']]
    assert len(keys) == len(set(keys)) and set(keys) == set(expected), 'Unreviewed or missing package'
    if profile != 'fixture':
        hashes = {(p['id'], p['version']):p['sha256'] for p in plan['packages']}
        for old in json.loads(ledger_file.read_text())['packages']:
            assert hashes.get((old['id'], old['version'])) == old['sha256'], 'Installer/package retention mismatch'
    expected_site = {'.nojekyll', 'index.html'}; assets = {}; packages = {}; receipts = []
    for record in plan['packages']:
        key = (record['id'], record['version']); reviewed = expected[key]
        assert record['lanes'] == reviewed['lanes'] and record['fixture_only'] is reviewed['fixture_only']
        assert record.get('approval') == reviewed.get('approval'), 'Approval report differs from reviewed input'
        relative = prefix+f'packages/{key[0]}/{key[0]}-{key[1]}.zip'
        assert record['path'] == relative
        blob = path(site, relative).read_bytes()
        assert len(blob) == record['bytes'] and digest(blob) == record['sha256']
        assert digest(blob) == path(site, relative+'.sha256').read_text().strip()
        if 'blob' in reviewed: assert blob == reviewed['blob'] and record['provenance'] == reviewed['provenance']
        manifest, files = archive_files(blob)
        assert (manifest.get('id'), manifest.get('version')) == key
        assert {n:digest(b) for n,b in files.items()} == record['provenance']['runtime_files']
        if 'manifest' in reviewed:
            assert set(files) == set(reviewed['files'])
            assert all(data == reviewed['files'][n] for n,data in files.items() if n != 'addon.xml')
            assert structure(manifest) == structure(reviewed['manifest'])
            dirs = manifest.findall("extension[@point='xbmc.addon.repository']/dir")
            assert len(dirs) == len(config['lanes'])
            for d,(lane,settings) in zip(dirs, config['lanes'].items()):
                assert d.attrib == {k:settings[k] for k in ['minversion', 'maxversion']}
                base = config['base_url']+prefix
                for tag, suffix in [('info', f'catalogs/{lane}/addons.xml'),
                    ('checksum', f'catalogs/{lane}/addons.xml.sha256'), ('datadir', 'packages/'), ('artdir', f'artwork/{lane}/')]:
                    assert d.findtext(tag) == base+suffix
                assert d.findtext('hashes') == 'sha256' and d.find('checksum').get('verify') == 'sha256'
        else: assert files == reviewed['files']
        mirror = Path(relative).name
        for name,data in [(mirror,blob), (mirror+'.sha256',(digest(blob)+'\n').encode())]:
            assert path(out/'release-assets', name).read_bytes() == data
            assets[name] = digest(data)
        expected_site.update([relative, relative+'.sha256'])
        if key[0] == config['addon_id']:
            bootstrap = f'{key[0]}-{key[1]}.zip'
            assert path(site, bootstrap).read_bytes() == blob, 'Bootstrap installer copy mismatch'
            assert path(site, bootstrap+'.sha256').read_bytes() == (digest(blob)+'\n').encode(), 'Bootstrap installer sidecar mismatch'
            expected_site.update([bootstrap, bootstrap+'.sha256'])
        packages[key] = (manifest, files)
        receipts.append({'id':key[0], 'version':key[1], 'entries':sorted(files), 'sha256':digest(blob), 'bytes':len(blob)})
    assert set(plan['catalogs']) == set(config['lanes'])
    for lane,settings in config['lanes'].items():
        record = plan['catalogs'][lane]; relative = prefix+f'catalogs/{lane}/addons.xml'
        assert record['path'] == relative
        selected = {key:packages[key] for key,item in expected.items() if lane in item['lanes']}
        assert len({k[0] for k in selected}) == len(selected)
        identities = {k[0]:k[1] for k in selected}
        data = path(site, relative).read_bytes()
        assert digest(data) == record['sha256'] == path(site, relative+'.sha256').read_text().strip()
        root = xml(data); assert root.tag == 'addons'
        assert len(root) == len(identities) and {m.get('id'):m.get('version') for m in root} == identities == record['ids']
        assert [m.get('id') for m in root] == sorted(identities)
        bindings = {key[0]:{'package_sha256':digest(item['blob']), 'source_commit':item['provenance']['source_commit'],
                    'source_repository':item['provenance']['source_repository']}
                    for key,item in expected.items() if lane in item['lanes'] and 'source_commit' in item.get('provenance',{})}
        external = external_dependency_report(profile, list(root), settings['builtins'], lane, bindings)
        assert record.get('official_dependencies', {}) == external, 'Official dependency report differs from actual inputs'
        check_dependencies(list(root), {**settings['builtins'], **external.get('core_versions', {})}, external.get('external_versions'))
        for m in root:
            manifest, files = selected[(m.get('id'), m.get('version'))]
            assert structure(m) == structure(manifest)
            for asset in m.findall("extension[@point='xbmc.addon.metadata']/assets/*"):
                relative_asset = prefix+f'artwork/{lane}/{m.get("id")}/{asset.text}'
                assert path(site, relative_asset).read_bytes() == files[asset.text]
                expected_site.add(relative_asset)
        expected_site.update([relative, relative+'.sha256'])
    # Reconstruct the whole page from reviewed inputs. Substring matching alone
    # would accept notices hidden in comments, styles or hidden ancestors.
    page = path(site, 'index.html').read_bytes().decode('utf-8')
    filename = f'{config["addon_id"]}-{installer_version}.zip'
    links = f'<li><a href="{filename}">{filename}</a></li>'
    notices = []
    for key,item in expected.items():
        record = item.get('provenance', {})
        if record.get('schema_version') == 3:
            runtime_text = ''
            if 'runtime_acceptance_exception' in record:
                value = record['runtime_acceptance_exception']
                public = []
                for s in value['scenarios']:
                    public.append({'id': s['id'], 'lane': s['lane'], 'kind': s['kind'],
                                   'observation': s['observation'], 'description': s['description'],
                                   'supporting_evidence': [{'method': e['method'], 'status': e['status'], 'scope': e['scope']}
                                                           for e in s['supporting_evidence']]})
                runtime_text = escape('\nRuntime coverage limitations (not passed):\n' +
                    json.dumps(public, sort_keys=True, ensure_ascii=True) +
                    '\nRuntime owner decision: ' + value['owner_decision']['status'] +
                    '; exception expires: ' + value['expires_at'])
            notices.append('<section data-unofficial-package="'+key[0]+'-'+key[1]+'"><h2>'
                           +key[0]+' '+key[1]+'</h2><pre>'
                           +escape(record['unofficial_integration']['disclosure']['release_text'])
                           +runtime_text
                           +'</pre></section>')
    for key,item in expected.items():
        record = item.get('provenance', {})
        if record.get('schema_version') not in (4, 5):
            continue
        if record.get('approval_policy') == 'aura-cast-fix-2.1.1-v1':
            text = escape('Omega skin ALPHA; incomplete formal coverage.\n' +
                          json.dumps(aura_patch_public(record),sort_keys=True,ensure_ascii=True))
            notices.append('<section data-skin-alpha-package="'+key[0]+'-'+key[1]+'"><h2>'+key[0]+' '+key[1]+' ALPHA</h2><pre>'+text+'</pre></section>')
            continue
        value = record['skin_alpha_evidence']; native = value['owner_native_use']
        public = {'alpha':True, 'native_evidence':'owner_reported_general_use',
            'reported_version':native['reported_version'], 'platform':native['platform'],
            'duration':native['duration'], 'result':native['result'], 'known_limitations':native['known_limitations'],
            'formal_scripted_acceptance':False, 'cleaned_package_native_accepted':False,
            'installed_identity':native['identity_disposition'], 'identity_limitation':native['identity_limitation'],
            'reviewed_package_delta':{k:value['reviewed_package_delta'].get(k) for k in ('status','scope')},
            'outstanding_scenarios':[{k:s[k] for k in ('id','lane','kind','observation','description')} for s in value['scenarios']],
            'owner_coverage_decision':value['owner_coverage_decision']['status'], 'expires_at':value['expires_at']}
        if record['schema_version'] == 5:
            material = record['original_assets_admission']
            public.pop('cleaned_package_native_accepted')
            public['distribution_package_native_accepted'] = False
            public['material_rights'] = {
                'rights_approved':False, 'rights_review':'pending',
                'admission':'owner_directed_exact_package_exception',
                'third_party_permission_established':False, 'legal_clearance_claimed':False,
                'notice':'This owner policy changes repository admission only; it grants no third-party rights and overrides no license restrictions.',
                'findings':[{k:r[k] for k in ('id','category','description')} for r in record['unresolved_risks'] if r['category']=='rights'],
                'expires_at':material['expires_at']}
            public['accepted_technical_findings'] = {k:v for k,v in material['technical_findings'].items() if k != 'evidence'}
        text = escape('Omega skin ALPHA; incomplete formal coverage.\n' + json.dumps(public,sort_keys=True,ensure_ascii=True))
        notices.append('<section data-skin-alpha-package="'+key[0]+'-'+key[1]+'"><h2>'+key[0]+' '+key[1]+' ALPHA</h2><pre>'+text+'</pre></section>')
    if profile == 'fixture':
        expected_page = ('<!doctype html><title>kcook-lab-repo: local draft</title>'
                         '<p>Not published. Fixture artifacts must never be deployed.</p><ul>'+links+'</ul>\n')
    elif profile == 'candidate':
        expected_page = ('<!doctype html><title>Private Kodi candidate</title>'
                         '<p>Not approved for release. Native acceptance and rights must be resolved.</p><ul>'+links+'</ul>\n')
    else:
        expected_page = ('<!doctype html><html lang="en"><meta charset="utf-8">'
                         '<meta name="viewport" content="width=device-width, initial-scale=1">'
                          '<title>kcook-lab-repo</title><h1>kcook-lab-repo</h1>'
                          '<p>Add this HTTPS source in Kodi File manager and name it kcook-lab-repo. '
                         'Use Install from zip file to select the repository installer below. '
                         'Then use Install from repository to browse compatible add-ons by category.</p><ul>'+links+'</ul>'
                         '<p>Each ZIP has a SHA-256 sidecar at the same URL plus .sha256.</p>'
                         '<p><a href="https://github.com/'+config['github_repository']+'">'
                         'Source, architecture and release procedures</a></p></html>\n')
    if notices:
        rendered = ''.join(notices)
        expected_page = (expected_page.replace('</html>', rendered+'</html>')
                         if '</html>' in expected_page else expected_page+rendered)
    assert page == expected_page, 'Public disclosure/index differs from reviewed input'
    actual = {p.relative_to(site).as_posix():digest(path(site, p.relative_to(site).as_posix()).read_bytes())
              for p in site.rglob('*') if p.is_file()}
    assert set(actual) == expected_site, 'Unreviewed or missing public site files'
    assert actual == plan['site_files'] and digest(json_bytes(actual)) == plan['site_manifest_sha256']
    assert {p.name:digest(path(out/'release-assets', p.name).read_bytes())
            for p in (out/'release-assets').iterdir() if p.is_file()} == assets == plan['release_assets']
    assert (out/'SHA256SUMS').read_bytes() == ''.join(f'{value}  {name}\n' for name,value in sorted(assets.items())).encode()
    blockers = ['Private candidate profile cannot authorize publication'] if profile == 'candidate' else []
    approvals = []
    for item in expected.values():
        if 'approval' in item:
            blockers.extend(item['approval']['release_blockers'])
            approvals.append(item['approval'])
    assert plan['release_blockers'] == sorted(set(blockers)), 'Approval blocker report mismatch'
    return {'status':'PASS', 'profile':profile, 'audit':'independent stdlib reviewed-input ZIP/XML/checksum inspection',
            'packages':receipts, 'catalogs':len(config['lanes']), 'site_files':len(actual),
            'production_addon_intake_empty':not json.loads((ROOT/'config/production.json').read_text())['packages'],
            'tastemade_or_aura_present':any(k[0] in ['plugin.video.tastemade', 'skin.aura'] for k in expected),
            'approvals': approvals, 'release_blockers':sorted(set(blockers)), 'runtime_tested':False, 'public_https_verified':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['fixture', 'production', 'candidate'], default='fixture')
    args = parser.parse_args()
    if not __debug__: raise RuntimeError('Run without -O; independent audit assertions are required')
    result = audit(args.profile); (ROOT/'reports').mkdir(exist_ok=True)
    target = 'operator-independent-audit.json' if args.profile == 'fixture' else args.profile+'-audit.json'
    (ROOT/'reports'/target).write_bytes(json_bytes(result))
    print(json.dumps(result, indent=2))
