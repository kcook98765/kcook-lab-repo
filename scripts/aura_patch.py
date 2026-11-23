"""Only the frozen owner-requested Aura 2.1.1 cast fix; not a successor framework."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = 'aura-cast-fix-2.1.1-v1'
POLICY_FILE = 'policies/aura-cast-fix-2.1.1.json'
POLICY_SHA256 = '49c684aaee6651fc8430bfec9498af02869adea201bf1d4a0dc291a914ebae7e'
PACKAGE = 'a5dc17aadfc5f14ed4807a2c16d55e23e3dd5fb5320fb9eb93885d3a0cbddb92'
COMMIT = 'bf4f74a2a0d4b80670213f0b6fdb8728b33dd5ab'
EXPIRY = '2026-12-15T02:11:01Z'


def pinned(name, expected, base=ROOT):
    from approval_contract import canonical_path, require
    require(canonical_path(name), 'Unsafe Aura patch evidence path')
    path = base / name
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked Aura patch evidence')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected, 'Changed Aura patch policy/evidence: ' + name)
    return json.loads(raw)


def reference(ref):
    from approval_contract import pinned_references, require
    require(pinned_references([ref]), 'Unpinned Aura patch evidence')
    name, expected = ref.rsplit(' sha256:', 1)
    return pinned(name, expected, ROOT / 'incoming')


def destination(config):
    from approval_contract import require
    policy = pinned(POLICY_FILE, POLICY_SHA256)
    require({k: config.get(k) for k in policy['destination']} == policy['destination'],
            'Aura patch actual destination mismatch')


def assess(record, lanes, identity, history, manifest):
    from approval_contract import decision, pinned_references, require, utc_now
    policy = pinned(POLICY_FILE, POLICY_SHA256)
    require(set(record) == {'schema_version', 'approval_policy', 'approval_lanes', 'package_sha256',
            'source_repository', 'source_commit', 'fixture_only', 'runtime_files', 'rights_approved',
            'rights_review', 'release_approved', 'release_decision', 'technical_release',
            'owner_acknowledgment', 'unresolved_risks', 'compatibility', 'aura_patch_admission',
            'limitations'}, 'Unexpected Aura patch record field')
    require(record['schema_version'] == 5 and record['approval_policy'] == POLICY and
            identity == ('skin.aura', '2.1.1') and record['source_commit'] == COMMIT and
            record['package_sha256'] == PACKAGE and record['source_repository'] == policy['source_repository'] and
            record['fixture_only'] is False, 'Only exact frozen Aura 2.1.1 is enrolled')
    require(lanes in (['omega'], []) and record['approval_lanes'] == lanes and
            set(record['compatibility']) == {'omega'}, 'Aura patch is Omega-only')
    require(isinstance(history, list) and any(p == {'id': 'skin.aura', 'version': '2.1.0',
            'sha256': policy['baseline_package_sha256']} for p in history), 'Published predecessor missing')
    if not lanes:
        require(any(p == {'id': 'skin.aura', 'version': '2.1.1', 'sha256': PACKAGE} for p in history),
                'Empty successor lanes require exact retained history')
    require(record['rights_approved'] is False and record['rights_review'] == {'status': 'pending'} and
            record['owner_acknowledgment'] == {'status': 'not_recorded'},
            'Task authority is not rights clearance or invented itemwise acknowledgment')
    require(not any(k in record for k in ('skin_alpha_evidence', 'original_assets_admission',
            'runtime_acceptance_exception', 'unofficial_integration')), 'Historical policy cannot be relabelled')
    value = record['aura_patch_admission']
    require(set(value) == {'scope', 'policy_sha256', 'expires_at', 'baseline_review', 'source_audit',
            'independent_artifact_review', 'historical_native_use', 'scenarios', 'technical_findings',
            'actor_fix_native_accepted', 'evidence'} and value['scope'] == policy['scope'] and
            value['policy_sha256'] == POLICY_SHA256 and value['expires_at'] == EXPIRY and
            value['actor_fix_native_accepted'] is False, 'Aura patch admission scope mismatch')
    require(value['baseline_review'].endswith(' sha256:' + policy['baseline_review_sha256']) and
            value['source_audit'].endswith(' sha256:' + policy['source_audit_sha256']) and
            value['independent_artifact_review'].endswith(' sha256:' + policy['independent_final_artifact_review_sha256']),
            'Aura patch evidence binding mismatch')
    baseline = reference(value['baseline_review'])
    source = reference(value['source_audit'])
    independent = reference(value['independent_artifact_review'])
    require(baseline['package_sha256'] == policy['baseline_package_sha256'], 'Wrong predecessor review')
    expected_files = baseline['runtime_files'] | policy['allowed_runtime_changes']
    require(record['runtime_files'] == expected_files and len(expected_files) == 1806 and
            set(expected_files) == set(baseline['runtime_files']), 'Unexpected runtime/asset/notice delta')
    require({n: entry['sha256'] for n, entry in source['files'].items()} == expected_files and
            source['merged_main_commit'] == COMMIT and source['zip']['sha256'] == PACKAGE,
            'Final merged-source audit differs from inspected package')
    require(independent['main'] == COMMIT and independent['zip_sha256'] == PACKAGE and
            independent['all_members_match_actual_merged_git_blobs'] is True and
            independent['all_published_fonts_artwork_and_supplemental_notices_retained_identically'] is True and
            independent['rights_verified'] is False and independent['native_acceptance'] is False,
            'Independent exact artifact evidence missing or overstated')
    require(record['unresolved_risks'] == baseline['unresolved_risks'] and
            value['scenarios'] == baseline['skin_alpha_evidence']['scenarios'] and
            value['historical_native_use'] == baseline['skin_alpha_evidence']['owner_native_use'] and
            value['technical_findings'] == baseline['original_assets_admission']['technical_findings'],
            'Every original finding/scenario/native-use limitation/checker failure must remain unchanged')
    require(manifest is not None and (manifest.get('id'), manifest.get('version')) == identity and
            len(manifest.findall("extension[@point='xbmc.gui.skin']")) == 1 and
            all(e.get('point') in ('xbmc.gui.skin', 'xbmc.addon.metadata') for e in manifest.findall('extension')) and
            manifest.find("requires/import[@addon='xbmc.gui']").get('version') == '5.17.0',
            'Inspected Omega skin-only manifest required')
    accepted = record['compatibility']['omega']; test = accepted['runtime_test']
    decision(test, ('deferred',), extra=('platform', 'kodi_version', 'scope', 'outstanding_tests'))
    require(accepted['static_accepted'] is True and accepted['runtime_accepted'] is False and
            test['outstanding_tests'] == [s['id'] for s in value['scenarios']] + ['AURA-CAST-2.1.1'],
            'Formal coverage and actor-fix runtime remain unaccepted')
    now = utc_now()
    require(datetime.strptime(test['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) <= now and
            test['recorded_at'] < EXPIRY, 'Future/expired runtime deferral recording')
    require(now < datetime.strptime(EXPIRY, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc),
            'Exact Aura patch policy expired')
    blockers = []
    for key in ('technical_release', 'release_decision'):
        action = record[key]
        decision(action, ('pending', 'approved', 'rejected', 'revoked'))
        if action['status'] != 'approved':
            blockers.append(key + ': ' + action['status'])
        else:
            require(pinned_references(action['evidence']), 'Technical/operator evidence must be hash-pinned')
            require(action['role'] == ('independent_reviewer' if key == 'technical_release' else 'operator'),
                    'Technical review and operator task-authority recording are distinct')
            require(action['actor'].strip().casefold() != 'kcook98765', 'Do not impersonate an owner decision')
            require(datetime.strptime(action['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) <= now and
                    action['recorded_at'] < EXPIRY, 'Future/expired Aura patch action')
    require(record['release_approved'] is (record['release_decision']['status'] == 'approved') and
            (not record['release_approved'] or not blockers), 'Premature Aura patch release approval')
    if all(record[k]['status'] == 'approved' for k in ('technical_release', 'release_decision')):
        require(record['technical_release']['actor'].strip().casefold() !=
                record['release_decision']['actor'].strip().casefold(),
                'Aura patch technical reviewer must be independent of recording operator')
        require(record['technical_release']['recorded_at'] <= record['release_decision']['recorded_at'],
                'Operator release recording must follow actual independent review')
    return {'package_sha256': PACKAGE, 'source_repository': record['source_repository'], 'source_commit': COMMIT,
        'lanes': list(lanes), 'approval_lanes': list(lanes), 'schema_version': 5, 'approval_policy': POLICY,
        'rights_approved': False, 'release_approved': record['release_approved'], 'rights_status': 'pending',
        'rights_review': record['rights_review'], 'release_status': record['release_decision']['status'],
        'technical_release_status': record['technical_release']['status'], 'technical_release': record['technical_release'],
        'release_decision': record['release_decision'], 'owner_acknowledgment': record['owner_acknowledgment'],
        'runtime': {'omega': test}, 'unresolved_risks': record['unresolved_risks'], 'aura_patch_admission': value,
        'material_rights_admission': 'owner_task_directed_exact_successor_only', 'third_party_permission_established': False,
        'distribution_package_native_accepted': False, 'runtime_admission': 'task_directed_no_further_testing',
        'native_evidence_grade': 'historical_owner_use_not_successor_acceptance', 'publication_authorized': False,
        'package_distribution_eligible': not blockers, 'release_blockers': blockers,
        'recorded_limitations': record['limitations'], 'recorded_native_scope': {}, 'limitations': []}


def public_notice(record):
    """Public factual subset only; never export private evidence paths or owner-use details."""
    value = record['aura_patch_admission']
    return {'alpha': True, 'admission': 'owner_task_directed_exact_2.1.1_patch',
        'rights_approved': False, 'rights_review': 'pending', 'third_party_permission_established': False,
        'native_candidate_accepted': False, 'actor_fix_native_accepted': False,
        'historical_owner_use': 'Previous general-use report is not native acceptance of this successor.',
        'testing': 'Owner requested no further testing; formal scenarios and actor-fix native bad-library route remain deferred.',
        'outstanding_scenarios': [{k: s[k] for k in ('id', 'lane', 'kind', 'observation', 'description')}
                                  for s in value['scenarios']],
        'additional_outstanding_scenario': 'AURA-CAST-2.1.1: native actor-art bad-library-route acceptance not performed',
        'material_findings': [{k: r[k] for k in ('id', 'category', 'description')}
                              for r in record['unresolved_risks'] if r['category'] == 'rights'],
        'technical_findings': {k: v for k, v in value['technical_findings'].items() if k != 'evidence'},
        'notice': 'This bounded repository admission grants no third-party rights, legal clearance or license override.',
        'expires_at': EXPIRY}


def toolchain():
    pinned(POLICY_FILE, POLICY_SHA256)
    return {'aura_patch_module_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'aura_patch_policy_sha256': POLICY_SHA256}
