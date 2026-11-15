"""One owner-approved admission-policy change. This supplies no asset rights.

Never use this route for another source, archive, release, lane or destination.
The independent auditor implements its own gate against the same frozen inputs.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

POLICY = 'aura-original-assets-alpha-v1'
REQUEST_SHA256 = 'fa0a5e73758fff3cc3d092683a34a82f103a2f66465b6f59afa58da8a27ac40f'
SOURCE_COMMIT = '88564fd2883d2d286bdf0e887dc0bee634fd8c4e'
PACKAGE_SHA256 = '7309fc3f60429e4ba638d36046565ae48fa2b75f56f653df5200a960aa3ce9c0'
DESTINATION = {'github_repository': 'kcook98765/kcook-lab-repo',
               'github_repository_id': 1428864210,
               'pages_url': 'https://kcook98765.github.io/kcook-lab-repo/',
               'repository_addon_id': 'repository.ai.kodi'}
EXPIRY = '2026-12-15T02:11:01Z'
ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = 'policies/aura-original-assets-2.1.0.json'
APPROVAL_FILE = 'policies/aura-original-assets-owner-approval.json'
APPROVAL_SHA256 = '326791dc0bf7884f3561d028cc9e394569c47b9d9df99e297358aca2981f613e'
VALIDATION_REF = ('evidence/aura-restored/omega-validation.json sha256:'
                  '2b13b6d7821e0bb17260b319e38540895722d8f5491ced4f8cd9414ae37b5f88')
DISPOSITION_REF = ('evidence/aura-restored/INDEPENDENT-DISPOSITION.md sha256:'
                   '46f0dd424e020790eeb9fe9b20dcf729541b411d37c80cd4e43c1850028e4d3a')


def require(value, message):
    if not value:
        raise ValueError('Original-assets admission: ' + message)


def pinned_json(name, digest):
    raw = (ROOT / name).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, 'frozen policy/approval changed')
    return json.loads(raw)


def destination(config):
    require((config['github_repository'], config.get('github_repository_id'), config['base_url'], config['addon_id']) ==
            (DESTINATION['github_repository'], DESTINATION['github_repository_id'], DESTINATION['pages_url'], DESTINATION['repository_addon_id']),
            'actual distribution destination differs from approved repository')


def evaluate(record, identity, lanes, manifest, history, now):
    # Import at evaluation time: the ordinary contract owns common action syntax.
    from approval_contract import decision, pinned_references, exact_risks, exception_digest
    request = pinned_json(POLICY_FILE, REQUEST_SHA256)
    receipt = pinned_json(APPROVAL_FILE, APPROVAL_SHA256)
    require(identity == ('skin.aura', '2.1.0') and
            record['source_repository'] == 'https://github.com/kcook98765/skin.aura' and
            record['source_commit'] == SOURCE_COMMIT and record['package_sha256'] == PACKAGE_SHA256 and
            record['fixture_only'] is False and len(record['runtime_files']) == 1806,
            'exact initial Aura source/package/inventory required')
    require(record['rights_approved'] is False and record['rights_review'] == {'status': 'pending'},
            'rights must remain false/pending; policy acceptance is not permission')
    expected_risks = request['proposed_policy_change']['rights_risks_must_remain_unresolved']
    require([r for r in record['unresolved_risks'] if r['category'] == 'rights'] == expected_risks,
            'all five complete material-rights findings must remain unchanged')
    value = record.get('original_assets_admission')
    require(isinstance(value, dict) and set(value) == {
        'scope', 'addon_id', 'addon_version', 'source_commit', 'package_sha256', 'lanes',
        'destination', 'expires_at', 'policy_request_sha256', 'owner_policy_decision',
        'independent_review', 'technical_findings'}, 'malformed exact-package policy evidence')
    require(value['scope'] == 'exact_original_assets_aura_alpha_admission_only' and
            (value['addon_id'], value['addon_version']) == identity and
            value['source_commit'] == SOURCE_COMMIT and value['package_sha256'] == PACKAGE_SHA256 and
            lanes == ['omega'] and value['lanes'] == ['omega'] and
            value['destination'] == DESTINATION and value['expires_at'] == EXPIRY and
            value['policy_request_sha256'] == REQUEST_SHA256,
            'policy identity/lane/destination/expiry mismatch')
    require(record['skin_alpha_evidence']['expires_at'] <= EXPIRY,
            'coverage cannot outlive material-admission policy')
    owner = value['owner_policy_decision']; review = value['independent_review']
    decision(owner, ('approved',), extra=('policy_request_sha256',))
    require(owner['actor'] == 'kcook98765' and owner['role'] == 'owner' and
            owner['recorded_at'] == receipt['recorded_at'] and
            owner['policy_request_sha256'] == REQUEST_SHA256 and
            pinned_references(owner['evidence']) and
            {POLICY_FILE+' sha256:'+REQUEST_SHA256, APPROVAL_FILE+' sha256:'+APPROVAL_SHA256} <= set(owner['evidence']),
            'actual hash-bound owner policy approval required')
    require(record['skin_alpha_evidence']['owner_native_use']['actor'] == owner['actor'],
            'policy and owner-use identity must match')
    require(receipt['status'] == 'approved' and receipt['actor'] == owner['actor'] and
            receipt['role'] == 'owner' and receipt['policy_request_sha256'] == REQUEST_SHA256 and
            receipt['owner_message'] == 'Approve Aura policy decision '+REQUEST_SHA256 and
            receipt['scope'] == 'implementation_and_independent_qualification_only' and
            all(receipt[k] is False for k in ('package_admission_authorized', 'publication_authorized',
                                             'third_party_permissions_granted')),
            'policy approval must not imply package approval or asset rights')
    extra = {'scope', 'risk_ids', 'rights_verified', 'permissions_granted',
             'implementation_verified', 'findings_retained'}
    decision(review, ('pending', 'verified', 'rejected', 'revoked'), extra=extra)
    risk_ids = [r['id'] for r in expected_risks]
    if review['status'] != 'pending':
        require(set(review) == {'status', 'actor', 'role', 'recorded_at', 'rationale', 'evidence'} | extra and
                review['scope'] == 'retained_material_findings_and_policy_implementation_only' and
                review['actor'].strip().casefold() != owner['actor'].casefold() and
                review['role'] == 'independent_reviewer' and review['recorded_at'] >= owner['recorded_at'] and
                exact_risks(review['risk_ids'], risk_ids) and pinned_references(review['evidence']) and
                review['rights_verified'] is False and review['permissions_granted'] is False and
                review['implementation_verified'] is True and review['findings_retained'] is True,
                'independent review verifies policy/findings, never permission')
    technical = value['technical_findings']
    require(isinstance(technical, dict) and set(technical) == {
        'id', 'status', 'official_checker_status', 'official_checker_errors', 'official_checker_warnings',
        'toolkit_overall_passed', 'original_dimensions', 'paths', 'evidence'} and
        technical['id'] == 'STATIC-SCREENSHOTS' and
        technical['status'] == 'accepted_unofficial_distribution_limitation' and
        technical['official_checker_status'] == 'failed' and
        type(technical['official_checker_errors']) is int and technical['official_checker_errors'] == 5 and
        type(technical['official_checker_warnings']) is int and technical['official_checker_warnings'] == 3 and
        technical['toolkit_overall_passed'] is False and technical['original_dimensions'] == '1366x768' and
        technical['paths'] == ['resources/screenshot-%02d.jpg' % n for n in range(1, 6)] and
        pinned_references(technical['evidence']) and
        {VALIDATION_REF, DISPOSITION_REF} <= set(technical['evidence']),
        'preserved screenshots and actual failed checker evidence must remain disclosed')
    expiry = datetime.strptime(EXPIRY, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    actions = [owner, review]
    active = review['status'] == 'verified' and now < expiry
    for action in actions:
        if action['status'] == 'pending':
            active = False
            continue
        stamp = datetime.strptime(action['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        require(stamp < expiry, 'policy decision postdates expiry')
        active = active and stamp <= now
    if record['release_approved']:
        require(record['release_decision'].get('original_assets_admission_sha256') == exception_digest(value),
                'final package approval must bind complete material-admission evidence')
    return active, risk_ids, actions


def toolchain():
    pinned_json(POLICY_FILE, REQUEST_SHA256)
    pinned_json(APPROVAL_FILE, APPROVAL_SHA256)
    return {'original_assets_module_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'original_assets_policy_sha256': hashlib.sha256((ROOT/POLICY_FILE).read_bytes()).hexdigest(),
            'original_assets_owner_approval_sha256': hashlib.sha256((ROOT/APPROVAL_FILE).read_bytes()).hexdigest()}
