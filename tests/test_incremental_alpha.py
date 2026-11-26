"""Synthetic successor approvals and archives exercise normal production entry points."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

import test_approvals as fixtures
import approval_contract as contract
import audit_candidate as audit
import check_publication as publication
import qualify
import repository as repo

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None


class IncrementalAlphaTests(unittest.TestCase):
    setUp = fixtures.ApprovalTests.setUp
    files = fixtures.ApprovalTests.files
    admit = fixtures.ApprovalTests.admit

    def evidence(self, name):
        data = ('Synthetic evidence of ' + name + '\n').encode()
        (self.root/'incoming'/name).write_bytes(data)
        return name+' sha256:'+repo.sha(data)

    def action(self, status, name, *, owner=False):
        return {'status': status, 'actor': 'fixture-owner' if owner else 'fixture-reviewer',
                'role': 'owner' if owner else 'independent-reviewer', 'recorded_at': self.now,
                'rationale': 'Synthetic review of '+name, 'evidence': [self.evidence(name)]}

    def replace_review(self, index, record, inputs):
        raw = repo.json_bytes(record)
        item = inputs['packages'][index]
        (self.root/'incoming'/item['review_record']).write_bytes(raw)
        item['review_record_sha256'] = repo.sha(raw)
        (self.root/'config/production.json').write_bytes(repo.json_bytes(inputs))

    def approve(self, record):
        record.update(release_approved=True,
            release_decision=dict(self.action('approved', 'release', owner=True),
                                  successor_sha256=contract.successor_digest(record)))

    def record(self, provider=False):
        now = datetime.now(timezone.utc)
        self.now = (now-timedelta(seconds=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        expiry = (now+timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        files = self.files()
        manifest = repo.parse_xml(files['addon.xml'])
        manifest.find('extension/description').text = 'Synthetic ALPHA package'
        files['addon.xml'] = repo.xml_bytes(manifest)
        _, old = self.admit(files, ['omega'])
        old.update(schema_version=2, approval_policy='strict-v1', approval_lanes=['omega'],
                   rights_review=self.action('verified', 'old-rights'),
                   technical_release=self.action('approved', 'old-technical'),
                   release_decision=self.action('approved', 'old-release', owner=True),
                   owner_acknowledgment={'status': 'not_recorded'}, unresolved_risks=[])
        old['compatibility']['omega']['runtime_test'] = dict(self.action('passed', 'old-scoped-test'),
            platform='Synthetic Linux', kodi_version='21.3', scope='Published predecessor scope', outstanding_tests=[])
        # Independently represent previous approval and ledger retention.
        (self.root/'releases/manifest.json').write_bytes(repo.json_bytes({'schema': 1, 'packages': [
            {'id':'plugin.video.example','version':'1.0.0','sha256':old['package_sha256']}]}))
        updated = dict(files, **{'default.py': b'# Synthetic changed function\n'})
        inputs, record = self.admit(updated, ['omega'], ver='1.1.0')
        inputs['packages'][0]['lanes'] = []
        record.update(schema_version=2, approval_policy=contract.SUCCESSOR_POLICY,
                      source_commit='b'*40, approval_lanes=['omega'], rights_review=self.action('verified', 'rights'),
                      technical_release=self.action('approved', 'technical'))
        runtime_risk = {'id': 'runtime', 'category': 'runtime', 'description': 'Unobserved inherited scope',
                        'evidence': [self.evidence('coverage')]}
        record['unresolved_risks'] = [runtime_risk]
        if provider:
            notice = {'package_path': 'LICENSE.txt', 'package_sha256': record['runtime_files']['LICENSE.txt'],
                      'release_text': 'Synthetic unofficial integration and unresolved provider terms.'}
            terms = {'id': 'provider', 'category': 'provider_terms', 'description': 'Authorization is unverified',
                     'evidence': [self.evidence('terms')]}
            for value, version in ((old, '1.0.0'), (record, '1.1.0')):
                value.update(schema_version=3, rights_approved=False, rights_review={'status': 'pending'})
                value['unresolved_risks'].append(copy.deepcopy(terms))
                value['owner_acknowledgment'] = dict(self.action('acknowledged', 'ack', owner=True), risk_ids=['provider'])
                value['unofficial_integration'] = {
                    'package_distribution_review': dict(self.action('verified', 'materials'), scope='all_distributed_materials'),
                    'service_use_review': dict(self.action('authorization_unverified', 'service'),
                        scope='runtime_service_content_and_marks', risk_ids=['provider'], provider_permission_obtained=False,
                        upstream_provider='Synthetic provider', provider_content_authorization='not_established'),
                    'owner_distribution_decision': dict(self.action('accepted', 'provider-decision', owner=True),
                        risk_ids=['provider'], authorization_claimed=False, provider_authorization_exception={
                            'scope': 'repository_provider_authorization_gate_only', 'upstream_provider': 'Synthetic provider',
                            'addon_id': 'plugin.video.example', 'addon_version': version,
                            'package_sha256': value['package_sha256'], 'provider_authorization_verified': False,
                            'provider_terms_concern': 'Synthetic risks', 'owner_accepts_risk': True, 'expires_at': expiry}),
                    'disclosure': copy.deepcopy(notice),
                }
            prior_owner = old['unofficial_integration']['owner_distribution_decision']
            prior_owner['recorded_at'] = (now-timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
            old['approval_policy'] = contract.INITIAL_POLICY
            old['unresolved_risks'].insert(0, runtime_risk)
            old['owner_acknowledgment']['risk_ids'].append('runtime')
            old['compatibility']['omega'].update(runtime_accepted=False)
            old['compatibility']['omega']['runtime_test'].update(status='deferred', outstanding_tests=['legacy-branch'])
            proof = {'method':'native', 'status':'passed', 'scope':'Observed subset',
                     'evidence':[self.evidence('scoped-native')]}
            runtime = {'scope':'initial_release_runtime_coverage_only', 'addon_id':'plugin.video.example',
                'addon_version':'1.0.0', 'package_sha256':old['package_sha256'], 'source_commit':old['source_commit'],
                'lanes':['omega'], 'expires_at':expiry,
                'scenarios':[{'id':'legacy-branch','lane':'omega','description':'Unobserved branch',
                              'risk_id':'runtime','kind':'unobserved_functionality','observation':'not_observed',
                              'supporting_evidence':[proof]}],
                'owner_decision':dict(self.action('accepted', 'old-coverage-owner', owner=True),
                                      scenario_ids=['legacy-branch'], risk_ids=['runtime']),
                'independent_verification':dict(self.action('verified', 'old-coverage-review'),
                    scenario_ids=['legacy-branch'], risk_ids=['runtime'], no_known_security_defects=True,
                    core_evidence=[proof, dict(proof, method='offline')])}
            old['runtime_acceptance_exception'] = runtime
            old['release_decision'] = dict(self.action('approved', 'old-release', owner=True),
                                           runtime_exception_sha256=contract.exception_digest(runtime))

        old_bytes = repo.json_bytes(old)
        (self.root/'incoming/original-review.json').write_bytes(old_bytes)
        self.replace_review(0, dict(old, approval_lanes=[]), inputs)
        record['owner_acknowledgment'] = dict(self.action('acknowledged', 'ack', owner=True),
                                              risk_ids=[risk['id'] for risk in record['unresolved_risks']])
        record['compatibility']['omega'].update(static_accepted=True, runtime_accepted=False,
            evidence=[self.evidence('static')], runtime_test=dict(self.action('deferred', 'runtime'),
                platform='Synthetic Linux', kodi_version='21.3', scope='Exact successor changed routes only',
                outstanding_tests=['legacy-branch']))
        value = {'predecessor': {'version':'1.0.0','package_sha256':old['package_sha256'],
                                 'source_commit':old['source_commit'],
                                 'review_record':'original-review.json sha256:'+repo.sha(old_bytes)},
                 'lanes':['omega'], 'changed_files':['addon.xml','default.py'],
                 'qualification':[{'lane':'omega','kind':kind,'scope':'Changed or affected behavior',
                                   'evidence':[self.evidence(kind)],'unchanged_files':[]}
                                  for kind in ('native','regression')],
                 'deferred':[{'id':'legacy-branch','lane':'omega','description':'Unobserved branch','risk_id':'runtime',
                              'observation':'not_observed'}],
                 'observed':[{'id':'optional-compatibility','lane':'omega','description':'Observed optional value unavailable',
                              'status':'compatibility_limitation','evidence':[self.evidence('optional-limitation')]}],
                 'resolved':[], 'independent_review':self.action('verified', 'delta-review'),
                 'owner_decision':self.action('accepted', 'coverage-owner', owner=True), 'expires_at':expiry}
        record['incremental_alpha'] = value
        self.approve(record)
        self.replace_review(1, record, inputs)
        return record, inputs

    def reject(self, record, inputs, pattern=None, *, reseal=True):
        if reseal:
            self.approve(record)
        self.replace_review(1, record, inputs)
        for reader in (repo.production_packages, audit.reviewed_inputs):
            with self.subTest(consumer=reader.__module__):
                if pattern and reader is repo.production_packages:
                    with self.assertRaisesRegex(ValueError, pattern):
                        reader(repo.load_config(), 'production')
                else:
                    with self.assertRaises((ValueError, AssertionError)):
                        reader(repo.load_config(), 'production')

    def test_valid_successor_and_retention_through_production_consumers(self):
        record, _ = self.record(provider=True)
        report = qualify.qualify('production')
        plan = json.loads((self.root/'dist/production/release-plan.json').read_text())
        preflight = publication.site_audit(plan)
        self.assertEqual(preflight['approvals'], report['independent_audit']['approvals'])
        approval = next(item for item in preflight['approvals'] if item['package_sha256'] == record['package_sha256'])
        self.assertEqual(approval['runtime']['omega']['status'], 'deferred')
        self.assertFalse(approval['publication_authorized'])
        self.assertFalse(plan['publication_authorized'])
        self.assertFalse(report['publication_authorized'])
        self.assertIn('plugin.video.example-1.0.0', report['historical_versions_retained'])
        html = (self.root/'dist/production/site/index.html').read_text()
        self.assertIn('Observed optional value unavailable', html)
        self.assertIn('legacy-branch', html)
        self.assertNotIn(' sha256:', html)
        self.assertNotIn('delta-review', html)

    def test_strict_rights_successor_build_and_schema(self):
        record, _ = self.record()
        repo.build('production')
        self.assertEqual(audit.audit('production')['status'], 'PASS')
        if Draft202012Validator:
            schema = json.loads((Path(__file__).resolve().parents[1]
                                 /'docs/REVIEW-RECORD-SCHEMA.json').read_text())
            Draft202012Validator(schema).validate(record)

    def test_ineligible_predecessor_and_unreviewed_delta(self):
        initial, inputs = self.record()
        mutations = [
            ('predecessor review', lambda a: a['predecessor'].update(review_record='original-review.json sha256:'+'0'*64)),
            ('predecessor source', lambda a: a['predecessor'].update(source_commit='f'*40)),
            ('unique retained', lambda a: a['predecessor'].update(package_sha256='f'*64)),
            ('exact package delta', lambda a: a.update(changed_files=['addon.xml'])),
            ('missing changed-functionality', lambda a: a['qualification'].pop()),
        ]
        for pattern, change in mutations:
            candidate = copy.deepcopy(initial)
            change(candidate['incremental_alpha'])
            self.reject(candidate, inputs, pattern)

    def test_immediate_ledger_predecessor_required(self):
        record, inputs = self.record()
        ledger = self.root/'releases/manifest.json'
        ledger.write_bytes(repo.json_bytes({'schema':1,'packages':[]}))
        self.reject(record, inputs, 'immediate published')

    def test_evidence_reuse_requires_previous_lane_and_unchanged_members(self):
        original, inputs = self.record()
        value = original['incremental_alpha']
        proof = {'lane':'omega','kind':'reused','scope':'Unchanged static package subset',
                 'unchanged_files':['LICENSE.txt'],'evidence':[self.evidence('old-scoped-test')]}
        value['qualification'].append(proof)
        self.approve(original)
        self.replace_review(1, original, inputs)
        self.assertTrue(repo.production_packages(repo.load_config()))
        for field, replacement in [('unchanged_files', ['default.py']), ('evidence', [self.evidence('unreviewed')])]:
            candidate = copy.deepcopy(original)
            candidate['incremental_alpha']['qualification'][-1][field] = replacement
            self.reject(candidate, inputs, 'reused evidence')

    def test_cannot_remove_or_rename_inherited_deferrals_or_mislabel_failures(self):
        original, inputs = self.record(provider=True)
        for change, pattern in [
            (lambda a: a['deferred'].clear(), 'deferred scenario changed or omitted'),
            (lambda a: a['deferred'][0].update(description='A smaller scope'), 'deferred scenario changed'),
            (lambda a: a['observed'][0].update(id='legacy-branch'), 'invalid observed finding'),
            (lambda a: a['observed'][0].update(status='failed'), 'outstanding gates'),
            (lambda a: a['deferred'][0].update(observation='failed'), 'may be deferred'),
        ]:
            candidate = copy.deepcopy(original)
            change(candidate['incremental_alpha'])
            self.reject(candidate, inputs, pattern)

    def test_missing_expired_or_self_reviewed_owner_actions(self):
        original, inputs = self.record()
        for change, pattern in [
            (lambda a: a.update(owner_decision={'status':'pending'}), 'final approval must bind'),
            (lambda a: a.update(expires_at=self.now), 'final successor approval date'),
            (lambda a: a.update(independent_review={'status':'pending'}), 'outstanding gates'),
            (lambda a: a['independent_review'].update(actor='fixture-owner'), 'independent of owner'),
        ]:
            candidate = copy.deepcopy(original)
            change(candidate['incremental_alpha'])
            self.reject(candidate, inputs, pattern)

    def test_missing_or_predecessor_provider_consent_fails(self):
        original, inputs = self.record(provider=True)
        candidate = copy.deepcopy(original)
        candidate['unofficial_integration']['owner_distribution_decision'] = {'status':'pending'}
        self.reject(candidate, inputs, 'outstanding gates')
        candidate = copy.deepcopy(original)
        original_record = json.loads((self.root/'incoming/original-review.json').read_text())
        prior = original_record['unofficial_integration']['owner_distribution_decision']
        candidate['unofficial_integration']['owner_distribution_decision']['recorded_at'] = prior['recorded_at']
        self.reject(candidate, inputs, 'must be renewed')
        candidate = copy.deepcopy(original)
        candidate['unofficial_integration']['owner_distribution_decision']['provider_authorization_exception'][
            'package_sha256'] = original['incremental_alpha']['predecessor']['package_sha256']
        self.reject(candidate, inputs, 'artifact identity/checksum mismatch')

    def test_changed_evidence_and_final_admission_digest_fail(self):
        original, inputs = self.record()
        original['incremental_alpha']['observed'][0]['description'] += ' unapproved edit'
        self.reject(original, inputs, 'exact successor record', reseal=False)
        self.approve(original)
        (self.root/'incoming/native').write_bytes(b'some other evidence')
        self.reject(original, inputs, 'evidence digest mismatch')

    def test_altered_zip_is_rejected_before_admission(self):
        original, inputs = self.record()
        (self.root/'incoming/1.zip').write_bytes(b'replacement')
        self.reject(original, inputs, 'input checksum mismatch')

    def test_strict_policy_cannot_apply_incremental_fields(self):
        original, inputs = self.record()
        original['approval_policy'] = 'strict-v1'
        self.reject(original, inputs, 'explicit successor policy')
        original.pop('incremental_alpha')
        original['release_decision'].pop('successor_sha256')
        self.reject(original, inputs, 'outstanding gates', reseal=False)

    def test_preflight_reassesses_current_inputs_before_promotion(self):
        record, inputs = self.record()
        plan = repo.build('production')
        record['incremental_alpha']['owner_decision'] = {'status':'pending'}
        self.replace_review(1, record, inputs)
        with self.assertRaises(ValueError):
            publication.site_audit(plan)

    def test_independent_audit_rejects_concealed_observation_with_rehashed_site(self):
        self.record()
        repo.build('production')
        root = self.root/'dist/production'
        plan_path = root/'release-plan.json'
        plan = json.loads(plan_path.read_bytes())
        site = root/'site/index.html'
        site.write_bytes(site.read_bytes().replace(b'Observed optional value unavailable', b'Hidden observation'))
        plan['site_files']['index.html'] = repo.sha(site.read_bytes())
        plan['site_manifest_sha256'] = repo.sha(repo.json_bytes(plan['site_files']))
        plan_path.write_bytes(repo.json_bytes(plan))
        repo.verify('production')
        with self.assertRaises(AssertionError):
            publication.site_audit(plan)

    def test_new_lane_and_failed_runtime_cannot_use_scoped_approval(self):
        record, inputs = self.record()
        candidate = copy.deepcopy(record)
        candidate['compatibility']['omega']['runtime_test']['status'] = 'failed'
        self.reject(candidate, inputs, 'exact outstanding scenarios')
        candidate = copy.deepcopy(record)
        candidate['approval_lanes'] = inputs['packages'][1]['lanes'] = ['nexus']
        candidate['compatibility']['nexus'] = candidate['compatibility'].pop('omega')
        candidate['incremental_alpha']['lanes'] = ['nexus']
        self.reject(candidate, inputs, 'already be admitted')

    def test_contract_schema_retains_provider_and_strict_predecessor_records(self):
        if not Draft202012Validator:
            self.skipTest('jsonschema is optional')
        record, _ = self.record(provider=True)
        schema = json.loads((Path(__file__).resolve().parents[1]/'docs/REVIEW-RECORD-SCHEMA.json').read_text())
        validator = Draft202012Validator(schema)
        validator.validate(record)
        validator.validate(json.loads((self.root/'incoming/original-review.json').read_text()))
        record['approval_policy'] = contract.UNOFFICIAL_POLICY
        self.assertFalse(validator.is_valid(record))

    def test_next_successor_retains_admitted_history_and_verifies_resolved_scope(self):
        previous, inputs = self.record()
        raw = repo.json_bytes(previous)
        (self.root/'incoming/previous-review.json').write_bytes(raw)
        ledger = self.root/'releases/manifest.json'
        history = json.loads(ledger.read_text())
        history['packages'].append({'id':'plugin.video.example','version':'1.1.0','sha256':previous['package_sha256']})
        ledger.write_bytes(repo.json_bytes(history))
        current = copy.deepcopy(previous)
        current['source_commit'] = 'c'*40
        current['unresolved_risks'] = []
        current['owner_acknowledgment'] = {'status':'not_recorded'}
        accepted = current['compatibility']['omega']
        accepted['runtime_accepted'] = True
        accepted['runtime_test'].update(status='passed', outstanding_tests=[])
        value = current['incremental_alpha']
        value['predecessor'] = {'version':'1.1.0','package_sha256':previous['package_sha256'],
                                'source_commit':previous['source_commit'],
                                'review_record':'previous-review.json sha256:'+repo.sha(raw)}
        scope = value['deferred'].pop()
        value['resolved'] = [{k: scope[k] for k in ('id','lane','description')} |
                             {'evidence':value['qualification'][0]['evidence']}]
        _, files = repo.inspect_zip((self.root/'incoming/1.zip').read_bytes())
        files['default.py'] = b'# New synthetic implementation\n'
        inputs, zip_fields = self.admit(files, ['omega'], ver='1.2.0')
        current.update({k: zip_fields[k] for k in ('package_sha256','runtime_files')})
        self.approve(current)
        inputs['packages'][1]['lanes'] = []
        self.replace_review(1, dict(previous, approval_lanes=[]), inputs)
        self.replace_review(2, current, inputs)
        repo.build('production')
        audit.audit('production')
