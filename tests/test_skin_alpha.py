"""Synthetic skin-alpha attestations; never real native or owner decisions."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import approval_contract as contract
try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

NOW = datetime(2026, 11, 15, 12, tzinfo=timezone.utc)
REF = 'evidence/synthetic.txt sha256:' + 'e' * 64


def action(status, owner=False, **extra):
    return {'status': status, 'actor': 'synthetic-owner' if owner else 'synthetic-independent-reviewer',
            'role': 'owner' if owner else 'reviewer', 'recorded_at': '2026-11-15T10:00:00Z',
            'rationale': 'Synthetic decision only; no real approval or testing', 'evidence': [REF], **extra}


def manifest():
    return ET.fromstring('<addon id="skin.example" version="2.1.0"><requires>'
        '<import addon="xbmc.gui" version="5.17.0"/></requires>'
        '<extension point="xbmc.gui.skin"/><extension point="xbmc.addon.metadata"/></addon>')


def skin_record(final=False):
    support = lambda method, status: {'method': method, 'status': status,
        'scope': 'Synthetic scoped evidence, not runtime test acceptance', 'evidence': [REF]}
    scenarios = [
        {'id': 'unobserved', 'lane': 'omega', 'risk_id': 'coverage',
         'kind': 'unobserved_functionality', 'observation': 'not_observed',
         'description': 'Synthetic PVR function not formally observed',
         'supporting_evidence': [support('offline', 'passed')]},
        {'id': 'layout', 'lane': 'omega', 'risk_id': 'layout-risk',
         'kind': 'cosmetic_layout_limitation', 'observation': 'owner_reported_minor_layout',
         'description': 'Owner reports minor cosmetic layout adjustments remain',
         'supporting_evidence': [support('owner_reported', 'reported_minor_layout')]},
    ]
    ids = ['unobserved', 'layout']; risks = ['coverage', 'layout-risk']
    record = {'schema_version': 4, 'approval_policy': contract.SKIN_ALPHA_POLICY,
        'approval_lanes': ['omega'], 'package_sha256': 'a'*64,
        'source_repository': 'https://github.com/synthetic/skin.example', 'source_commit': 'b'*40,
        'runtime_files': {'addon.xml': 'c'*64}, 'fixture_only': False,
        'rights_approved': True, 'rights_review': action('verified'),
        'technical_release': action('approved'), 'release_approved': False,
        'release_decision': {'status': 'pending'},
        'owner_acknowledgment': action('acknowledged', True, risk_ids=risks),
        'unresolved_risks': [{'id': rid, 'category': 'runtime', 'description': rid,
                              'evidence': [REF]} for rid in risks],
        'compatibility': {'omega': {'static_accepted': True, 'runtime_accepted': False,
            'evidence': [REF], 'runtime_test': action('deferred', platform='Synthetic unspecified production platform',
                kodi_version='21 Omega; exact patch unverified', scope='Owner general-use report plus static delta; no formal scenarios',
                outstanding_tests=ids)}},
    }
    value = {'scope': 'initial_release_skin_alpha_coverage_only', 'addon_id': 'skin.example',
        'addon_version': '2.1.0', 'package_sha256': record['package_sha256'],
        'source_commit': record['source_commit'], 'lanes': ['omega'], 'expires_at': '2026-12-15T10:00:00Z',
        'owner_native_use': action('owner_reported', True, addon_id='skin.example',
            reported_version='Omega 2.1.0 development candidate, identity subject to verification',
            kodi_major=21, platform='Existing production Omega; OS/patch unverified',
            duration='More than one week of normal daily use', result='stable_regular_use',
            known_limitations=['Minor cosmetic layout adjustments remain'], formal_scripted_acceptance=False,
            cleaned_package_native_accepted=False, identity_disposition='unverified',
            installed_package_sha256=None, identity_limitation='Installed files not inspected; cleaned ZIP changes reviewed statically'),
        'reviewed_package_delta': action('verified', scope='Synthetic full source/package/assets/static delta comparison',
            source_provenance_verified=True, no_known_security_defects=True,
            no_known_functionality_failures=True, static_package_evidence=[REF]),
        'scenarios': scenarios,
        'owner_coverage_decision': action('accepted', True, scenario_ids=ids, risk_ids=risks,
            accepts_unverified_installed_identity=True, acknowledges_package_delta=True),
        'independent_verification': action('verified', scenario_ids=ids, risk_ids=risks,
            no_known_security_defects=True, no_known_functionality_failures=True, owner_report_scope_verified=True)}
    record['skin_alpha_evidence'] = value
    if final:
        record['release_approved'] = True
        record['release_decision'] = action('approved', True,
            skin_alpha_evidence_sha256=contract.exception_digest(value))
    return record


class SkinAlphaTests(unittest.TestCase):
    def setUp(self):
        self.clock = patch.object(contract, 'utc_now', return_value=NOW)
        self.clock.start(); self.addCleanup(self.clock.stop)

    def assess(self, record, history=None, inspected=True):
        return contract.assess(record, ['omega'], ('skin.example', '2.1.0'),
            [] if history is None else history, package_manifest=manifest() if inspected else None)

    def test_owner_use_with_reviewed_delta_is_eligible_but_final_package_decision_separate(self):
        record = skin_record(); report = self.assess(record)
        self.assertTrue(report['skin_alpha_policy_active'])
        self.assertTrue(report['package_distribution_eligible'])
        self.assertEqual(report['release_blockers'], ['release_approved'])
        self.assertEqual(report['skin_alpha_admission'], 'owner_reported_use_with_reviewed_distribution_delta')
        self.assertEqual(report['runtime']['omega']['status'], 'deferred')
        self.assertFalse(report['cleaned_package_native_accepted'])
        self.assertFalse(report['publication_authorized'])
        self.assertTrue(report['rights_approved'])
        self.assertEqual(report['skin_alpha_evidence'], record['skin_alpha_evidence'])
        self.assertEqual(self.assess(skin_record(True))['release_blockers'], [])

    def test_pending_real_decisions_do_not_become_accepted_through_policy_setup(self):
        for field in ('owner_coverage_decision', 'independent_verification', 'reviewed_package_delta'):
            record = skin_record(); record['skin_alpha_evidence'][field] = {'status': 'pending'}
            with self.subTest(field=field):
                result = self.assess(record); self.assertFalse(result['package_distribution_eligible'])
                self.assertFalse(result['skin_alpha_policy_active'])
        for field in ('rights_review', 'technical_release'):
            record = skin_record(); record[field] = {'status': 'pending'}
            if field == 'rights_review': record['rights_approved'] = False
            with self.subTest(field=field): self.assertFalse(self.assess(record)['package_distribution_eligible'])

    def test_skin_manifest_and_exact_omega_identity_required(self):
        with self.assertRaisesRegex(ValueError, 'inspected skin'): self.assess(skin_record(), inspected=False)
        for mutate in [lambda m:m.set('id', 'script.fake'),
                       lambda m:m.find('extension').set('point', 'xbmc.python.script'),
                       lambda m:m.find('requires/import').set('version', '5.16.0')]:
            record = skin_record(); m = manifest(); mutate(m)
            with self.assertRaises(ValueError): contract.assess(record,['omega'],('skin.example','2.1.0'),[],m)
        for key, value in [('source_commit','0'*40),('package_sha256','0'*64),('addon_version','2.1.1'),
                           ('lanes',['omega','nexus']),('scope','all_releases')]:
            record=skin_record(); record['skin_alpha_evidence'][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): self.assess(record)

    def test_report_cannot_turn_unknown_installed_files_into_exact_package_or_test_pass(self):
        for key, value in [('formal_scripted_acceptance',True),('cleaned_package_native_accepted',True),
                           ('status','passed'),('identity_disposition','verified'),('installed_package_sha256','a'*64)]:
            record=skin_record();record['skin_alpha_evidence']['owner_native_use'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): self.assess(record)
        record=skin_record();record['skin_alpha_evidence']['owner_coverage_decision']['accepts_unverified_installed_identity']=False
        with self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['skin_alpha_evidence']['owner_native_use'].update(
            identity_disposition='verified',installed_package_sha256='a'*64)
        record['skin_alpha_evidence']['owner_coverage_decision']['accepts_unverified_installed_identity']=False
        self.assertTrue(self.assess(record)['skin_alpha_policy_active'])

    def test_known_functionality_or_security_failure_never_admitted(self):
        for field in ('reviewed_package_delta','independent_verification'):
            for flag in ('no_known_functionality_failures','no_known_security_defects'):
                record=skin_record();record['skin_alpha_evidence'][field][flag]=False
                with self.subTest(field=field,flag=flag),self.assertRaises(ValueError):self.assess(record)
        for kind, observation in [('failed_functionality','failed'),('unobserved_functionality','passed')]:
            record=skin_record();record['skin_alpha_evidence']['scenarios'][0].update(kind=kind,observation=observation)
            with self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['compatibility']['omega']['runtime_test']['status']='failed'
        with self.assertRaises(ValueError):self.assess(record)

    def test_all_risks_scenarios_and_reported_cosmetic_limitations_remain_visible(self):
        for mutate in [lambda r:r['skin_alpha_evidence']['scenarios'].pop(),
            lambda r:r['compatibility']['omega']['runtime_test']['outstanding_tests'].pop(),
            lambda r:r['unresolved_risks'].append({'id':'hidden','category':'runtime','description':'hidden','evidence':[REF]}),
            lambda r:r['skin_alpha_evidence']['scenarios'][1].update(kind='unobserved_functionality',observation='not_observed')]:
            record=skin_record();mutate(record)
            with self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['unresolved_risks'].append({'id':'unresolved-rights','category':'rights','description':'No permission','evidence':[REF]})
        with self.assertRaises(ValueError):self.assess(record)

    def test_independence_acknowledgment_and_hash_pins_required(self):
        for field in ('reviewed_package_delta','independent_verification'):
            record=skin_record();record['skin_alpha_evidence'][field]['actor']='SYNTHETIC-OWNER'
            with self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['owner_acknowledgment']={'status':'not_recorded'}
        self.assertFalse(self.assess(record)['skin_alpha_policy_active'])
        record=skin_record();record['skin_alpha_evidence']['owner_native_use']['evidence']=['unbound']
        with self.assertRaises(ValueError):self.assess(record)

    def test_initial_history_expiry_future_actions_and_final_binding(self):
        record=skin_record()
        prior=[{'id':'skin.example','version':'2.0.0','sha256':'f'*64}]
        self.assertFalse(self.assess(record,prior)['skin_alpha_policy_active'])
        prior=[{'id':'skin.example','version':'2.1.0','sha256':'a'*64}]
        self.assertTrue(self.assess(record,prior)['skin_alpha_policy_active'])
        for expiry in ('2026-11-15T11:00:00Z','2027-11-15T10:00:00Z','2026-02-30T10:00:00Z'):
            record=skin_record();record['skin_alpha_evidence']['expires_at']=expiry
            with self.subTest(expiry=expiry):
                try:self.assertFalse(self.assess(record)['skin_alpha_policy_active'])
                except ValueError:pass
        record=skin_record();record['skin_alpha_evidence']['owner_coverage_decision']['recorded_at']='2026-11-16T10:00:00Z'
        self.assertFalse(self.assess(record)['skin_alpha_policy_active'])
        record=skin_record(True);record['skin_alpha_evidence']['owner_native_use']['duration']='Changed duration'
        with self.assertRaisesRegex(ValueError,'bind exact'):self.assess(record)

    def test_policy_fields_cannot_be_smuggled_into_existing_versions(self):
        for version in (1,2,3):
            record=skin_record();record['schema_version']=version
            with self.subTest(version=version),self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['unofficial_integration']={}
        with self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['runtime_acceptance_exception']={}
        with self.assertRaises(ValueError):self.assess(record)

    @unittest.skipIf(Draft202012Validator is None, "Optional jsonschema interchange qualification unavailable")
    def test_interchange_schema_accepts_v4_and_rejects_version_downgrade(self):
        schema = json.loads((Path(__file__).parents[1] / 'docs/REVIEW-RECORD-SCHEMA.json').read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(skin_record())
        validator.validate(skin_record(True))
        for version in (1, 2, 3):
            record = skin_record(); record['schema_version'] = version
            self.assertFalse(validator.is_valid(record))
        record = skin_record(); record['skin_alpha_evidence']['owner_native_use']['formal_scripted_acceptance'] = True
        self.assertFalse(validator.is_valid(record))
        record = skin_record(); record['skin_alpha_evidence']['unexpected'] = True
        self.assertFalse(validator.is_valid(record))

    def test_closed_evidence_fields_and_no_invented_native_scenario_support(self):
        original=skin_record()
        for key in original['skin_alpha_evidence']:
            record=copy.deepcopy(original);del record['skin_alpha_evidence'][key]
            with self.subTest(missing=key),self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['skin_alpha_evidence']['unknown']=True
        with self.assertRaises(ValueError):self.assess(record)
        record=skin_record();record['skin_alpha_evidence']['scenarios'][0]['supporting_evidence'][0]['method']='native'
        with self.assertRaises(ValueError):self.assess(record)


if __name__=='__main__':unittest.main()
