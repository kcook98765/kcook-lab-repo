"""Synthetic v5 shape/control fixtures; never a real package approval or native receipt.

The exact source/ZIP constants exercise the closed rule only. The 1,806 dummy
file hashes do not represent an inspected archive. Actual byte qualification and
all real decisions remain outside these in-memory tests.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import approval_contract as contract
import audit_candidate as auditor
import original_assets as original
import test_skin_alpha as skin

NOW=datetime(2026,11,16,12,tzinfo=timezone.utc)
STAMP='2026-11-15T04:00:00Z'


class AuditClock(datetime):
    @classmethod
    def now(cls,tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


def action(status,owner=False,**extra):
    result=skin.action(status,owner,**extra)
    result['recorded_at']=STAMP
    result['rationale']='SYNTHETIC TEST ONLY: not real package admission, rights approval or native acceptance'
    if owner:result['actor']='kcook98765'
    return result


def material_record(final=False):
    record=skin.skin_record()
    def update_actions(value):
        if isinstance(value,dict):
            if 'recorded_at' in value:
                value['recorded_at']=STAMP
                value['rationale']='SYNTHETIC fixture only; no actual package approval or runtime testing'
                if value.get('role')=='owner':value['actor']='kcook98765'
            for child in value.values():update_actions(child)
        elif isinstance(value,list):
            for child in value:update_actions(child)
    update_actions(record)
    request=json.loads((original.ROOT/original.POLICY_FILE).read_text())
    receipt=json.loads((original.ROOT/original.APPROVAL_FILE).read_text())
    record.update(schema_version=5,approval_policy=original.POLICY,
        source_repository='https://github.com/kcook98765/skin.aura',source_commit=original.SOURCE_COMMIT,
        package_sha256=original.PACKAGE_SHA256,rights_approved=False,rights_review={'status':'pending'},
        runtime_files={'addon.xml':'d'*64,**{f'synthetic/{i:04d}.txt':'d'*64 for i in range(1805)}})
    rights=copy.deepcopy(request['proposed_policy_change']['rights_risks_must_remain_unresolved'])
    record['unresolved_risks']=rights+record['unresolved_risks']
    record['owner_acknowledgment']['risk_ids']=[r['id'] for r in record['unresolved_risks']]
    value=record['skin_alpha_evidence'];value.update(addon_id='skin.aura',source_commit=original.SOURCE_COMMIT,
        package_sha256=original.PACKAGE_SHA256,expires_at=original.EXPIRY)
    value['owner_native_use']['addon_id']='skin.aura'
    technical={'id':'STATIC-SCREENSHOTS','status':'accepted_unofficial_distribution_limitation',
        'official_checker_status':'failed','official_checker_errors':5,'official_checker_warnings':3,
        'toolkit_overall_passed':False,'original_dimensions':'1366x768',
        'paths':[f'resources/screenshot-{i:02d}.jpg' for i in range(1,6)],
        'evidence':[original.VALIDATION_REF,original.DISPOSITION_REF]}
    record['original_assets_admission']={'scope':'exact_original_assets_aura_alpha_admission_only',
        'addon_id':'skin.aura','addon_version':'2.1.0','source_commit':original.SOURCE_COMMIT,
        'package_sha256':original.PACKAGE_SHA256,'lanes':['omega'],'destination':copy.deepcopy(original.DESTINATION),
        'expires_at':original.EXPIRY,'policy_request_sha256':original.REQUEST_SHA256,
        'owner_policy_decision':dict(action('approved',True,policy_request_sha256=original.REQUEST_SHA256),
            recorded_at=receipt['recorded_at'],evidence=[original.POLICY_FILE+' sha256:'+original.REQUEST_SHA256,
                original.APPROVAL_FILE+' sha256:'+original.APPROVAL_SHA256]),
        'independent_review':dict(action('verified',scope='retained_material_findings_and_policy_implementation_only',
            risk_ids=[r['id'] for r in rights],rights_verified=False,permissions_granted=False,
            implementation_verified=True,findings_retained=True),role='independent_reviewer'),
        'technical_findings':technical}
    if final:
        record['release_approved']=True
        record['release_decision']=action('approved',True,
            skin_alpha_evidence_sha256=contract.exception_digest(value),
            original_assets_admission_sha256=contract.exception_digest(record['original_assets_admission']))
    return record


def inspected_manifest():
    root=skin.manifest();root.set('id','skin.aura');return root


def actual_config():
    return {'github_repository':original.DESTINATION['github_repository'],
        'github_repository_id':original.DESTINATION['github_repository_id'],
        'base_url':original.DESTINATION['pages_url'],'addon_id':original.DESTINATION['repository_addon_id']}


class OriginalAssetsTests(unittest.TestCase):
    def setUp(self):
        for item in (patch.object(contract,'utc_now',return_value=NOW),patch.object(auditor,'datetime',AuditClock)):
            item.start();self.addCleanup(item.stop)

    def assess(self,record,history=None):
        return contract.assess(record,['omega'],('skin.aura','2.1.0'),[] if history is None else history,inspected_manifest())

    def evaluate(self,record,identity=('skin.aura','2.1.0'),lanes=None,now=NOW):
        return original.evaluate(record,identity,['omega'] if lanes is None else lanes,inspected_manifest(),[],now)

    def test_exact_policy_pins_and_truthful_synthetic_result(self):
        for name,digest in [(original.POLICY_FILE,original.REQUEST_SHA256),(original.APPROVAL_FILE,original.APPROVAL_SHA256)]:
            self.assertEqual(hashlib.sha256((original.ROOT/name).read_bytes()).hexdigest(),digest)
        record=material_record();result=self.assess(record)
        self.assertTrue(result['original_assets_policy_active']);self.assertTrue(result['skin_alpha_policy_active'])
        self.assertEqual(result['material_rights_admission'],'owner_directed_exact_package_exception')
        self.assertFalse(result['rights_approved']);self.assertEqual(result['rights_status'],'pending')
        self.assertFalse(result['third_party_permission_established']);self.assertFalse(result['cleaned_package_native_accepted'])
        self.assertEqual(result['accepted_technical_findings']['official_checker_status'],'failed')
        self.assertEqual(result['accepted_technical_findings']['official_checker_errors'],5)
        self.assertEqual(result['release_blockers'],['release_approved'])
        self.assertEqual(len([r for r in result['unresolved_risks'] if r['category']=='rights']),5)
        self.assertEqual(self.assess(material_record(True))['release_blockers'],[])
        self.assertFalse(result['publication_authorized'])

    def test_pending_independent_policy_coverage_ack_or_final_decision_stays_blocked(self):
        for field in ('independent_review','owner_coverage_decision','owner_acknowledgment','release_decision'):
            record=material_record()
            if field=='independent_review':record['original_assets_admission'][field]={'status':'pending'}
            elif field=='owner_coverage_decision':record['skin_alpha_evidence'][field]={'status':'pending'}
            elif field=='owner_acknowledgment':record[field]={'status':'not_recorded'}
            with self.subTest(field=field):
                result=self.assess(record)
                self.assertTrue(result['release_blockers'])
                if field!='release_decision':self.assertFalse(result['package_distribution_eligible'])
                self.assertFalse(record['release_approved'])

    def test_wrong_identity_source_zip_inventory_and_destination_reject_both_gates(self):
        for field,value in [('source_commit','0'*40),('package_sha256','0'*64),
                            ('source_repository','https://github.com/other/skin.aura')]:
            record=material_record();record[field]=value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):self.evaluate(record)
                with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        record=material_record();record['runtime_files'].pop('addon.xml')
        with self.assertRaises(ValueError):self.evaluate(record)
        with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        for field,value in [('github_repository','other/repository'),('github_repository_id',1),
                            ('pages_url','https://evil.invalid/'),('repository_addon_id','repository.other')]:
            record=material_record();record['original_assets_admission']['destination'][field]=value
            with self.subTest(destination=field):
                with self.assertRaises(ValueError):self.evaluate(record)
                with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        cfg=actual_config();cfg['github_repository_id']=1
        with self.assertRaises(ValueError):original.destination(cfg)
        with self.assertRaises(AssertionError):auditor.original_assets_gate(material_record(),cfg)
        for identity,lanes in [(('skin.other','2.1.0'),['omega']),(('skin.aura','2.1.1'),['omega']),
                               (('skin.aura','2.1.0'),['nexus']),(('skin.aura','2.1.0'),['omega','piers'])]:
            with self.assertRaises(ValueError):self.evaluate(material_record(),identity,lanes)

    def test_every_complete_rights_finding_stays_unchanged(self):
        original_record=material_record()
        for i in range(5):
            for mutation in ('drop','description','evidence','category'):
                record=copy.deepcopy(original_record)
                if mutation=='drop':record['unresolved_risks'].pop(i)
                elif mutation=='description':record['unresolved_risks'][i]['description']='Cleared by owner'
                elif mutation=='evidence':record['unresolved_risks'][i]['evidence']=[skin.REF]
                else:record['unresolved_risks'][i]['category']='runtime'
                with self.subTest(finding=i,mutation=mutation):
                    with self.assertRaises(ValueError):self.evaluate(record)
                    with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        record=material_record();record['unresolved_risks'][:5]=list(reversed(record['unresolved_risks'][:5]))
        with self.assertRaises(ValueError):self.evaluate(record)

    def test_rights_or_permission_claims_are_never_supplied_by_policy_acceptance(self):
        for field,value in [('rights_approved',True),('rights_review',skin.action('verified'))]:
            record=material_record();record[field]=value
            with self.assertRaises(ValueError):self.evaluate(record)
            with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        for field,value in [('rights_verified',True),('permissions_granted',True),
                            ('findings_retained',False),('implementation_verified',False),('actor','kcook98765')]:
            record=material_record();record['original_assets_admission']['independent_review'][field]=value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):self.evaluate(record)
                with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())

    def test_closed_scope_pinned_owner_approval_and_fixed_expiry(self):
        for field,value in [('scope','all_original_assets'),('policy_request_sha256','0'*64),
                            ('expires_at','2099-01-01T00:00:00Z'),('lanes',['omega','nexus']),('unknown',True)]:
            record=material_record();record['original_assets_admission'][field]=value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):self.evaluate(record)
                with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        for field,value in [('actor','synthetic-owner'),('recorded_at',STAMP),('policy_request_sha256','0'*64),('evidence',[skin.REF])]:
            record=material_record();record['original_assets_admission']['owner_policy_decision'][field]=value
            with self.assertRaises(ValueError):self.evaluate(record)
            with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        active,_,_=self.evaluate(material_record(),now=datetime(2026,12,16,tzinfo=timezone.utc));self.assertFalse(active)
        record=material_record();record['skin_alpha_evidence']['expires_at']='2026-12-16T00:00:00Z'
        with self.assertRaises(ValueError):self.evaluate(record)
        with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())

    def test_policy_and_approval_file_changes_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            for name in (original.POLICY_FILE,original.APPROVAL_FILE):
                p=base/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((original.ROOT/name).read_bytes())
            with patch.object(original,'ROOT',base):
                for name in (original.POLICY_FILE,original.APPROVAL_FILE):
                    p=base/name;raw=p.read_bytes();p.write_bytes(raw+b' ')
                    with self.assertRaisesRegex(ValueError,'frozen policy/approval'):self.evaluate(material_record_from_constants())
                    p.write_bytes(raw)

    def test_future_policy_review_and_fixture_identity_do_not_activate_real_admission(self):
        record=material_record();record['original_assets_admission']['independent_review']['recorded_at']='2026-11-17T04:00:00Z'
        self.assertFalse(self.evaluate(record)[0])
        with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())
        record=material_record();record['fixture_only']=True
        with self.assertRaises(ValueError):self.evaluate(record)
        with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())

    @unittest.skipIf(skin.Draft202012Validator is None,'Optional jsonschema unavailable')
    def test_schema_five_closed_route_and_no_old_version_field_smuggling(self):
        schema=json.loads((original.ROOT/'docs/REVIEW-RECORD-SCHEMA.json').read_text())
        validator=skin.Draft202012Validator(schema)
        validator.validate(material_record())
        validator.validate(material_record(True))
        for version in (1,2,3,4):
            record=material_record();record['schema_version']=version
            with self.subTest(version=version):self.assertFalse(validator.is_valid(record))
        record=material_record();record['original_assets_admission']['unknown_permission']=True
        self.assertFalse(validator.is_valid(record))

    def test_original_failed_checker_results_and_all_five_screenshots_remain_disclosed(self):
        for field,value in [('official_checker_status','passed'),('official_checker_errors',0),
                            ('official_checker_warnings',0),('official_checker_errors',True),('official_checker_warnings',True),('toolkit_overall_passed',True),
                            ('original_dimensions','1920x1080'),('paths',[]),('evidence',[skin.REF])]:
            record=material_record();record['original_assets_admission']['technical_findings'][field]=value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):self.evaluate(record)
                with self.assertRaises(AssertionError):auditor.original_assets_gate(record,actual_config())

    def test_old_versions_cannot_use_this_exact_material_exception(self):
        for version in (1,2,3,4):
            record=material_record();record['schema_version']=version
            with self.subTest(version=version),self.assertRaises(ValueError):self.assess(record)
        record=material_record();record['approval_policy']=contract.SKIN_ALPHA_POLICY
        with self.assertRaises(ValueError):self.assess(record)
        ordinary=skin.skin_record()
        result=contract.assess(ordinary,['omega'],('skin.example','2.1.0'),[],skin.manifest())
        self.assertEqual(result['rights_status'],'verified');self.assertTrue(result['package_distribution_eligible'])
        ordinary.update(rights_approved=False,rights_review={'status':'pending'})
        self.assertFalse(contract.assess(ordinary,['omega'],('skin.example','2.1.0'),[],skin.manifest())['package_distribution_eligible'])

    def test_final_owner_package_decision_binds_both_complete_evidence_objects(self):
        record=material_record(True);self.assertEqual(self.assess(record)['release_blockers'],[])
        for field in ('skin_alpha_evidence_sha256','original_assets_admission_sha256'):
            changed=copy.deepcopy(record);changed['release_decision'][field]='0'*64
            with self.subTest(field=field),self.assertRaises(ValueError):self.assess(changed)
        changed=copy.deepcopy(record);changed['skin_alpha_evidence']['owner_native_use']['duration']='Changed owner report'
        with self.assertRaises(ValueError):self.assess(changed)
        changed=copy.deepcopy(record);changed['original_assets_admission']['independent_review']['rationale']='Altered review'
        with self.assertRaises(ValueError):self.assess(changed)
        with self.assertRaises(AssertionError):auditor.original_assets_gate(changed,actual_config())

    def test_independent_gate_rejects_unsafe_material_fields_under_permissive_shared_assess(self):
        record=material_record(True)
        permissive=self.assess(record)
        with patch.object(contract,'assess',return_value=permissive):
            for field,value in [('rights_verified',True),('permissions_granted',True),('risk_ids',[])]:
                unsafe=copy.deepcopy(record);unsafe['original_assets_admission']['independent_review'][field]=value
                with self.subTest(field=field),self.assertRaises(AssertionError):auditor.original_assets_gate(unsafe,actual_config())
        self.assertEqual(auditor.original_assets_gate(record,actual_config())[0]['status'],'approved')


# Build before a temporary policy-root patch so a deliberately corrupted policy
# file is never used to populate the fixture's expected findings.
def material_record_from_constants():
    return copy.deepcopy(_POLICY_ROOT_FIXTURE)


_POLICY_ROOT_FIXTURE=material_record()

if __name__=='__main__':unittest.main()
