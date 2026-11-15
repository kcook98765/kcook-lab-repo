"""Synthetic all-consumer Aura admission controls; no owner/native release evidence."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import test_intake as intake
import test_skin_alpha as skin
import approval_contract as contract
import repository as repo
import audit_candidate as auditor
import check_publication as publication
import official_omega
import qualify


class AuraAdmissionTests(unittest.TestCase):
    setUp = intake.IntakeTests.setUp
    admit = intake.IntakeTests.admit

    def files(self):
        manifest = ET.fromstring('''<addon id="skin.aura" version="2.1.0" name="Aura Alpha" provider-name="Synthetic tests">
          <requires><import addon="xbmc.gui" version="5.17.0"/><import addon="script.synthetic" version="1.2.0"/></requires>
          <extension point="xbmc.gui.skin"><res default="true" folder="1080i" width="1920" height="1080"/></extension>
          <extension point="xbmc.addon.metadata"><summary>Omega alpha fixture</summary><description>Synthetic skin only</description>
            <platform>all</platform><license>MIT</license><assets><icon>resources/icon.png</icon></assets></extension></addon>''')
        return {'addon.xml':repo.xml_bytes(manifest),'1080i/Home.xml':b'<window/>',
                'LICENSE.txt':b'MIT\n','resources/icon.png':b'synthetic artwork'}

    def setup_skin(self, profile='production', pending=False):
        _, old = self.admit(files=self.files(),lanes=['omega'],profile=profile)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.stamp = (self.now-timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        evidence = b'Synthetic pinned source/package/owner-use statements. No actual native or owner approval.\n'
        self.evidence_path=self.root/'incoming/evidence/private-synthetic.txt'
        self.evidence_path.parent.mkdir();self.evidence_path.write_bytes(evidence)
        reference='evidence/private-synthetic.txt sha256:'+repo.sha(evidence)
        record=skin.skin_record(final=True)
        def adjust(value):
            if isinstance(value,dict):
                for k,v in value.items():
                    if k=='recorded_at':value[k]=self.stamp
                    elif k in ('evidence','static_package_evidence'):value[k]=[reference]
                    else:adjust(v)
            elif isinstance(value,list):
                for child in value:adjust(child)
        adjust(record)
        record.update(package_sha256=old['package_sha256'],runtime_files=old['runtime_files'],
                      source_repository='https://github.com/kcook98765/skin.aura')
        value=record['skin_alpha_evidence'];value.update(addon_id='skin.aura',package_sha256=old['package_sha256'],
            expires_at=(self.now+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        value['owner_native_use']['addon_id']='skin.aura'
        if pending:
            record['owner_acknowledgment']={'status':'not_recorded'}
            value['owner_coverage_decision']={'status':'pending'}
            record.update(release_approved=False,release_decision={'status':'pending'})
        self.save_record(record,profile)
        snapshot=b'''<addons><addon id="script.synthetic" version="1.2.0+matrix.1"><requires>
            <import addon="xbmc.python" version="3.0.1"/></requires>
            <extension point="xbmc.addon.metadata"><platform>all</platform></extension></addon></addons>'''
        self.snapshot_path=self.root/'incoming/omega-addons.xml';self.snapshot_path.write_bytes(snapshot)
        self.spec={'official_omega':{'schema':1,'source_url':official_omega.SOURCE_URL,'snapshot':'omega-addons.xml',
            'snapshot_sha256':repo.sha(snapshot),'retrieved_at':self.stamp,
            'expires_at':(self.now+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'core_commit':official_omega.CORE_COMMIT,'allowlist':{'script.synthetic':'1.2.0+matrix.1'},
            'roots':{'skin.aura':{'version':'2.1.0','package_sha256':record['package_sha256'],
                                  'source_commit':record['source_commit']}}}}
        p=self.root/f'config/{profile}.json';inputs=json.loads(p.read_text());inputs['external_dependencies']=self.spec
        p.write_bytes(repo.json_bytes(inputs))
        return record

    def save_record(self,record,profile='production',seal=True):
        if seal and record['release_approved'] and 'skin_alpha_evidence' in record:
            record['release_decision']['skin_alpha_evidence_sha256']=contract.exception_digest(record['skin_alpha_evidence'])
        raw=repo.json_bytes(record);(self.root/'incoming/0.json').write_bytes(raw)
        p=self.root/f'config/{profile}.json';inputs=json.loads(p.read_text());inputs['packages'][0]['review_record_sha256']=repo.sha(raw)
        p.write_bytes(repo.json_bytes(inputs))

    def load_plan(self,profile='production'):
        return json.loads((self.root/f'dist/{profile}/release-plan.json').read_text())

    def candidate_context(self):
        config=json.loads((self.root/'config/repository.json').read_text());task='c'*32
        config.update(addon_id='repository.ai.kodi.candidate.'+task,base_url='https://candidate.invalid/synthetic-aura/',
            candidate_context={'task_id':task,
                'production_config_sha256':repo.sha((self.root/'config/repository.json').read_bytes()),
                'production_ledger_sha256':repo.sha((self.root/'releases/manifest.json').read_bytes())})
        (self.root/'config/candidate-repository.json').write_bytes(repo.json_bytes(config))
        (self.root/'releases/candidate-manifest.json').write_bytes(repo.json_bytes(
            {'schema':1,'repository_id':config['addon_id'],'packages':[]}))
        for name,data in repo.installer(config,'candidate').items():
            target=self.root/'packages'/config['addon_id']/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)

    def test_approved_synthetic_skin_official_dependencies_all_consumers_agree(self):
        record=self.setup_skin();repo.build('production');repo.verify('production')
        plan=self.load_plan();audit=auditor.audit('production');qualification=qualify.qualify('production')
        public=publication.site_audit(self.load_plan())
        expected=next(p['approval'] for p in plan['packages'] if p['id']=='skin.aura')
        self.assertEqual(expected,audit['approvals'][0]);self.assertEqual(expected,qualification['independent_audit']['approvals'][0])
        self.assertEqual(expected,public['approvals'][0]);self.assertEqual(expected['runtime']['omega']['status'],'deferred')
        self.assertTrue(expected['skin_alpha_policy_active']);self.assertFalse(expected['cleaned_package_native_accepted'])
        self.assertFalse(plan['publication_authorized']);self.assertEqual(plan['remote_actions_executed'],[])
        self.assertTrue(qualification['whole_site_reproducible']);self.assertFalse(qualification['url_validation']['kodi_runtime_tested'])
        external=plan['catalogs']['omega']['official_dependencies'];self.assertTrue(external['active'])
        self.assertEqual(external['external_versions'],{'script.synthetic':'1.2.0+matrix.1'})
        for lane in ('matrix','nexus','piers'):
            self.assertNotIn('skin.aura',plan['catalogs'][lane]['ids'])
            self.assertFalse(plan['catalogs'][lane]['official_dependencies']['active'])
        page=(self.root/'dist/production/site/index.html').read_text()
        self.assertIn('owner_reported_general_use',page);self.assertIn('unverified',page)
        self.assertIn('reviewed_package_delta',page);self.assertIn('Synthetic full source/package/assets/static delta comparison',page)
        self.assertIn('verified',page);self.assertIn('owner_reported_minor_layout',page)
        self.assertNotIn('evidence/private-synthetic.txt',page);self.assertNotIn(str(self.root),page)
        self.assertEqual(expected['skin_alpha_evidence'],record['skin_alpha_evidence'])

    def test_pending_owner_candidate_identity_qualifies_structurally_and_stays_blocked(self):
        record=self.setup_skin('candidate',pending=True);self.candidate_context()
        repo.build('candidate');repo.verify('candidate');result=auditor.audit('candidate');plan=self.load_plan('candidate')
        self.assertTrue(result['release_blockers']);self.assertFalse(result['approvals'][0]['package_distribution_eligible'])
        self.assertEqual(result['approvals'][0]['owner_acknowledgment'],{'status':'not_recorded'})
        self.assertEqual(result['approvals'][0]['skin_alpha_evidence']['owner_coverage_decision'],{'status':'pending'})
        self.assertIn('repository.ai.kodi.candidate.'+'c'*32, {p['id'] for p in plan['packages']})
        self.assertFalse((self.root/'dist/production').exists())
        with self.assertRaises(ValueError):publication.site_audit(plan)

    def test_mutated_retained_evidence_and_official_snapshot_fail_fresh_rechecks(self):
        self.setup_skin();repo.build('production');evidence=self.evidence_path.read_bytes();snapshot=self.snapshot_path.read_bytes()
        for target,original in [(self.evidence_path,evidence),(self.snapshot_path,snapshot)]:
            target.write_bytes(original+b'changed')
            with self.subTest(target=target.name):
                with self.assertRaises((ValueError,AssertionError)):repo.verify('production')
                with self.assertRaises((ValueError,AssertionError)):auditor.audit('production')
                with self.assertRaises((ValueError,AssertionError)):publication.site_audit(self.load_plan())
            target.write_bytes(original)

    def test_forged_public_notice_rejects_even_with_rehashed_producer_plan(self):
        self.setup_skin();repo.build('production');site=self.root/'dist/production/site';page=site/'index.html'
        page.write_text(page.read_text().replace('owner_reported_minor_layout','fully_tested'))
        plan=self.load_plan();plan['site_files']={p.relative_to(site).as_posix():repo.sha(p.read_bytes()) for p in sorted(site.rglob('*')) if p.is_file()}
        plan['site_manifest_sha256']=repo.sha(repo.json_bytes(plan['site_files']))
        (self.root/'dist/production/release-plan.json').write_bytes(repo.json_bytes(plan))
        with self.assertRaises((ValueError,AssertionError)):auditor.audit('production')
        with self.assertRaises((ValueError,AssertionError)):publication.site_audit(plan)

    def test_independent_auditor_rejects_failed_support_under_permissive_shared_contract(self):
        record=self.setup_skin();repo.build('production')
        permissive=next(p['approval'] for p in self.load_plan()['packages'] if p['id']=='skin.aura')
        value=record['skin_alpha_evidence'];value['scenarios'][0]['supporting_evidence'][0]['status']='failed'
        self.save_record(record)
        permissive.update(skin_alpha_evidence=value,skin_alpha_evidence_sha256=contract.exception_digest(value))
        with patch.object(contract,'assess',return_value=permissive):
            with self.assertRaises((ValueError,AssertionError)):auditor.reviewed_inputs(repo.load_config(),'production')

    def test_empty_lanes_require_exact_ledger_and_retained_first_artifact_stays_valid(self):
        record=self.setup_skin();record['approval_lanes']=[];self.save_record(record)
        p=self.root/'config/production.json';inputs=json.loads(p.read_text());inputs['packages'][0]['lanes']=[];p.write_bytes(repo.json_bytes(inputs))
        with self.assertRaises((ValueError,AssertionError)):repo.production_packages(repo.load_config())
        with self.assertRaises((ValueError,AssertionError)):auditor.reviewed_inputs(repo.load_config(),'production')
        (self.root/'releases/manifest.json').write_bytes(repo.json_bytes({'schema':1,'packages':[
            {'id':'skin.aura','version':'2.1.0','sha256':record['package_sha256']}]}))
        repo.build('production');repo.verify('production');audit=auditor.audit('production')
        self.assertEqual(audit['release_blockers'],[])
        self.assertTrue((self.root/'dist/production/site/packages/skin.aura/skin.aura-2.1.0.zip').is_file())
        self.assertTrue(all('skin.aura' not in x['ids'] for x in self.load_plan()['catalogs'].values()))

    def test_future_deferral_and_policy_only_v2_downgrade_reject(self):
        record=self.setup_skin();original=copy.deepcopy(record)
        record['compatibility']['omega']['runtime_test']['recorded_at']=(self.now+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.save_record(record)
        with self.assertRaises((ValueError,AssertionError)):repo.production_packages(repo.load_config())
        with self.assertRaises((ValueError,AssertionError)):auditor.reviewed_inputs(repo.load_config(),'production')
        record=original;record['schema_version']=2;record.pop('skin_alpha_evidence')
        record['release_decision'].pop('skin_alpha_evidence_sha256');self.save_record(record,seal=False)
        with self.assertRaises((ValueError,AssertionError)):repo.production_packages(repo.load_config())
        with self.assertRaises((ValueError,AssertionError)):auditor.reviewed_inputs(repo.load_config(),'production')


if __name__=='__main__':unittest.main()
