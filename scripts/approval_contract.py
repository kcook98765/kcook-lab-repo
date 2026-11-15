"""Versioned approval evidence. No publication or evidence invention.

The builder and auditor use this contract against independently loaded, hashed
inputs. Package, catalog, retention and production gates remain in each consumer.
"""
from datetime import datetime, timezone
from pathlib import PurePosixPath
import hashlib
import json
import re
import original_assets

POLICY = 'strict-v1'
UNOFFICIAL_POLICY = 'unofficial-integration-v1'
INITIAL_POLICY = 'unofficial-integration-initial-release-v1'
SKIN_ALPHA_POLICY = 'initial-release-skin-alpha-v1'
DECISION_FIELDS = {'status', 'actor', 'role', 'recorded_at', 'rationale', 'evidence'}
V2_FIELDS = {'approval_policy', 'approval_lanes', 'rights_review',
             'owner_acknowledgment', 'technical_release', 'release_decision',
             'unresolved_risks'}


def require(condition, message):
    if not condition:
        raise ValueError('Approval contract: ' + message)


def references(value):
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and item.strip() for item in value)


def decision(value, statuses, inactive='pending', extra=()):
    require(isinstance(value, dict) and value.get('status') in statuses,
            'invalid decision status')
    require(set(value) <= DECISION_FIELDS | set(extra), 'unknown decision field')
    if value['status'] == inactive:
        require(set(value) == {'status'}, 'pending decision must not imply an action')
        return
    require(DECISION_FIELDS <= set(value), 'decision attribution/evidence missing')
    for key in ('actor', 'role', 'rationale'):
        require(isinstance(value[key], str) and bool(value[key].strip()), 'empty ' + key)
    stamp = value['recorded_at']
    require(isinstance(stamp, str) and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp) is not None,
        'recorded_at must be UTC RFC3339 seconds')
    try:
        datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise ValueError('Approval contract: invalid recorded_at date') from None
    require(references(value['evidence']), 'decision evidence missing')


def canonical_path(value):
    return (isinstance(value, str) and bool(PurePosixPath(value).parts) and
            not PurePosixPath(value).is_absolute() and PurePosixPath(value).as_posix() == value and
            '..' not in PurePosixPath(value).parts and
            not any(c in value for c in ('\\', ':')) and
            all(ord(c) >= 32 for c in value))


def pinned_references(value):
    if not references(value):
        return False
    for item in value:
        match = re.fullmatch(r'(.+) sha256:([0-9a-f]{64})', item)
        if not match or not canonical_path(match[1]):
            return False
    return True


def exact_risks(value, ids):
    return (isinstance(value, list) and bool(value) and
            all(isinstance(item, str) for item in value) and
            len(value) == len(set(value)) and set(value) == set(ids))


def utc_now():
    return datetime.now(timezone.utc)


def exception_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode('utf-8')).hexdigest()


def runtime_exception(record, lanes, risks, ack, identity, history, blockers):
    """Coverage-only initial release admission; never a passed runtime test."""
    value = record.get('runtime_acceptance_exception')
    require(isinstance(value, dict) and set(value) == {
        'scope', 'addon_id', 'addon_version', 'package_sha256', 'source_commit', 'lanes',
        'expires_at', 'scenarios', 'owner_decision', 'independent_verification'},
        'malformed runtime acceptance exception')
    require(value['scope'] == 'initial_release_runtime_coverage_only' and identity is not None and
            (value['addon_id'], value['addon_version']) == identity and
            value['package_sha256'] == record['package_sha256'] and
            value['source_commit'] == record['source_commit'], 'runtime exception artifact/source mismatch')
    require(exact_risks(value['lanes'], lanes), 'runtime exception lane mismatch')
    scenarios = value['scenarios']
    require(isinstance(scenarios, list) and bool(scenarios), 'runtime exception scenarios missing')
    ids = []; risk_ids = set()
    for scenario in scenarios:
        require(isinstance(scenario, dict) and set(scenario) == {
            'id', 'lane', 'risk_id', 'kind', 'observation', 'description', 'supporting_evidence'},
            'malformed runtime scenario')
        require(all(isinstance(scenario[k], str) and scenario[k].strip() for k in ('id', 'risk_id', 'description'))
                and scenario['lane'] in lanes, 'runtime scenario identity/scope missing')
        require((scenario['kind'], scenario['observation']) in (
            ('unobserved_functionality', 'not_observed'), ('environment_limitation', 'unavailable')),
            'runtime exception cannot waive failed tests or assert a pass')
        support = scenario['supporting_evidence']
        require(isinstance(support, list) and bool(support), 'runtime supporting evidence missing')
        for evidence in support:
            require(isinstance(evidence, dict) and set(evidence) == {'method', 'status', 'scope', 'evidence'} and
                    evidence['method'] in ('offline', 'native', 'environment') and
                    evidence['status'] in ('passed', 'not_observed', 'unavailable') and
                    isinstance(evidence['scope'], str) and evidence['scope'].strip() and
                    pinned_references(evidence['evidence']), 'invalid or failed runtime supporting evidence')
        if scenario['kind'] == 'environment_limitation':
            require(any(e['method'] == 'environment' and e['status'] == 'unavailable' for e in support),
                    'environment limitation requires unavailable environment evidence')
        ids.append(scenario['id']); risk_ids.add(scenario['risk_id'])
    require(len(ids) == len(set(ids)), 'duplicate runtime scenario id')
    require(risk_ids == {r['id'] for r in risks if r['category'] == 'runtime'} and bool(risk_ids),
            'runtime exception must identify every runtime risk exactly')
    for lane in lanes:
        item = record['compatibility'][lane]; test = item['runtime_test']
        expected = [s['id'] for s in scenarios if s['lane'] == lane]
        if expected:
            require(item['runtime_accepted'] is False and test['status'] == 'deferred' and
                    exact_risks(test['outstanding_tests'], expected),
                    'runtime exception must match every deferred outstanding scenario')
        else:
            require(item['runtime_accepted'] is True and test['status'] == 'passed',
                    'unlisted runtime limitation or incomplete lane')
        require(item['static_accepted'] is True and references(item['evidence']) and
                pinned_references(test['evidence']), 'runtime exception requires static and scoped runtime evidence')
    owner = value['owner_decision']; review = value['independent_verification']
    for action, statuses, extras in (
        (owner, ('pending', 'accepted', 'declined', 'revoked'), ('scenario_ids', 'risk_ids')),
        (review, ('pending', 'verified', 'rejected', 'revoked'), ('scenario_ids', 'risk_ids', 'no_known_security_defects', 'core_evidence')),
    ):
        decision(action, statuses, extra=extras)
        if action['status'] != 'pending':
            require(set(action) == DECISION_FIELDS | set(extras) and
                    exact_risks(action['scenario_ids'], ids) and exact_risks(action['risk_ids'], risk_ids) and
                    pinned_references(action['evidence']), 'runtime decision scope/evidence mismatch')
    if owner['status'] != 'pending':
        require(owner['role'] == 'owner', 'runtime exception requires owner decision')
        require(owner['actor'].strip().casefold() ==
                record['unofficial_integration']['owner_distribution_decision'].get('actor', '').strip().casefold(),
                'runtime and provider distribution owner mismatch')
    if review['status'] != 'pending':
        require(review['no_known_security_defects'] is True, 'known security defects cannot be waived')
        require(review['actor'].strip().casefold() != owner.get('actor', '').strip().casefold(),
                'runtime verification must be independent of accepting owner')
        core = review['core_evidence']
        require(isinstance(core, list) and bool(core), 'core native/offline verification missing')
        for evidence in core:
            require(isinstance(evidence, dict) and set(evidence) == {'method', 'status', 'scope', 'evidence'} and
                    evidence['method'] in ('offline', 'native') and evidence['status'] == 'passed' and
                    isinstance(evidence['scope'], str) and evidence['scope'].strip() and
                    pinned_references(evidence['evidence']), 'core native/offline verification failed or missing')
        require({e['method'] for e in core} == {'native', 'offline'}, 'core native and offline evidence both required')
    stamp = value['expires_at']
    require(isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp),
            'runtime exception expiry must be UTC RFC3339 seconds')
    try:
        expiry = datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('Approval contract: invalid runtime exception date') from None
    now = utc_now()
    actions_current = True
    for action in (owner, review):
        if action['status'] == 'pending':
            actions_current = False
            continue
        recorded = datetime.strptime(action['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        require(recorded < expiry, 'runtime exception expiry must follow decisions')
        actions_current = actions_current and recorded <= now
    prior = [old for old in history if old['id'] == identity[0]] if isinstance(history, list) else None
    initial = prior is not None and (not prior or
        (prior[0]['version'], prior[0]['sha256']) == (identity[1], record['package_sha256']))
    acknowledged = ack['status'] == 'acknowledged' and ack['actor'].strip().casefold() == owner.get('actor', '').strip().casefold()
    active = (owner['status'] == 'accepted' and review['status'] == 'verified' and acknowledged and
              actions_current and now < expiry and initial)
    if not active:
        blockers.append('Initial runtime exception missing acceptance, independent verification, acknowledgment, initial history or current expiry')
    if record['release_approved']:
        final = record['release_decision']
        require(final['role'] == 'owner' and final['actor'].strip().casefold() == owner.get('actor', '').strip().casefold()
                and final.get('runtime_exception_sha256') == exception_digest(value) and
                pinned_references(final['evidence']), 'final owner approval must bind exact runtime exception')
        final_time = datetime.strptime(final['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        require(all(a['status'] != 'pending' and a['recorded_at'] <= final['recorded_at'] for a in (owner, review))
                and final_time <= now, 'final runtime owner approval precedes decisions or is future-dated')
    return active, risk_ids


def provider_exception(record, owner, service, package_identity, blockers):
    """Owner policy acceptance supplies no provider permission or package rights."""
    value = owner.get('provider_authorization_exception')
    if value is None:
        require('provider_authorization_exception' not in owner, 'malformed provider exception')
        return False
    require(isinstance(value, dict) and set(value) == {
        'scope', 'upstream_provider', 'addon_id', 'addon_version', 'package_sha256',
        'provider_authorization_verified', 'provider_terms_concern', 'owner_accepts_risk', 'expires_at'},
        'malformed provider exception')
    require(value['scope'] == 'repository_provider_authorization_gate_only' and
            value['provider_authorization_verified'] is False and value['owner_accepts_risk'] is True,
            'provider exception must record unverified authorization and owner risk acceptance only')
    require(all(isinstance(value[k], str) and value[k].strip() and value[k] == value[k].strip()
                for k in ('upstream_provider', 'provider_terms_concern', 'addon_id', 'addon_version')),
            'provider exception identity/terms concern missing')
    require(package_identity is not None and
            (value['addon_id'], value['addon_version']) == package_identity and
            value['package_sha256'] == record['package_sha256'],
            'provider exception artifact identity/checksum mismatch')
    require(service['status'] == 'authorization_unverified' and
            service.get('upstream_provider') == value['upstream_provider'],
            'provider exception service/provider mismatch')
    stamp = value['expires_at']
    require(isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp),
            'provider exception expiry must be UTC RFC3339 seconds')
    try:
        expiry = datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        recorded = datetime.strptime(owner['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('Approval contract: invalid provider exception date') from None
    require(expiry > recorded, 'provider exception expiry must follow owner decision')
    now = utc_now()
    active = owner['status'] == 'accepted' and recorded <= now < expiry
    if not active:
        blockers.append('Owner provider-authorization exception inactive, future-dated or expired')
    return active


def unofficial(record, risks, ack, blockers, package_identity, accepted_runtime_ids=()):
    """Validate the closed v3 assertions; retain accepted findings as unresolved."""
    require(record['rights_approved'] is False and record['rights_review'] == {'status': 'pending'},
            'v3 broad rights must remain false/pending')
    value = record.get('unofficial_integration')
    require(isinstance(value, dict) and set(value) == {'package_distribution_review',
            'service_use_review', 'owner_distribution_decision', 'disclosure'},
            'malformed unofficial_integration')
    package = value['package_distribution_review']
    service = value['service_use_review']
    owner = value['owner_distribution_decision']
    require(all(isinstance(action, dict) for action in (package, service, owner)), 'malformed v3 action')
    ids = [r['id'] for r in risks if r['category'] == 'provider_terms']
    for action, statuses, extras in [
        (package, ('pending', 'verified', 'rejected', 'revoked'), ('scope',)),
        (service, ('pending', 'terms_unresolved', 'authorization_unverified', 'blocked', 'revoked'),
         ('scope', 'risk_ids', 'provider_permission_obtained', 'provider_content_authorization') +
         (('upstream_provider',) if service.get('status') == 'authorization_unverified' else ())),
        (owner, ('pending', 'accepted', 'declined', 'revoked'), ('risk_ids', 'authorization_claimed') +
         (('provider_authorization_exception',) if 'provider_authorization_exception' in owner else ()))]:
        decision(action, statuses, extra=extras)
        if action['status'] != 'pending':
            require(set(action) == DECISION_FIELDS | set(extras), 'v3 action fields missing')
            require(pinned_references(action['evidence']), 'v3 evidence must be hash-pinned')
    if package['status'] != 'pending':
        require(package['scope'] == 'all_distributed_materials', 'package distribution scope missing')
    if service['status'] != 'pending':
        require(service['scope'] == 'runtime_service_content_and_marks' and
                service['provider_permission_obtained'] is False and
                service['provider_content_authorization'] == 'not_established',
                'v3 must not claim provider/content authorization')
        require(exact_risks(service['risk_ids'], ids), 'service review risk scope mismatch')
    if owner['status'] != 'pending':
        require(owner['role'] == 'owner' and owner['authorization_claimed'] is False,
                'owner distribution decision must not claim authorization')
        require(exact_risks(owner['risk_ids'], ids), 'owner distribution risk scope mismatch')
    exception_active = provider_exception(record, owner, service, package_identity, blockers)
    if 'provider_authorization_exception' in owner and ack['status'] == 'acknowledged':
        require(ack['actor'].strip().casefold() == owner['actor'].strip().casefold(),
                'owner-risk decision contradicts acknowledging owner identity')
    if service['status'] == 'authorization_unverified':
        require(isinstance(service['upstream_provider'], str) and bool(service['upstream_provider'].strip()),
                'upstream provider missing')
        if not exception_active:
            blockers.append('Provider authorization unverified; active owner-risk decision required')
    notice = value['disclosure']
    require(isinstance(notice, dict) and set(notice) == {'package_path', 'package_sha256', 'release_text'},
            'malformed unofficial disclosure')
    require(canonical_path(notice['package_path']) and
            isinstance(notice['package_sha256'], str) and
            re.fullmatch('[0-9a-f]{64}', notice['package_sha256']) is not None and
            record['runtime_files'].get(notice['package_path']) == notice['package_sha256'],
            'disclosure must bind a reviewed runtime member')
    require(isinstance(notice['release_text'], str) and bool(notice['release_text'].strip()) and
            all(ord(c) >= 32 or c in '\n\r\t' for c in notice['release_text']),
            'release disclosure text missing or unsafe')
    gates = [
        (bool(ids) and all(r['category'] == 'provider_terms' or r['id'] in accepted_runtime_ids for r in risks),
         'Only nonempty provider-terms findings are eligible'),
        (package['status'] == 'verified', 'Package distribution review missing'),
        (service['status'] == 'terms_unresolved' or exception_active, 'Service-use assessment missing or blocked'),
        (ack['status'] == 'acknowledged', 'Owner acknowledgment missing'),
        (owner['status'] == 'accepted', 'Owner distribution acceptance missing'),
    ]
    if owner['status'] == 'accepted':
        for review in (package, service):
            gates.append((review.get('actor', '').strip().casefold() != owner['actor'].strip().casefold(),
                          'Distribution and service reviewers must be independent of accepting owner'))
    blockers.extend(message for passed, message in gates if not passed)
    accepted = all(passed for passed, _ in gates)
    if not accepted:
        blockers.extend('Unresolved risk: ' + item for item in ids)
    return {'unofficial_integration': value,
            'provider_authorization_exception_active': exception_active,
            'provider_permission_obtained': False, 'provider_content_authorization': 'not_established',
            'accepted_terms_risks': [r for r in risks if r['category'] == 'provider_terms'] if accepted else [],
            'publication_authorized': False}


def skin_alpha(record, lanes, risks, ack, identity, history, manifest, blockers,
               material_policy=None):
    """Owner-reported use plus independently reviewed distribution delta.

    This never converts general use to native acceptance of the cleaned ZIP or
    an unobserved scripted scenario. Only named alpha coverage can be admitted.
    """
    value = record.get('skin_alpha_evidence')
    require(isinstance(value, dict) and set(value) == {
        'scope', 'addon_id', 'addon_version', 'package_sha256', 'source_commit',
        'lanes', 'expires_at', 'owner_native_use', 'reviewed_package_delta',
        'scenarios', 'owner_coverage_decision', 'independent_verification'},
        'malformed skin-alpha evidence')
    require(value['scope'] == 'initial_release_skin_alpha_coverage_only' and identity is not None and
            (value['addon_id'], value['addon_version']) == identity and
            value['package_sha256'] == record['package_sha256'] and
            value['source_commit'] == record['source_commit'], 'skin-alpha artifact/source mismatch')
    require(manifest is not None and (manifest.get('id'), manifest.get('version')) == identity and
            identity[0].startswith('skin.') and
            len(manifest.findall("extension[@point='xbmc.gui.skin']")) == 1 and
            all(e.get('point') in ('xbmc.gui.skin', 'xbmc.addon.metadata') for e in manifest.findall('extension')),
            'skin-alpha requires inspected skin-only manifest')
    gui = manifest.find("requires/import[@addon='xbmc.gui']")
    require(gui is not None and gui.get('version') == '5.17.0' and
            lanes == ['omega'] and value['lanes'] == ['omega'] and
            set(record['compatibility']) == {'omega'}, 'skin-alpha is Omega-only')
    use = value['owner_native_use']
    use_fields = {'addon_id', 'reported_version', 'kodi_major', 'platform', 'duration',
        'result', 'known_limitations', 'formal_scripted_acceptance',
        'cleaned_package_native_accepted', 'identity_disposition',
        'installed_package_sha256', 'identity_limitation'}
    decision(use, ('owner_reported',), extra=use_fields)
    require(set(use) == DECISION_FIELDS | use_fields and use['role'] == 'owner' and
            use['addon_id'] == identity[0] and type(use['kodi_major']) is int and use['kodi_major'] == 21 and
            use['result'] == 'stable_regular_use' and use['formal_scripted_acceptance'] is False and
            use['cleaned_package_native_accepted'] is False and pinned_references(use['evidence']),
            'skin-alpha owner use must remain attributable owner-reported evidence')
    require(all(isinstance(use[k], str) and use[k].strip()
                for k in ('reported_version', 'platform', 'duration', 'identity_limitation')) and
            isinstance(use['known_limitations'], list) and
            all(isinstance(x, str) and x.strip() for x in use['known_limitations']),
            'skin-alpha owner scope/limitations missing')
    require(use['identity_disposition'] in ('verified', 'unverified') and
            (use['installed_package_sha256'] == record['package_sha256']
             if use['identity_disposition'] == 'verified' else use['installed_package_sha256'] is None),
            'skin-alpha installed identity must be verified exactly or explicitly unknown')
    delta = value['reviewed_package_delta']
    delta_extras = {'scope', 'source_provenance_verified', 'no_known_security_defects',
                    'no_known_functionality_failures', 'static_package_evidence'}
    decision(delta, ('pending', 'verified', 'rejected', 'revoked'), extra=delta_extras)
    if delta['status'] != 'pending':
        require(set(delta) == DECISION_FIELDS | delta_extras and
                isinstance(delta['scope'], str) and delta['scope'].strip() and
                delta['source_provenance_verified'] is True and delta['no_known_security_defects'] is True and
                delta['no_known_functionality_failures'] is True and
                pinned_references(delta['evidence']) and pinned_references(delta['static_package_evidence']),
                'skin-alpha package delta/source/static/security review missing or adverse')
    scenarios = value['scenarios']; ids = []; risk_ids = set(); cosmetic = False
    require(isinstance(scenarios, list) and bool(scenarios), 'skin-alpha scenarios missing')
    for scenario in scenarios:
        require(isinstance(scenario, dict) and set(scenario) == {
            'id', 'lane', 'risk_id', 'kind', 'observation', 'description', 'supporting_evidence'} and
            all(isinstance(scenario[k], str) and scenario[k].strip() for k in ('id', 'risk_id', 'description')) and
            scenario['lane'] == 'omega', 'malformed skin-alpha scenario')
        require((scenario['kind'], scenario['observation']) in (
            ('unobserved_functionality', 'not_observed'), ('environment_limitation', 'unavailable'),
            ('cosmetic_layout_limitation', 'owner_reported_minor_layout')),
            'skin-alpha cannot waive failed functionality or assert scenario PASS')
        cosmetic |= scenario['kind'] == 'cosmetic_layout_limitation'
        support = scenario['supporting_evidence']
        require(isinstance(support, list) and bool(support), 'skin-alpha scenario evidence missing')
        for item in support:
            require(isinstance(item, dict) and set(item) == {'method', 'status', 'scope', 'evidence'} and
                    (item['method'], item['status']) in (
                        ('offline', 'passed'), ('offline', 'not_observed'), ('environment', 'unavailable'),
                        ('owner_reported', 'not_observed'), ('owner_reported', 'reported_minor_layout')) and
                    isinstance(item['scope'], str) and item['scope'].strip() and
                    pinned_references(item['evidence']), 'invalid skin-alpha supporting evidence')
        if scenario['kind'] == 'environment_limitation':
            require(any(x['method'] == 'environment' and x['status'] == 'unavailable' for x in support),
                    'skin-alpha environment scenario lacks environment evidence')
        if scenario['kind'] == 'cosmetic_layout_limitation':
            require(any(x['method'] == 'owner_reported' and x['status'] == 'reported_minor_layout' for x in support),
                    'skin-alpha cosmetic finding must retain owner report')
        ids.append(scenario['id']); risk_ids.add(scenario['risk_id'])
    require(len(ids) == len(set(ids)) and
            risk_ids == {x['id'] for x in risks if x['category'] == 'runtime'} and bool(risk_ids),
            'skin-alpha scenarios must cover every runtime risk exactly')
    require(not use['known_limitations'] or cosmetic, 'skin-alpha must retain reported minor-layout finding')
    lane = record['compatibility']['omega']; test = lane['runtime_test']
    require(lane['static_accepted'] is True and lane['runtime_accepted'] is False and
            test['status'] == 'deferred' and exact_risks(test['outstanding_tests'], ids) and
            pinned_references(test['evidence']) and pinned_references(lane['evidence']),
            'skin-alpha requires static approval and explicit deferred coverage, never native acceptance')
    owner = value['owner_coverage_decision']; review = value['independent_verification']
    owner_extra = {'scenario_ids', 'risk_ids', 'accepts_unverified_installed_identity', 'acknowledges_package_delta'}
    review_extra = {'scenario_ids', 'risk_ids', 'no_known_security_defects',
                    'no_known_functionality_failures', 'owner_report_scope_verified'}
    for action, statuses, extras in (
        (owner, ('pending', 'accepted', 'declined', 'revoked'), owner_extra),
        (review, ('pending', 'verified', 'rejected', 'revoked'), review_extra),
    ):
        decision(action, statuses, extra=extras)
        if action['status'] != 'pending':
            require(set(action) == DECISION_FIELDS | extras and exact_risks(action['scenario_ids'], ids) and
                    exact_risks(action['risk_ids'], risk_ids) and pinned_references(action['evidence']),
                    'skin-alpha decision scope/evidence mismatch')
    if owner['status'] != 'pending':
        require(owner['role'] == 'owner' and owner['actor'].strip().casefold() == use['actor'].strip().casefold() and
                owner['acknowledges_package_delta'] is True and
                owner['accepts_unverified_installed_identity'] is (use['identity_disposition'] == 'unverified'),
                'skin-alpha owner must accept exact identity and package-delta limitations')
    if review['status'] != 'pending':
        require(review['no_known_security_defects'] is True and review['no_known_functionality_failures'] is True and
                review['owner_report_scope_verified'] is True, 'skin-alpha cannot waive security or functionality failures')
    for action in (delta, review, record['rights_review'], record['technical_release']):
        if action['status'] != 'pending':
            require(action['actor'].strip().casefold() != use['actor'].strip().casefold() and
                    pinned_references(action['evidence']), 'skin-alpha review must be independent and hash-pinned')
    stamp = value['expires_at']
    require(isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp),
            'skin-alpha expiry must be UTC RFC3339 seconds')
    try:
        expiry = datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError('Approval contract: invalid skin-alpha expiry') from None
    now = utc_now(); current = True
    material_active, material_actions = (False, []) if material_policy is None else material_policy
    rights_actions = [record['rights_review']] if material_policy is None else material_actions
    all_actions = [use, delta, owner, review, ack, test, record['technical_release'], *rights_actions]
    for action in all_actions:
        if action['status'] in ('pending', 'not_recorded'):
            current = False
            continue
        recorded = datetime.strptime(action['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        require(recorded < expiry, 'skin-alpha expiry must follow all decisions')
        current = current and recorded <= now
    use_time = datetime.strptime(use['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    require(0 < (expiry - use_time).total_seconds() <= 90 * 86400,
            'skin-alpha expiry must be within 90 days of owner-use report')
    prior = [x for x in history if x['id'] == identity[0]] if isinstance(history, list) else None
    initial = prior is not None and (not prior or
        (prior[0]['version'], prior[0]['sha256']) == (identity[1], record['package_sha256']))
    acknowledged = ack['status'] == 'acknowledged' and ack['actor'].strip().casefold() == use['actor'].strip().casefold()
    if ack['status'] == 'acknowledged':
        require(pinned_references(ack['evidence']), 'skin-alpha acknowledgment must be hash-pinned')
    for action in (owner, review):
        if action['status'] != 'pending':
            require(action['recorded_at'] >= use['recorded_at'], 'skin-alpha decision precedes owner-use report')
    active = ((record['rights_approved'] is True or material_active) and record['technical_release']['status'] == 'approved' and
              delta['status'] == 'verified' and owner['status'] == 'accepted' and review['status'] == 'verified' and
              acknowledged and initial and current and now < expiry)
    if not active:
        blockers.append('Skin-alpha coverage missing rights, delta, owner acceptance, independent review, acknowledgment, initial history or current expiry'
                        if material_policy is None else
                        'Skin-alpha coverage missing reviewed material policy, delta, owner acceptance, independent review, acknowledgment, initial history or current expiry')
    if record['release_approved']:
        final = record['release_decision']
        require(final['role'] == 'owner' and final['actor'].strip().casefold() == use['actor'].strip().casefold() and
                final.get('skin_alpha_evidence_sha256') == exception_digest(value) and pinned_references(final['evidence']),
                'final owner package approval must bind exact skin-alpha evidence')
        final_time = datetime.strptime(final['recorded_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        require(all(x['status'] not in ('pending', 'not_recorded') and x['recorded_at'] <= final['recorded_at']
                    for x in all_actions) and
                final_time <= now, 'final skin-alpha owner approval precedes evidence/decisions or is future-dated')
    return active, risk_ids


def assess(record, lanes, package_identity=None, release_history=None, package_manifest=None):
    """Validate versioned assertions and return an honest, JSON-safe report.

    Unversioned and explicit v1 records keep the old boolean contract. New
    fields cannot be smuggled into v1 where an older consumer would ignore them.
    This does not authenticate actors or establish the substance of evidence.
    """
    version = record.get('schema_version', 1)
    require(type(version) is int and version in (1, 2, 3, 4, 5), 'unsupported schema_version')
    require(version == 3 or 'unofficial_integration' not in record, 'v3 fields require schema_version=3')
    initial_policy = version == 3 and record.get('approval_policy') == INITIAL_POLICY
    material_policy = version == 5 and record.get('approval_policy') == original_assets.POLICY
    skin_policy = (version == 4 and record.get('approval_policy') == SKIN_ALPHA_POLICY) or material_policy
    require(material_policy or 'original_assets_admission' not in record,
            'original-assets evidence requires explicit schema-5 policy')
    if skin_policy and not lanes:
        require(isinstance(release_history, list) and package_identity is not None and
                any((old.get('id'),old.get('version'),old.get('sha256')) ==
                    (package_identity[0],package_identity[1],record['package_sha256']) for old in release_history),
                'Empty skin-alpha lanes require exact retained history')
    require(skin_policy or 'skin_alpha_evidence' not in record, 'skin-alpha evidence requires explicit skin policy')
    require(initial_policy or 'runtime_acceptance_exception' not in record,
            'runtime exception requires explicit initial-release policy')
    scope = {key: record[key] for key in ('package_sha256', 'source_repository', 'source_commit',
                                        'rights_approved', 'release_approved')}
    scope['lanes'] = list(lanes)
    blockers = [key for key in ('rights_approved', 'release_approved')
                if not record[key] and not (version == 3 and key == 'rights_approved')]
    runtime = {}
    # No active lanes is retained history only. Preserve acceptance over the
    # recorded compatibility scope; both consumers separately require the ledger.
    acceptance_lanes = lanes or (list(record['compatibility']) if version in (3, 4, 5) else [])
    if version in (3, 4, 5) and not acceptance_lanes:
        blockers.append('Original runtime acceptance scope missing')
    for lane in acceptance_lanes:
        item = record['compatibility'][lane]
        if not (item['static_accepted'] and item['runtime_accepted'] and item['evidence']):
            blockers.append('Per-lane acceptance missing: ' + lane)
        runtime[lane] = {'status': 'legacy_accepted' if item['runtime_accepted'] else 'legacy_not_accepted',
                         'evidence': item['evidence']}
    if version == 1:
        require(not (V2_FIELDS & set(record)) and all('runtime_test' not in item
                for item in record['compatibility'].values()), 'v2 fields require schema_version=2')
        return {**scope, 'schema_version': 1, 'rights_status': 'legacy_approved' if record['rights_approved'] else 'pending',
                'release_status': 'legacy_approved' if record['release_approved'] else 'pending',
                'technical_release_status': 'legacy_unspecified', 'owner_acknowledgment': {'status': 'not_recorded'},
                'runtime': runtime, 'unresolved_risks': None,
                'recorded_limitations': record.get('limitations', []),
                'recorded_native_scope': record.get('native_scope', {}),
                'limitations': ['Legacy boolean attestations; separate attribution, rights basis, technical decision and runtime deferrals are unspecified.'],
                'release_blockers': sorted(set(blockers))}

    require(V2_FIELDS <= set(record), 'v2 fields missing')
    policy = record['approval_policy']
    require(policy in ((UNOFFICIAL_POLICY, INITIAL_POLICY) if version == 3 else
                       (SKIN_ALPHA_POLICY,) if version == 4 else
                       (original_assets.POLICY,) if version == 5 else (POLICY,)), 'unsupported approval_policy')
    require(isinstance(record['approval_lanes'], list) and
            all(isinstance(lane, str) for lane in record['approval_lanes']) and
            len(record['approval_lanes']) == len(set(record['approval_lanes'])) and
            set(record['approval_lanes']) == set(lanes), 'approval lane scope mismatch')
    for key, statuses in [('rights_review', ('verified', 'pending', 'rejected', 'revoked')),
                          ('technical_release', ('approved', 'pending', 'rejected', 'revoked')),
                          ('release_decision', ('approved', 'pending', 'rejected', 'revoked'))]:
        extras = (('original_assets_admission_sha256', 'skin_alpha_evidence_sha256') if material_policy else
                  ('runtime_exception_sha256',) if initial_policy else
                  ('skin_alpha_evidence_sha256',) if skin_policy else ()) if key == 'release_decision' else ()
        decision(record[key], statuses, extra=extras)
    require(record['rights_approved'] is (record['rights_review']['status'] == 'verified'),
            'rights_approved contradicts rights_review')
    require(record['release_approved'] is (record['release_decision']['status'] == 'approved'),
            'release_approved contradicts release_decision')
    if record['technical_release']['status'] != 'approved':
        blockers.append('Explicit technical release approval missing')

    risks = record['unresolved_risks']
    require(isinstance(risks, list), 'unresolved_risks must be a list')
    ids = []
    for risk in risks:
        require(isinstance(risk, dict) and set(risk) == {'id', 'category', 'description', 'evidence'},
                'malformed unresolved risk')
        require(all(isinstance(risk[k], str) and risk[k].strip() for k in ('id', 'description'))
                and risk['category'] in (('rights', 'runtime', 'technical', 'other', 'provider_terms')
                                         if version == 3 else ('rights', 'runtime', 'technical', 'other'))
                and references(risk['evidence']), 'risk evidence missing')
        if version in (3, 4, 5):
            require(pinned_references(risk['evidence']), 'v3/v4/v5 risk evidence must be hash-pinned')
        ids.append(risk['id'])
        if version != 3 or risk['category'] != 'provider_terms':
            blockers.append('Unresolved risk: ' + risk['id'])
    require(len(ids) == len(set(ids)), 'duplicate risk id')
    ack = record['owner_acknowledgment']
    decision(ack, ('acknowledged', 'not_recorded'), inactive='not_recorded', extra=('risk_ids',))
    if ack['status'] == 'acknowledged':
        require(ack['role'] == 'owner', 'acknowledgment must record an owner action')
        require(isinstance(ack.get('risk_ids'), list) and bool(ids) and
                all(isinstance(item, str) for item in ack['risk_ids']) and
                len(ack['risk_ids']) == len(set(ack['risk_ids'])) and set(ack['risk_ids']) == set(ids),
                'acknowledgment must identify the exact unresolved risks')
    require(not (record['rights_approved'] and any(r['category'] == 'rights' for r in risks)),
            'verified rights contradict unresolved rights risks')
    require(not (record['technical_release']['status'] == 'approved' and
                 any(r['category'] == 'technical' for r in risks)),
            'technical approval contradicts unresolved technical risks')

    for lane, item in record['compatibility'].items():
        require(lane in ('matrix', 'nexus', 'omega', 'piers'), 'unknown compatibility lane')
        require(all(type(item[k]) is bool for k in ('static_accepted', 'runtime_accepted')) and
                isinstance(item['evidence'], list) and all(isinstance(e, str) and e.strip()
                for e in item['evidence']), 'malformed compatibility evidence')
        test = item.get('runtime_test')
        decision(test, ('passed', 'deferred', 'pending', 'failed'),
                 extra=('platform', 'kodi_version', 'scope', 'outstanding_tests'))
        passed = test['status'] == 'passed'
        require(type(item['runtime_accepted']) is bool and item['runtime_accepted'] is passed,
                'runtime_accepted contradicts runtime_test')
        if test['status'] != 'pending':
            require(all(isinstance(test.get(k), str) and test[k].strip()
                        for k in ('platform', 'kodi_version', 'scope')), 'runtime scope missing')
            pending = test.get('outstanding_tests')
            require(isinstance(pending, list) and all(isinstance(t, str) and t.strip() for t in pending),
                    'invalid outstanding_tests')
            require(not pending if passed else bool(pending), 'runtime result contradicts outstanding tests')
            if passed:
                require(references(item['evidence']), 'completed runtime evidence missing')
        if lane in acceptance_lanes:
            runtime[lane] = test
            if not passed:
                blockers.append('Runtime testing ' + test['status'] + ': ' + lane)
    require(not (risks and any(r['category'] == 'runtime' for r in risks) and
                 runtime and all(t['status'] == 'passed' for t in runtime.values())),
            'completed runtime contradicts unresolved runtime risks')
    accepted_runtime_ids = set()
    runtime_active = False
    if initial_policy:
        runtime_active, runtime_ids = runtime_exception(record, acceptance_lanes, risks, ack,
                                                       package_identity, release_history, blockers)
        if runtime_active:
            accepted_runtime_ids = runtime_ids
            removable = {'Unresolved risk: ' + rid for rid in runtime_ids}
            for lane in acceptance_lanes:
                removable.update(('Per-lane acceptance missing: ' + lane, 'Runtime testing deferred: ' + lane))
            blockers = [b for b in blockers if b not in removable]
    alternative = unofficial(record, risks, ack, blockers, package_identity, accepted_runtime_ids) if version == 3 else {}
    if initial_policy:
        alternative.update(runtime_acceptance_exception=record['runtime_acceptance_exception'],
                           runtime_exception_active=runtime_active,
                           runtime_admission='owner_accepted_runtime_limitations' if runtime_active else 'blocked')
    if skin_policy:
        material_active = False; material_ids = []; material_actions = []
        if material_policy:
            material_active, material_ids, material_actions = original_assets.evaluate(
                record, package_identity, acceptance_lanes, package_manifest, release_history, utc_now())
            if material_active:
                removable = {'rights_approved', *('Unresolved risk: '+rid for rid in material_ids)}
                blockers = [b for b in blockers if b not in removable]
            else:
                blockers.append('Exact original-assets policy missing independent review or current expiry')
        skin_active, skin_ids = skin_alpha(record, acceptance_lanes, risks, ack,
            package_identity, release_history, package_manifest, blockers,
            material_policy=(material_active, material_actions) if material_policy else None)
        if skin_active:
            removable = {'Unresolved risk: ' + rid for rid in skin_ids}
            removable.update(('Per-lane acceptance missing: omega', 'Runtime testing deferred: omega'))
            blockers = [b for b in blockers if b not in removable]
        alternative.update(skin_alpha_evidence=record['skin_alpha_evidence'],
                           skin_alpha_evidence_sha256=exception_digest(record['skin_alpha_evidence']),
                           skin_alpha_policy_active=skin_active,
                           skin_alpha_admission='owner_reported_use_with_reviewed_distribution_delta' if skin_active else 'blocked',
                           runtime_admission='owner_reported_skin_alpha_limitations' if skin_active else 'blocked',
                           native_evidence_grade='owner_reported_general_use',
                           cleaned_package_native_accepted=False, publication_authorized=False)
        if material_policy:
            alternative.update(original_assets_admission=record['original_assets_admission'],
                original_assets_admission_sha256=exception_digest(record['original_assets_admission']),
                original_assets_policy_active=material_active,
                material_rights_admission='owner_directed_exact_package_exception' if material_active else 'blocked',
                third_party_permission_established=False, distribution_package_native_accepted=False,
                accepted_technical_findings=record['original_assets_admission']['technical_findings'])
    if version in (3, 4, 5):
        alternative['package_distribution_eligible'] = not any(b != 'release_approved' for b in blockers)
    require(not record['release_approved'] or not blockers,
            'final release approval contradicts outstanding gates')
    return {**scope, **alternative, 'schema_version': version, 'approval_policy': policy, 'approval_lanes': record['approval_lanes'],
            'release_status': record['release_decision']['status'],
            'rights_status': record['rights_review']['status'], 'rights_review': record['rights_review'],
            'technical_release_status': record['technical_release']['status'],
            'technical_release': record['technical_release'], 'release_decision': record['release_decision'],
            'owner_acknowledgment': ack, 'runtime': runtime, 'unresolved_risks': risks,
            'recorded_limitations': record.get('limitations', []),
            'recorded_native_scope': record.get('native_scope', {}),
            'limitations': [], 'release_blockers': sorted(set(blockers))}
