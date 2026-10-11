"""Verified Entra ID-token reduction and the separate admission decision."""

import pytest

from canvas_mcp.core.selfhost.accounts import (
    DENY_BAD_ROLES,
    DENY_BAD_SUBJECT,
    DENY_WRONG_TENANT,
    Denied,
    EntraClaimsPolicy,
    ExternalClaims,
    default_policy,
    entra_external_claims,
    entra_issuer,
    evaluate_admission,
)

TENANT = '11111111-2222-3333-4444-555555555555'
CLIENT = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
OID = '99999999-8888-7777-6666-555555555555'
POLICY = EntraClaimsPolicy(TENANT, CLIENT)


def claims(**overrides):
    values = {'tid': TENANT, 'oid': OID, 'roles': ['Canvas.User'],
              'name': 'Ada Lovelace', 'preferred_username': 'ada@example.test'}
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not ...}


def external(**overrides):
    result = entra_external_claims(claims(**overrides), POLICY)
    assert isinstance(result, ExternalClaims)
    return result


def test_verified_identity_has_stable_provider_key_and_informational_names():
    result = external()
    assert result.identity == ('entra', entra_issuer(TENANT), OID)
    assert result.display_name == 'Ada Lovelace'
    assert result.username == 'ada@example.test'
    assert result.roles == frozenset({'Canvas.User'})


@pytest.mark.parametrize('tid', [None, 123, ['x'], '', '00000000-0000-0000-0000-000000000000'])
def test_wrong_tenant_is_refused_before_subject_or_roles(tid):
    result = entra_external_claims(claims(tid=tid, oid='bad', roles=3), POLICY)
    assert isinstance(result, Denied) and result.code == DENY_WRONG_TENANT
    assert result.message == "Your Microsoft account belongs to a different directory than this server accepts."


@pytest.mark.parametrize('oid', [None, '', 'not-a-guid', 42, OID + 'x'])
def test_bad_subject_is_refused(oid):
    result = entra_external_claims(claims(oid=oid), POLICY)
    assert isinstance(result, Denied) and result.code == DENY_BAD_SUBJECT


@pytest.mark.parametrize('roles', ['Canvas.User', 1, {'Canvas.User': True}, ['Canvas.User', 7], ('Canvas.User',), None])
def test_malformed_role_claim_is_refused(roles):
    result = entra_external_claims(claims(roles=roles), POLICY)
    assert isinstance(result, Denied) and result.code == DENY_BAD_ROLES


@pytest.mark.parametrize('roles', [[], ..., ['Other'], ['canvas.user']])
def test_well_formed_identity_without_admission_is_not_a_reduction_error(roles):
    ext = external(roles=roles)
    verdict = evaluate_admission(ext, default_policy('Canvas.User', 'Canvas.Owner'))
    assert not verdict.admitted_by_rule and not verdict.owner_by_rule


@pytest.mark.parametrize('roles,admitted,owner', [
    (['Canvas.User'], True, False), (['Canvas.Owner'], False, True),
    (['Canvas.User', 'Canvas.Owner'], True, True),
])
def test_admission_and_owner_evidence_are_evaluated_separately(roles, admitted, owner):
    verdict = evaluate_admission(external(roles=roles), default_policy('Canvas.User', 'Canvas.Owner'))
    assert verdict.admitted_by_rule is admitted and verdict.owner_by_rule is owner


@pytest.mark.parametrize('azp', [None, CLIENT, 'another-client'])
def test_id_tokens_do_not_require_an_access_token_azp_claim(azp):
    assert external(azp=azp).subject == OID


def test_guids_are_canonical_and_names_are_bounded():
    ext = external(tid=TENANT.upper(), oid=OID.upper(), name='n' * 500, preferred_username='u' * 500)
    assert ext.tenant_id == TENANT and ext.subject == OID
    assert len(ext.display_name) == 200 and len(ext.username) == 254
    assert external(name=None, preferred_username=None, upn='u@example.test').username == 'u@example.test'


def test_group_claims_are_optional_and_overage_never_fetches_membership():
    group = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    ext = entra_external_claims(claims(groups=[group.upper(), 'invalid', 7]), POLICY)
    assert isinstance(ext, ExternalClaims) and ext.groups == frozenset({group})
    ext = entra_external_claims(claims(groups=[group]), POLICY, parse_groups=False)
    assert isinstance(ext, ExternalClaims) and ext.groups == frozenset()
    ext = external(groups=[group], _claim_names={'groups': 'source'})
    assert ext.groups_overage and ext.groups == frozenset()
