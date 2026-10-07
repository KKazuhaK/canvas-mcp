"""Tests for the pure claim-authorization rules."""

import pytest

from canvas_mcp.core.credentials import RequestPrincipal
from canvas_mcp.core.selfhost.identity import (
    ClaimsDenied,
    ClaimsPolicy,
    authorize_id_token_claims,
    evaluate_entra_claims,
    principal_key,
)

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID = "99999999-8888-7777-6666-555555555555"
POLICY = ClaimsPolicy(tenant_id=TENANT, client_id=CLIENT, required_role="Canvas.User", owner_role="Canvas.Owner")


def _claims(**overrides):
    claims = {
        "tid": TENANT, "azp": CLIENT, "oid": OID, "roles": ["Canvas.User"],
        "name": "Ada Lovelace", "preferred_username": "ada@example.test",
    }
    for key, value in overrides.items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    return claims


def _denied(claims, kind="access") -> ClaimsDenied:
    result = evaluate_entra_claims(claims, POLICY, token_kind=kind)
    assert isinstance(result, ClaimsDenied), result
    return result


class TestAccess:
    def test_valid_user(self):
        result = evaluate_entra_claims(_claims(), POLICY, token_kind="access")
        assert isinstance(result, RequestPrincipal)
        assert result.key == f"entra:{TENANT}:{OID}"
        assert (result.tenant_id, result.object_id) == (TENANT, OID)
        assert result.display_name == "Ada Lovelace"
        assert result.upn == "ada@example.test"
        assert result.roles == frozenset({"Canvas.User"})
        assert result.is_owner is False

    def test_owner_role_alone_grants_access_and_marks_owner(self):
        result = evaluate_entra_claims(_claims(roles=["Canvas.Owner"]), POLICY, token_kind="access")
        assert isinstance(result, RequestPrincipal)
        assert result.is_owner is True

    def test_both_roles(self):
        result = evaluate_entra_claims(_claims(roles=["Canvas.User", "Canvas.Owner", "Other"]), POLICY, token_kind="access")
        assert isinstance(result, RequestPrincipal)
        assert result.is_owner is True
        assert "Other" in result.roles

    def test_other_tenant(self):
        assert _denied(_claims(tid="00000000-0000-0000-0000-000000000000")).reason == "wrong_tenant"

    @pytest.mark.parametrize("tid", [None, 123, ["x"], ""])
    def test_tenant_must_be_a_matching_string(self, tid):
        assert _denied(_claims(tid=tid)).reason == "wrong_tenant"

    def test_other_client(self):
        assert _denied(_claims(azp="00000000-0000-0000-0000-000000000000")).reason == "wrong_client"

    def test_missing_azp(self):
        assert _denied(_claims(azp=None)).reason == "wrong_client"

    @pytest.mark.parametrize("oid", [None, "", "not-a-guid", 42, OID + "x"])
    def test_bad_subject(self, oid):
        assert _denied(_claims(oid=oid)).reason == "bad_subject"

    def test_missing_roles_claim(self):
        assert _denied(_claims(roles=None)).reason == "missing_role"

    def test_roles_without_a_granting_role(self):
        assert _denied(_claims(roles=["Something.Else"])).reason == "missing_role"
        assert _denied(_claims(roles=[])).reason == "missing_role"

    def test_role_comparison_is_exact(self):
        assert _denied(_claims(roles=["canvas.user"])).reason == "missing_role"

    @pytest.mark.parametrize("roles", ["Canvas.User", 1, {"Canvas.User": True}, ["Canvas.User", 7], ("Canvas.User",)])
    def test_roles_of_the_wrong_shape_are_rejected(self, roles):
        assert _denied(_claims(roles=roles)).reason == "bad_roles"

    def test_a_roles_string_containing_the_role_is_still_rejected(self):
        # "Canvas.User" in "Canvas.User Canvas.Owner" would be a substring match.
        assert _denied(_claims(roles="Canvas.User Canvas.Owner")).reason == "bad_roles"

    def test_guids_compare_case_insensitively_and_the_key_is_lower_case(self):
        result = evaluate_entra_claims(
            _claims(tid=TENANT.upper(), azp=CLIENT.upper(), oid=OID.upper()), POLICY, token_kind="access"
        )
        assert isinstance(result, RequestPrincipal)
        assert result.key == f"entra:{TENANT}:{OID}"
        assert result.object_id == OID

    def test_tenant_is_checked_before_everything_else(self):
        assert _denied(_claims(tid="x", azp="y", oid="z", roles=None)).reason == "wrong_tenant"

    def test_long_names_are_truncated(self):
        result = evaluate_entra_claims(
            _claims(name="n" * 500, preferred_username="u" * 500), POLICY, token_kind="access"
        )
        assert isinstance(result, RequestPrincipal)
        assert len(result.display_name) == 200
        assert len(result.upn) == 254

    def test_upn_falls_back_and_missing_names_are_empty(self):
        result = evaluate_entra_claims(
            _claims(name=None, preferred_username=None, upn="u@example.test"), POLICY, token_kind="access"
        )
        assert isinstance(result, RequestPrincipal)
        assert (result.display_name, result.upn) == ("", "u@example.test")

    def test_messages_are_fixed_english(self):
        message = _denied(_claims(roles=[])).message
        assert message == (
            "Your Microsoft account is not allowed to use this server. "
            "Ask the server owner to add you to the access group."
        )
        for reason_claims in (_claims(tid="x"), _claims(azp="x"), _claims(oid="x"), _claims(roles="x")):
            denied = _denied(reason_claims)
            assert denied.message and TENANT not in denied.message and OID not in denied.message


class TestIdToken:
    def test_azp_is_not_required_for_id_tokens(self):
        for azp in (None, "00000000-0000-0000-0000-000000000000"):
            result = evaluate_entra_claims(_claims(azp=azp), POLICY, token_kind="id")
            assert isinstance(result, RequestPrincipal)

    def test_other_checks_still_apply(self):
        assert _denied(_claims(tid="x"), "id").reason == "wrong_tenant"
        assert _denied(_claims(oid="x"), "id").reason == "bad_subject"
        assert _denied(_claims(roles=[]), "id").reason == "missing_role"


class TestAdapter:
    def test_success_shape(self):
        principal, message = authorize_id_token_claims(POLICY)(_claims(azp=None))
        assert isinstance(principal, RequestPrincipal)
        assert message == ""

    def test_denied_shape(self):
        principal, message = authorize_id_token_claims(POLICY)(_claims(roles=[]))
        assert principal is None
        assert "not allowed to use this server" in message


def test_principal_key_is_lower_case():
    assert principal_key(TENANT.upper(), OID.upper()) == f"entra:{TENANT}:{OID}"
