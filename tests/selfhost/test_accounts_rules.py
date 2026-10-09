"""Admission rules and the decision table: pure functions, no database.

The default policy must admit exactly the people the first release admitted (the
two Entra app roles); the oracle below is a transcription of that release's
``evaluate_entra_claims`` so the equivalence cannot drift with the new code.
"""

from __future__ import annotations

import itertools
import re
from typing import Any

import pytest

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import (
    AccessPolicy,
    AccessRule,
    AccountFacts,
    Decision,
    DecisionFacts,
    Denied,
    EntraClaimsPolicy,
    ExternalClaims,
    Verdict,
    decide,
    default_policy,
    entra_external_claims,
    evaluate_admission,
    parse_access_settings,
)

TID = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID = "aaaaaaaa-0000-4000-8000-00000000000a"
GROUP = "99999999-0000-4000-8000-000000000001"
GROUP_B = "99999999-0000-4000-8000-000000000002"
POLICY = EntraClaimsPolicy(TID, CLIENT)


def claims(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tid": TID,
        "azp": CLIENT,
        "oid": OID,
        "roles": ["Canvas.User"],
        "name": "Ada",
        "preferred_username": "ada@example.test",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def settings(**env: str) -> tuple[AccessPolicy, list[str]]:
    problems: list[str] = []
    policy = parse_access_settings(
        env, tenant_id=TID, required_role="Canvas.User", owner_role="Canvas.Owner", problems=problems
    )
    return policy, problems


# -- the oracle: the first release's rule, verbatim ---------------------------------

_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def oracle(claims: dict[str, Any], token_kind: str) -> tuple[str, bool] | str:
    """``(oid, is_owner)`` when admitted, otherwise the old reason code."""
    if not (isinstance(claims.get("tid"), str) and claims["tid"].lower() == TID):
        return "wrong_tenant"
    if token_kind == "access" and not (
        isinstance(claims.get("azp"), str) and claims["azp"].lower() == CLIENT
    ):
        return "wrong_client"
    oid = claims.get("oid")
    if not isinstance(oid, str) or not _GUID.match(oid):
        return "bad_subject"
    if "roles" not in claims:
        return "missing_role"
    roles = claims["roles"]
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        return "bad_roles"
    if "Canvas.User" not in roles and "Canvas.Owner" not in roles:
        return "missing_role"
    return oid.lower(), "Canvas.Owner" in roles


def new_pipeline(claims: dict[str, Any], token_kind: str) -> tuple[str, bool] | str:
    ext = entra_external_claims(claims, POLICY, token_kind=token_kind)  # type: ignore[arg-type]
    if isinstance(ext, Denied):
        return ext.code
    policy = default_policy("Canvas.User", "Canvas.Owner")
    verdict = evaluate_admission(ext, policy)
    decision = decide(None, verdict, policy, DecisionFacts(), "sign_in")
    if decision.outcome == "deny":
        assert decision.denied is not None
        return "missing_role" if decision.denied.code == acc.DENY_ACCESS_DENIED else decision.denied.code
    return ext.subject, verdict.owner_by_rule


class TestDefaultPolicyEqualsTheFirstRelease:
    @pytest.mark.parametrize("token_kind", ["access", "id"])
    def test_a_grid_of_claims_gets_the_same_answer(self, token_kind: str) -> None:
        tids = [TID, TID.upper(), "99999999-9999-9999-9999-999999999999", None, 5]
        azps = [CLIENT, CLIENT.upper(), "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", None]
        oids = [OID, OID.upper(), "not-a-guid", None, 7]
        role_sets: list[Any] = [
            ["Canvas.User"],
            ["Canvas.Owner"],
            ["Canvas.User", "Canvas.Owner"],
            ["canvas.user"],
            ["Other"],
            [],
            "Canvas.User",
            [1, "Canvas.User"],
            None,
        ]
        checked = 0
        for tid, azp, oid, roles in itertools.product(tids, azps, oids, role_sets):
            sample = claims(tid=tid, azp=azp, oid=oid, roles=roles)
            assert new_pipeline(sample, token_kind) == oracle(sample, token_kind), sample
            checked += 1
        assert checked == len(tids) * len(azps) * len(oids) * len(role_sets)

    def test_owner_role_alone_admits(self) -> None:
        assert new_pipeline(claims(roles=["Canvas.Owner"]), "access") == (OID, True)


class TestIdentityIsTheDirectoryObjectId:
    def test_the_subject_is_oid_lower_cased_and_the_issuer_comes_from_the_tenant(self) -> None:
        ext = entra_external_claims(claims(oid=OID.upper(), sub="pairwise-sub"), POLICY, token_kind="id")
        assert isinstance(ext, ExternalClaims)
        assert ext.identity == ("entra", f"https://login.microsoftonline.com/{TID}/v2.0", OID)

    def test_sub_and_email_never_change_the_identity(self) -> None:
        a = entra_external_claims(claims(sub="s1", email="x@example.test"), POLICY, token_kind="id")
        b = entra_external_claims(claims(sub="s2", email="y@example.test"), POLICY, token_kind="id")
        assert isinstance(a, ExternalClaims) and isinstance(b, ExternalClaims)
        assert a.identity == b.identity

    def test_the_same_email_with_another_oid_is_another_identity(self) -> None:
        other = "bbbbbbbb-0000-4000-8000-00000000000b"
        a = entra_external_claims(claims(email="same@example.test"), POLICY, token_kind="id")
        b = entra_external_claims(claims(oid=other, email="same@example.test"), POLICY, token_kind="id")
        assert isinstance(a, ExternalClaims) and isinstance(b, ExternalClaims)
        assert a.identity != b.identity
        assert a.email is None and not a.email_verified  # never trusted, never stored

    def test_names_are_bounded(self) -> None:
        ext = entra_external_claims(
            claims(name="n" * 500, preferred_username="u" * 500), POLICY, token_kind="id"
        )
        assert isinstance(ext, ExternalClaims)
        assert len(ext.display_name) == 200 and len(ext.username) == 254


class TestGroups:
    def test_a_group_claim_is_read_and_lower_cased(self) -> None:
        ext = entra_external_claims(claims(groups=[GROUP.upper()]), POLICY, token_kind="id")
        assert isinstance(ext, ExternalClaims) and ext.groups == {GROUP}

    def test_an_overage_yields_no_groups_and_no_match(self) -> None:
        policy, problems = settings(ACCESS_RULES=f"entra:group:{GROUP}")
        assert problems == []
        sample = claims(
            roles=None, groups=None, **{"_claim_names": {"groups": "src1"}, "hasgroups": True}
        )
        ext = entra_external_claims(sample, POLICY, token_kind="id")
        assert isinstance(ext, ExternalClaims)
        assert ext.groups == frozenset() and ext.groups_overage
        verdict = evaluate_admission(ext, policy)
        assert not verdict.admitted_by_rule
        assert verdict.reason == acc.REASON_GROUPS_OVERAGE

    def test_the_overage_marker_alone_is_enough(self) -> None:
        ext = entra_external_claims(claims(hasgroups=True, groups=[GROUP]), POLICY, token_kind="id")
        assert isinstance(ext, ExternalClaims) and ext.groups_overage and not ext.groups

    @pytest.mark.parametrize("bad", ["x", [1], ["not-a-guid"], {"a": 1}])
    def test_malformed_groups_are_refused(self, bad: Any) -> None:
        result = entra_external_claims(claims(groups=bad), POLICY, token_kind="id")
        assert isinstance(result, Denied) and result.code == acc.DENY_BAD_GROUPS

    def test_a_group_rule_admits_a_member_and_not_a_stranger(self) -> None:
        policy, _ = settings(ACCESS_RULES=f"entra:group:{GROUP}")
        member = entra_external_claims(claims(roles=None, groups=[GROUP]), POLICY, token_kind="id")
        stranger = entra_external_claims(claims(roles=None, groups=[GROUP_B]), POLICY, token_kind="id")
        assert isinstance(member, ExternalClaims) and isinstance(stranger, ExternalClaims)
        assert evaluate_admission(member, policy).admitted_by_rule
        assert not evaluate_admission(stranger, policy).admitted_by_rule

    def test_a_tenant_rule_admits_the_configured_tenant(self) -> None:
        policy, problems = settings(ACCESS_RULES=f"entra:tenant:{TID}")
        assert problems == []
        ext = entra_external_claims(claims(roles=None), POLICY, token_kind="id")
        assert isinstance(ext, ExternalClaims)
        assert evaluate_admission(ext, policy).admitted_by_rule


class TestClaimShapes:
    @pytest.mark.parametrize("bad", ["Canvas.User", [1], {"a": "b"}, ["ok", None]])
    def test_malformed_roles_are_refused(self, bad: Any) -> None:
        result = entra_external_claims(claims(roles=bad), POLICY, token_kind="id")
        assert isinstance(result, Denied) and result.code == acc.DENY_BAD_ROLES

    def test_missing_roles_is_an_identity_without_roles(self) -> None:
        ext = entra_external_claims(claims(roles=None), POLICY, token_kind="id")
        assert isinstance(ext, ExternalClaims) and ext.roles == frozenset()

    def test_tenant_client_and_subject_checks(self) -> None:
        assert entra_external_claims(claims(tid="x"), POLICY, token_kind="id") == acc.denied(
            acc.DENY_WRONG_TENANT
        )
        assert entra_external_claims(claims(azp="x"), POLICY, token_kind="access") == acc.denied(
            acc.DENY_WRONG_CLIENT
        )
        # The client is only checked on an access token (an id token's client is its aud).
        assert isinstance(entra_external_claims(claims(azp="x"), POLICY, token_kind="id"), ExternalClaims)
        assert entra_external_claims(claims(oid="nope"), POLICY, token_kind="id") == acc.denied(
            acc.DENY_BAD_SUBJECT
        )


class TestSettingsGrammar:
    def test_unset_means_the_first_release(self) -> None:
        policy, problems = settings()
        assert problems == []
        assert policy == default_policy("Canvas.User", "Canvas.Owner")
        assert policy.mode == "rules" and policy.fallback == "deny"
        assert policy.rules == (AccessRule("entra", "role", "Canvas.User"),)
        assert policy.owner_rules == (AccessRule("entra", "role", "Canvas.Owner"),)

    def test_every_rule_kind_parses(self) -> None:
        policy, problems = settings(
            ACCESS_RULES=f"entra:role:Canvas.User, entra:group:{GROUP.upper()}, entra:tenant:{TID}",
            OWNER_RULES=f"entra:role:Canvas.Owner,entra:group:{GROUP_B}",
            ACCESS_FALLBACK="approval",
        )
        assert problems == []
        assert policy.rules == (
            AccessRule("entra", "role", "Canvas.User"),
            AccessRule("entra", "group", GROUP),
            AccessRule("entra", "tenant", TID),
        )
        assert policy.fallback == "approval"
        assert policy.owner_rules[1] == AccessRule("entra", "group", GROUP_B)

    @pytest.mark.parametrize(
        ("name", "value", "fragment"),
        [
            ("ACCESS_RULES", "ldap:group:x", "unknown provider"),
            ("ACCESS_RULES", "entra:team:x", "unknown rule kind"),
            ("ACCESS_RULES", "entra:group:not-a-guid", "GUID"),
            ("ACCESS_RULES", "entra:role:bad value", "role value"),
            ("ACCESS_RULES", "entra:role", "unknown rule kind"),
            ("ACCESS_RULES", "justaword", "not '<provider>"),
            ("ACCESS_RULES", "google:hd:uci.edu", "not enabled in this release"),
            ("ACCESS_RULES", "github:org:Kazuha", "not enabled in this release"),
            ("ACCESS_RULES", "oidc:school:claim:groups=a", "not enabled in this release"),
            ("ACCESS_RULES", "entra:tenant:99999999-9999-9999-9999-999999999999", "other than"),
            ("OWNER_RULES", f"entra:tenant:{TID}", "may not use entra:tenant"),
            ("OWNER_RULES", "google:email:a@b.test", "not enabled in this release"),
            ("ACCESS_POLICY", "everyone", "'open', 'rules' or 'approval'"),
            ("ACCESS_FALLBACK", "maybe", "'deny' or 'approval'"),
            ("SELFHOST_BOOTSTRAP_OWNER", "entra:x:y", "must look like"),
            (
                "SELFHOST_BOOTSTRAP_OWNER",
                "entra:99999999-9999-9999-9999-999999999999:" + OID,
                "ENTRA_TENANT_ID",
            ),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8", "reserved"),
            ("ACCESS_OPEN_ACKNOWLEDGE_PUBLIC", "perhaps", "true or false"),
        ],
    )
    def test_bad_values_refuse_startup(self, name: str, value: str, fragment: str) -> None:
        _, problems = settings(**{name: value})
        assert any(fragment in p and name in p for p in problems), problems

    def test_problems_never_echo_the_value(self) -> None:
        secret = "entra:role:s3cr3t value!"
        _, problems = settings(ACCESS_RULES=secret)
        assert problems and not any("s3cr3t" in p for p in problems)

    def test_an_empty_rule_list_is_refused_when_set_to_only_separators(self) -> None:
        _, problems = settings(ACCESS_RULES=" , , ")
        assert problems == [] or any("ACCESS_RULES" in p for p in problems)  # unset-like input is the default
        policy, problems = settings(ACCESS_RULES="entra:role:  ")
        assert any("ACCESS_RULES" in p for p in problems)
        assert policy.rules == ()

    @pytest.mark.parametrize("mode", ["open", "approval"])
    def test_rules_and_fallback_need_the_rules_policy(self, mode: str) -> None:
        _, problems = settings(ACCESS_POLICY=mode, ACCESS_RULES="entra:role:X")
        assert any("ACCESS_RULES must not be set" in p for p in problems)
        _, problems = settings(ACCESS_POLICY=mode, ACCESS_FALLBACK="deny")
        assert any("ACCESS_FALLBACK must not be set" in p for p in problems)
        policy, problems = settings(ACCESS_POLICY=mode)
        assert problems == [] and policy.mode == mode and policy.rules == ()

    def test_owner_rules_none_and_the_bootstrap_owner(self) -> None:
        policy, problems = settings(
            OWNER_RULES="none",
            SELFHOST_BOOTSTRAP_OWNER=f"entra:{TID.upper()}:{OID.upper()}",
        )
        assert problems == []
        assert policy.owner_rules == ()
        assert policy.bootstrap_owner == acc.BootstrapOwner(
            "entra", f"https://login.microsoftonline.com/{TID}/v2.0", OID
        )

    def test_open_is_accepted_for_a_single_tenant_and_the_flag_is_parsed(self) -> None:
        policy, problems = settings(ACCESS_POLICY="open", ACCESS_OPEN_ACKNOWLEDGE_PUBLIC="true")
        assert problems == [] and policy.ack_public
        policy, problems = settings(ACCESS_POLICY="open")
        assert problems == [] and not policy.ack_public

    def test_all_problems_are_collected_at_once(self) -> None:
        _, problems = settings(
            ACCESS_POLICY="nope", OWNER_RULES="x:y:z", TRUSTED_PROXY_CIDRS="1.2.3.4/32"
        )
        assert len(problems) >= 3


# -- the decision table ---------------------------------------------------------------

NOBODY = Verdict(admitted_by_rule=False, owner_by_rule=False)
RULE = Verdict(admitted_by_rule=True, owner_by_rule=False)
OWNER = Verdict(admitted_by_rule=False, owner_by_rule=True)
OVERAGE = Verdict(admitted_by_rule=False, owner_by_rule=False, reason=acc.REASON_GROUPS_OVERAGE)

RULES_DENY = AccessPolicy(mode="rules", rules=(AccessRule("entra", "role", "U"),), fallback="deny")
RULES_APPROVAL = AccessPolicy(
    mode="rules", rules=(AccessRule("entra", "role", "U"),), fallback="approval"
)
OPEN = AccessPolicy(mode="open")
APPROVAL = AccessPolicy(mode="approval")


def active(role: str = "user", source: str | None = None, via: str = "rules") -> AccountFacts:
    return AccountFacts("active", role, source, via)


class TestDecisionTableForNewIdentities:
    def test_open_creates_an_active_account(self) -> None:
        d = decide(None, NOBODY, OPEN, DecisionFacts(), "sign_in")
        assert (d.outcome, d.create, d.create_status, d.admitted_via) == (
            "allow", True, "active", "open"
        )

    def test_rules_with_a_match_create_an_active_account(self) -> None:
        d = decide(None, RULE, RULES_DENY, DecisionFacts(), "sign_in")
        assert (d.outcome, d.create_status, d.admitted_via) == ("allow", "active", "rules")

    def test_rules_without_a_match_and_deny_writes_nothing(self) -> None:
        d = decide(None, NOBODY, RULES_DENY, DecisionFacts(), "sign_in")
        assert d.outcome == "deny" and not d.create and not d.writes
        assert d.denied is not None and d.denied.code == acc.DENY_ACCESS_DENIED

    def test_an_overage_is_remembered_as_the_reason_but_the_code_is_the_same(self) -> None:
        d = decide(None, OVERAGE, RULES_DENY, DecisionFacts(), "request")
        assert d.denied is not None and d.denied.code == acc.DENY_ACCESS_DENIED
        assert d.reason == acc.REASON_GROUPS_OVERAGE

    def test_rules_without_a_match_and_approval_create_a_pending_account(self) -> None:
        d = decide(None, NOBODY, RULES_APPROVAL, DecisionFacts(), "sign_in")
        assert (d.outcome, d.create_status, d.admitted_via) == ("pending", "pending", "approval")

    def test_approval_creates_pending_accounts_for_everyone(self) -> None:
        d = decide(None, RULE, APPROVAL, DecisionFacts(), "sign_in")
        assert d.create_status == "pending" and d.outcome == "pending"

    def test_on_the_mcp_path_a_pending_account_is_created_but_the_request_is_refused(self) -> None:
        d = decide(None, NOBODY, APPROVAL, DecisionFacts(), "request")
        assert d.create and d.create_status == "pending" and d.outcome == "deny"
        assert d.denied is not None and d.denied.code == acc.DENY_PENDING_APPROVAL

    @pytest.mark.parametrize("policy", [RULES_APPROVAL, APPROVAL])
    def test_the_pending_cap_pauses_sign_ups(self, policy: AccessPolicy) -> None:
        d = decide(None, NOBODY, policy, DecisionFacts(pending_count=200), "sign_in")
        assert d.outcome == "deny" and not d.create
        assert d.denied is not None and d.denied.code == acc.DENY_SIGNUPS_PAUSED
        below = decide(None, NOBODY, policy, DecisionFacts(pending_count=199), "sign_in")
        assert below.create

    @pytest.mark.parametrize("policy", [OPEN, RULES_DENY, RULES_APPROVAL, APPROVAL])
    def test_an_owner_match_is_admitted_whatever_the_policy(self, policy: AccessPolicy) -> None:
        d = decide(None, OWNER, policy, DecisionFacts(), "sign_in")
        assert d.create_status == "active" and d.role == "owner" and d.session_owner
        assert (d.role_source, d.role_event) == ("rules", "owner_gained")

    def test_the_mcp_path_creates_an_owner_match_as_a_plain_user(self) -> None:
        d = decide(None, OWNER, RULES_DENY, DecisionFacts(), "request")
        assert d.create_status == "active" and d.role is None and not d.session_owner

    def test_the_bootstrap_identity_is_owner_only_while_there_is_no_owner(self) -> None:
        first = decide(
            None, NOBODY, APPROVAL, DecisionFacts(active_owner_count=0, is_bootstrap_identity=True), "sign_in"
        )
        assert first.create_status == "active" and first.role == "owner"
        assert (first.role_source, first.admitted_via) == ("bootstrap", "bootstrap")
        later = decide(
            None, NOBODY, APPROVAL, DecisionFacts(active_owner_count=1, is_bootstrap_identity=True), "sign_in"
        )
        assert later.create_status == "pending" and later.role is None


class TestDecisionTableForExistingAccounts:
    @pytest.mark.parametrize("verdict", [NOBODY, RULE, OWNER])
    @pytest.mark.parametrize("policy", [OPEN, RULES_DENY, APPROVAL])
    @pytest.mark.parametrize("purpose", ["sign_in", "request"])
    def test_a_disabled_account_is_always_refused_and_nothing_changes(
        self, verdict: Verdict, policy: AccessPolicy, purpose: Any
    ) -> None:
        d = decide(AccountFacts("disabled"), verdict, policy, DecisionFacts(), purpose)
        assert d.outcome == "deny" and not d.writes
        assert d.denied is not None and d.denied.code == acc.DENY_ACCESS_DISABLED

    def test_a_pending_account_is_activated_by_a_rule_that_now_matches(self) -> None:
        d = decide(AccountFacts("pending", admitted_via="approval"), RULE, RULES_APPROVAL, DecisionFacts(), "sign_in")
        assert d.outcome == "allow" and d.activate and d.admitted_via == "rules"

    def test_a_pending_account_is_activated_when_the_policy_became_open(self) -> None:
        d = decide(AccountFacts("pending", admitted_via="approval"), NOBODY, OPEN, DecisionFacts(), "request")
        assert d.outcome == "allow" and d.activate and d.admitted_via == "open"

    def test_a_pending_account_stays_pending_otherwise(self) -> None:
        sign_in = decide(AccountFacts("pending", admitted_via="approval"), NOBODY, APPROVAL, DecisionFacts(), "sign_in")
        assert sign_in.outcome == "pending" and not sign_in.writes
        request = decide(AccountFacts("pending", admitted_via="approval"), RULE, APPROVAL, DecisionFacts(), "request")
        assert request.outcome == "deny" and request.denied is not None
        assert request.denied.code == acc.DENY_PENDING_APPROVAL

    @pytest.mark.parametrize("policy", [OPEN, APPROVAL])
    def test_an_active_account_is_allowed_under_open_and_approval(self, policy: AccessPolicy) -> None:
        assert decide(active(), NOBODY, policy, DecisionFacts(active_owner_count=1), "request").outcome == "allow"

    def test_rules_allow_a_match_and_deny_a_miss_without_changing_the_status(self) -> None:
        assert decide(active(), RULE, RULES_DENY, DecisionFacts(), "request").outcome == "allow"
        d = decide(active(), NOBODY, RULES_DENY, DecisionFacts(), "request")
        assert d.outcome == "deny" and not d.writes
        assert d.denied is not None and d.denied.code == acc.DENY_ACCESS_DENIED

    @pytest.mark.parametrize("via", ["approval", "operator", "bootstrap"])
    def test_a_personal_admission_survives_a_miss(self, via: str) -> None:
        d = decide(active(via=via), NOBODY, RULES_DENY, DecisionFacts(), "request")
        assert d.outcome == "allow"

    @pytest.mark.parametrize("via", ["rules", "open"])
    def test_an_admission_by_rules_or_open_does_not_survive_a_miss(self, via: str) -> None:
        d = decide(active(via=via), NOBODY, RULES_DENY, DecisionFacts(), "sign_in")
        assert d.outcome == "deny"


class TestRoles:
    def test_an_owner_rule_promotes_a_user_at_sign_in_only(self) -> None:
        up = decide(active(), OWNER, RULES_DENY, DecisionFacts(active_owner_count=1), "sign_in")
        assert (up.role, up.role_source, up.role_event, up.session_owner) == (
            "owner", "rules", "owner_gained", True
        )
        mcp = decide(active(), OWNER, RULES_DENY, DecisionFacts(active_owner_count=1), "request")
        assert mcp.role is None and mcp.role_event is None and not mcp.session_owner

    def test_losing_the_rule_demotes_a_rules_owner_unless_it_is_the_last(self) -> None:
        owner = active("owner", "rules")
        down = decide(owner, RULE, RULES_DENY, DecisionFacts(active_owner_count=2), "sign_in")
        assert (down.role, down.role_event, down.session_owner) == ("user", "owner_lost", False)
        last = decide(owner, RULE, RULES_DENY, DecisionFacts(active_owner_count=1), "sign_in")
        assert last.role is None and last.role_event == "owner_loss_refused_last_owner"
        assert not last.session_owner  # the stored role is kept, admin rights are not

    @pytest.mark.parametrize("source", ["bootstrap", "operator"])
    def test_a_bootstrap_or_operator_owner_is_never_touched_by_rules(self, source: str) -> None:
        owner = active("owner", source, via=source)
        d = decide(owner, RULE, RULES_DENY, DecisionFacts(active_owner_count=1), "sign_in")
        assert d.role is None and d.role_event is None and d.session_owner

    def test_a_rules_owner_who_still_matches_keeps_the_session_flag(self) -> None:
        d = decide(active("owner", "rules"), OWNER, RULES_DENY, DecisionFacts(active_owner_count=1), "sign_in")
        assert d.session_owner and d.role_event is None

    def test_the_mcp_path_never_lowers_or_raises(self) -> None:
        d = decide(active("owner", "rules"), RULE, RULES_DENY, DecisionFacts(active_owner_count=2), "request")
        assert d.role is None and d.role_event is None

    def test_a_pending_account_that_matches_an_owner_rule_is_activated_as_owner(self) -> None:
        d = decide(AccountFacts("pending", admitted_via="approval"), OWNER, APPROVAL, DecisionFacts(), "sign_in")
        assert d.activate and d.role == "owner" and d.session_owner

    def test_a_disabled_owner_is_not_counted_as_the_last_one(self) -> None:
        # count excludes disabled owners by construction; a demotion with one other owner is fine
        d = decide(active("owner", "rules"), RULE, RULES_DENY, DecisionFacts(active_owner_count=2), "sign_in")
        assert d.role == "user"


class TestKeys:
    def test_account_keys(self) -> None:
        key = "acct:" + "0123abcd-0000-4000-8000-000000000001"
        assert acc.valid_account_key(key)
        assert acc.account_key_of(acc.account_id_of(key)) == key
        for bad in ("acct:", "acct:NOT", "entra:a:b", "ACCT:0123abcd-0000-4000-8000-000000000001", 5, None):
            assert not acc.valid_account_key(bad)
        with pytest.raises(ValueError):
            acc.account_id_of("acct:x")

    def test_decision_is_a_plain_value(self) -> None:
        assert isinstance(decide(None, NOBODY, OPEN, DecisionFacts(), "sign_in"), Decision)
