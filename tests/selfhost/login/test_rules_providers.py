"""Admission rules for Google, GitHub and generic OIDC, and the owner guarantees around them."""

from __future__ import annotations

from typing import Any

import pytest

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import (
    AccessPolicy,
    AccessRule,
    AccountFacts,
    DecisionFacts,
    ExternalClaims,
    Verdict,
    decide,
    evaluate_admission,
    link_admissible,
    parse_access_settings,
    parse_rule,
)

ALL = ("entra", "google", "github", "oidc:school")
TID = "11111111-2222-3333-4444-555555555555"


def rule(text: str, *, owner: bool = False, providers: Any = ALL) -> AccessRule | str:
    return parse_rule(text, tenant_id=TID, owner=owner, providers=providers)


def google_ext(**kw: Any) -> ExternalClaims:
    base: dict[str, Any] = {
        "provider_id": "google", "issuer": acc.GOOGLE_ISSUER, "subject": "1001",
        "email": "ada@example.edu", "email_verified": True, "hd": "example.edu",
    }
    base.update(kw)
    return ExternalClaims(**base)


def github_ext(**kw: Any) -> ExternalClaims:
    base: dict[str, Any] = {
        "provider_id": "github", "issuer": acc.GITHUB_ISSUER, "subject": "583231", "username": "octocat",
    }
    base.update(kw)
    return ExternalClaims(**base)


def oidc_ext(**kw: Any) -> ExternalClaims:
    base: dict[str, Any] = {
        "provider_id": "oidc:school", "issuer": "https://idp.example.edu", "subject": "u-1",
        "email": "ada@example.edu", "email_verified": True,
    }
    base.update(kw)
    return ExternalClaims(**base)


def policy_of(*rules: str, **kw: Any) -> AccessPolicy:
    parsed = []
    for text in rules:
        got = rule(text)
        assert isinstance(got, AccessRule), got
        parsed.append(got)
    return AccessPolicy(rules=tuple(parsed), **kw)


def admitted(text: str, ext: ExternalClaims) -> bool:
    return evaluate_admission(ext, policy_of(text)).admitted_by_rule


class TestRuleGrammar:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("google:domain:Example.EDU", AccessRule("google", "domain", "example.edu")),
            ("google:email:Ada@Example.edu", AccessRule("google", "email", "ada@example.edu")),
            ("github:user:583231", AccessRule("github", "user", "583231")),
            ("github:org:Acme-Inc", AccessRule("github", "org", "acme-inc")),
            ("github:team:Acme-Inc/Core_Team", AccessRule("github", "team", "acme-inc/core_team")),
            ("oidc:school:any", AccessRule("oidc:school", "any", "")),
            ("oidc:school:email:Ada@Example.edu", AccessRule("oidc:school", "email", "ada@example.edu")),
            ("oidc:school:claim:groups=canvas-users", AccessRule("oidc:school", "claim", "groups=canvas-users")),
            ("oidc:school:claim:realm_access.roles=a b", AccessRule("oidc:school", "claim", "realm_access.roles=a b")),
            ("oidc:school:claim:urn:x/y=1:2", AccessRule("oidc:school", "claim", "urn:x/y=1:2")),
        ],
    )
    def test_good_rules(self, text: str, expected: AccessRule) -> None:
        assert rule(text) == expected

    @pytest.mark.parametrize(
        ("text", "fragment"),
        [
            ("google:hd:example.edu", "unknown rule kind"),
            ("google:domain:not a domain", "domain name"),
            ("google:domain:localhost", "domain name"),
            ("google:email:nobody", "e-mail address"),
            ("github:user:octocat", "numeric GitHub user id"),
            ("github:user:0", "numeric GitHub user id"),
            ("github:org:-bad", "organisation login"),
            ("github:org:" + "a" * 40, "organisation login"),
            ("github:team:acme", "<organisation>/<team slug>"),
            ("github:team:acme/Bad Slug", "<organisation>/<team slug>"),
            ("github:repo:x", "unknown rule kind"),
            ("oidc:school:claim:groups", "claim:<name>=<value>"),
            ("oidc:school:claim:=x", "claim:<name>=<value>"),
            ("oidc:school:claim:a b=x", "plain claim name"),
            ("oidc:school:claim:email=a@b.test", "use the email: kind"),
            ("oidc:school:claim:groups= padded", "claim value"),
            ("oidc:school:claim:groups=", "claim value"),
            ("oidc:school:claim:groups=" + "x" * 257, "claim value"),
            ("oidc:school:claim:groups=café", "claim value"),
            ("oidc:school:group:x", "unknown rule kind"),
            ("oidc:Bad:any", "valid provider slug"),
            ("oidc:school", "valid provider slug"),
            ("oidc:school:email:x", "e-mail address"),
        ],
    )
    def test_bad_rules(self, text: str, fragment: str) -> None:
        got = rule(text)
        assert isinstance(got, str) and fragment in got, got

    def test_a_rule_of_a_provider_that_is_not_listed_keeps_the_old_phrase(self) -> None:
        for text in ("google:domain:a.test", "github:user:1", "oidc:school:any"):
            got = rule(text, providers=None)
            assert isinstance(got, str)
            assert "not enabled in this release" in got
            assert "SELFHOST_LOGIN_PROVIDERS" in got

    def test_owner_rules_accept_only_entra(self) -> None:
        for text in ("google:domain:a.test", "github:user:1", "oidc:school:any"):
            got = rule(text, owner=True)
            assert isinstance(got, str) and "owners come only from Entra" in got
        assert rule("entra:role:Canvas.Owner", owner=True) == AccessRule("entra", "role", "Canvas.Owner")

    def test_str_round_trips(self) -> None:
        for text in ("google:domain:example.edu", "github:team:a/b", "oidc:school:any",
                     "oidc:school:claim:groups=x", "entra:role:R"):
            got = rule(text)
            assert isinstance(got, AccessRule) and str(got) == text

    def test_policy_helpers(self) -> None:
        policy = policy_of(
            "github:org:Acme", "github:team:acme/core", "google:domain:example.edu",
            "oidc:school:claim:groups=a", "oidc:school:claim:dept=b", "github:user:1",
        )
        assert policy.github_orgs() == ("acme",)
        assert policy.github_teams() == ("acme/core",)
        assert policy.google_domains() == ("example.edu",)
        assert policy.oidc_claim_names("oidc:school") == frozenset({"groups", "dept"})
        assert policy.oidc_claim_names("oidc:other") == frozenset()
        assert AccessPolicy().github_orgs() == ()


class TestRuleMatching:
    def test_google_domain_needs_hd_and_a_verified_email(self) -> None:
        assert admitted("google:domain:example.edu", google_ext())
        assert not admitted("google:domain:example.edu", google_ext(email_verified=False))
        # A consumer account has no hd even when its address ends in the domain.
        assert not admitted("google:domain:example.edu", google_ext(hd="", email="ada@example.edu"))
        assert not admitted("google:domain:example.edu", google_ext(hd="other.edu"))
        assert admitted("google:domain:example.edu", google_ext(hd="EXAMPLE.edu"))

    def test_there_is_no_google_email_domain_rule(self) -> None:
        got = rule("google:email_domain:example.edu")
        assert isinstance(got, str)

    def test_google_email_is_exact_and_verified(self) -> None:
        assert admitted("google:email:ada@example.edu", google_ext(email="Ada@Example.edu"))
        assert not admitted("google:email:ada@example.edu", google_ext(email="ada@example.edu", email_verified=False))
        assert not admitted("google:email:ada@example.edu", google_ext(email="ada@example.edu.evil.test"))
        assert not admitted("google:email:ada@example.edu", google_ext(email=None))

    def test_github_user_is_the_numeric_id(self) -> None:
        assert admitted("github:user:583231", github_ext())
        assert not admitted("github:user:583231", github_ext(subject="583232"))
        assert not admitted("github:user:583231", github_ext(username="583231", subject="1"))

    def test_github_org_and_team(self) -> None:
        assert admitted("github:org:acme", github_ext(orgs=frozenset({"acme"})))
        assert not admitted("github:org:acme", github_ext(orgs=frozenset({"other"})))
        assert not admitted("github:org:acme", github_ext())
        assert admitted("github:team:acme/core", github_ext(teams=frozenset({"acme/core"})))
        assert not admitted("github:team:acme/core", github_ext(orgs=frozenset({"acme"})))

    def test_oidc_any_matches_only_its_own_provider(self) -> None:
        assert admitted("oidc:school:any", oidc_ext())
        assert not admitted("oidc:school:any", oidc_ext(provider_id="oidc:other"))
        assert not admitted("oidc:school:any", google_ext())

    def test_oidc_email_needs_the_json_value_true(self) -> None:
        assert admitted("oidc:school:email:ada@example.edu", oidc_ext())
        assert not admitted("oidc:school:email:ada@example.edu", oidc_ext(email_verified=False))

    def test_oidc_claim_is_exact_and_case_sensitive(self) -> None:
        claim = "oidc:school:claim:groups=Canvas-Users"
        assert admitted(claim, oidc_ext(claims=(("groups", ("Canvas-Users",)),)))
        assert admitted(claim, oidc_ext(claims=(("groups", ("a", "Canvas-Users", "b")),)))
        assert not admitted(claim, oidc_ext(claims=(("groups", ("canvas-users",)),)))
        assert not admitted(claim, oidc_ext(claims=(("groups", ("Canvas-Users-Extra",)),)))
        assert not admitted(claim, oidc_ext(claims=(("other", ("Canvas-Users",)),)))
        assert not admitted(claim, oidc_ext())

    def test_a_rule_never_matches_another_providers_identity(self) -> None:
        assert not admitted("google:email:ada@example.edu", oidc_ext())
        assert not admitted("github:user:1", google_ext(subject="1"))

    def test_membership_unavailable_is_the_reason_when_nothing_matched(self) -> None:
        policy = policy_of("github:org:acme")
        verdict = evaluate_admission(github_ext(membership_unavailable=True), policy)
        assert not verdict.admitted_by_rule and verdict.reason == acc.REASON_MEMBERSHIP_UNAVAILABLE
        # A rule that matches wins, and a policy without org rules never reports it.
        assert evaluate_admission(github_ext(orgs=frozenset({"acme"}), membership_unavailable=True), policy).admitted_by_rule
        assert evaluate_admission(github_ext(membership_unavailable=True), policy_of("github:user:1")).reason == acc.REASON_OK

    def test_the_denied_decision_carries_that_reason(self) -> None:
        policy = policy_of("github:org:acme")
        verdict = evaluate_admission(github_ext(membership_unavailable=True), policy)
        decision = decide(None, verdict, policy, DecisionFacts(), "sign_in")
        assert decision.outcome == "deny" and decision.reason == acc.REASON_MEMBERSHIP_UNAVAILABLE
        assert decision.denied is not None and decision.denied.code == acc.DENY_ACCESS_DENIED
        assert decision.reason in acc.AUTH_REASONS


class TestOwners:
    def test_only_entra_ever_has_owner_evidence(self) -> None:
        policy = policy_of("google:domain:example.edu")
        assert evaluate_admission(google_ext(), policy).owner_evidence is False
        entra = ExternalClaims("entra", acc.entra_issuer(TID), "s", roles=frozenset({"Canvas.User"}))
        assert evaluate_admission(entra, acc.default_policy("Canvas.User", "Canvas.Owner")).owner_evidence

    def test_a_google_github_or_oidc_user_never_becomes_owner_through_rules(self) -> None:
        policy = policy_of("google:domain:example.edu", "github:user:583231", "oidc:school:any")
        for ext in (google_ext(), github_ext(), oidc_ext()):
            verdict = evaluate_admission(ext, policy)
            assert verdict.admitted_by_rule and not verdict.owner_by_rule
            decision = decide(None, verdict, policy, DecisionFacts(active_owner_count=1), "sign_in")
            assert decision.outcome == "allow" and decision.role is None and not decision.session_owner

    def test_the_bootstrap_identity_becomes_owner_only_while_there_is_no_owner(self) -> None:
        boot = acc.BootstrapOwner("google", acc.GOOGLE_ISSUER, "1001")
        policy = policy_of("google:domain:example.edu", bootstrap_owner=boot)
        ext = google_ext()
        verdict = evaluate_admission(ext, policy)
        assert acc.is_bootstrap_identity(ext, policy)
        facts = DecisionFacts(active_owner_count=0, is_bootstrap_identity=True)
        first = decide(None, verdict, policy, facts, "sign_in")
        assert first.role == acc.ROLE_OWNER and first.role_source == acc.ROLE_SOURCE_BOOTSTRAP and first.session_owner
        # Once an owner exists the same identity is an ordinary user.
        later = decide(
            None, verdict, policy, DecisionFacts(active_owner_count=1, is_bootstrap_identity=True), "sign_in"
        )
        assert later.outcome == "allow" and later.role is None and not later.session_owner

    def test_a_bootstrap_identity_is_matched_by_the_full_key(self) -> None:
        boot = acc.BootstrapOwner("oidc:school", "https://idp.example.edu", "u-1")
        policy = AccessPolicy(bootstrap_owner=boot)
        assert acc.is_bootstrap_identity(oidc_ext(), policy)
        assert not acc.is_bootstrap_identity(oidc_ext(issuer="https://other.example.edu"), policy)
        assert not acc.is_bootstrap_identity(oidc_ext(subject="U-1"), policy)

    def test_an_entra_rules_owner_signing_in_through_another_provider_is_not_demoted(self) -> None:
        policy = AccessPolicy(
            mode="rules",
            rules=(AccessRule("google", "domain", "example.edu"),),
            owner_rules=(AccessRule("entra", "role", "Canvas.Owner"),),
        )
        owner = AccountFacts(acc.STATUS_ACTIVE, acc.ROLE_OWNER, acc.ROLE_SOURCE_RULES, acc.ADMITTED_RULES)
        verdict = evaluate_admission(google_ext(), policy)
        assert verdict.owner_by_rule is False and verdict.owner_evidence is False
        decision = decide(owner, verdict, policy, DecisionFacts(active_owner_count=2), "sign_in")
        assert decision.outcome == "allow"
        assert decision.role is None and decision.role_event is None
        # No fresh Entra evidence: this session is not an owner session.
        assert decision.session_owner is False

    def test_an_entra_sign_in_still_demotes_a_rules_owner_who_lost_the_role(self) -> None:
        policy = acc.default_policy("Canvas.User", "Canvas.Owner")
        owner = AccountFacts(acc.STATUS_ACTIVE, acc.ROLE_OWNER, acc.ROLE_SOURCE_RULES, acc.ADMITTED_RULES)
        ext = ExternalClaims("entra", acc.entra_issuer(TID), "s", roles=frozenset({"Canvas.User"}))
        verdict = evaluate_admission(ext, policy)
        decision = decide(owner, verdict, policy, DecisionFacts(active_owner_count=2), "sign_in")
        assert decision.role == acc.ROLE_USER and decision.role_event == acc.EVENT_OWNER_LOST

    def test_bootstrap_and_operator_owners_keep_their_session_through_any_provider(self) -> None:
        policy = policy_of("google:domain:example.edu")
        for source in (acc.ROLE_SOURCE_BOOTSTRAP, acc.ROLE_SOURCE_OPERATOR):
            owner = AccountFacts(acc.STATUS_ACTIVE, acc.ROLE_OWNER, source, acc.ADMITTED_BOOTSTRAP)
            decision = decide(owner, evaluate_admission(google_ext(), policy), policy, DecisionFacts(active_owner_count=1), "sign_in")
            assert decision.outcome == "allow" and decision.session_owner and decision.role is None


class TestLinkAdmissible:
    def test_it_equals_the_active_account_admission_of_decide(self) -> None:
        policies = {
            "rules": policy_of("google:domain:example.edu"),
            "open": AccessPolicy(mode="open"),
            "approval": AccessPolicy(mode="approval"),
        }
        exts = (google_ext(), google_ext(hd="other.edu"), github_ext())
        for via in acc.ADMITTED_VIA:
            existing = AccountFacts(acc.STATUS_ACTIVE, acc.ROLE_USER, None, via)
            for policy in policies.values():
                for ext in exts:
                    verdict = evaluate_admission(ext, policy)
                    decision = decide(existing, verdict, policy, DecisionFacts(active_owner_count=1), "request")
                    assert link_admissible(existing, verdict, policy) is (decision.outcome == "allow")

    def test_rules_mode_refuses_an_identity_no_rule_admits(self) -> None:
        policy = policy_of("google:domain:example.edu")
        by_rules = AccountFacts(acc.STATUS_ACTIVE, acc.ROLE_USER, None, acc.ADMITTED_RULES)
        assert not link_admissible(by_rules, evaluate_admission(github_ext(), policy), policy)
        by_approval = AccountFacts(acc.STATUS_ACTIVE, acc.ROLE_USER, None, acc.ADMITTED_APPROVAL)
        assert link_admissible(by_approval, evaluate_admission(github_ext(), policy), policy)


class TestDenialMessage:
    def test_a_neutral_message_exists_and_names_no_provider(self) -> None:
        assert "Microsoft" not in acc.NEUTRAL_ACCESS_DENIED
        assert acc.NEUTRAL_ACCESS_DENIED != acc.DENIAL_MESSAGES[acc.DENY_ACCESS_DENIED]


def test_every_existing_entra_decision_row_is_unchanged() -> None:
    """The first release's table, replayed through decide() with the new Verdict fields."""
    policy = acc.default_policy("Canvas.User", "Canvas.Owner")
    for roles, expect in (
        (("Canvas.User",), "allow"),
        (("Canvas.Owner",), "allow"),
        ((), "deny"),
    ):
        ext = ExternalClaims("entra", acc.entra_issuer(TID), "s", roles=frozenset(roles), tenant_id=TID)
        verdict = evaluate_admission(ext, policy)
        assert isinstance(verdict, Verdict) and verdict.owner_evidence
        assert decide(None, verdict, policy, DecisionFacts(), "sign_in").outcome == expect


def test_parse_access_settings_without_providers_is_the_first_release() -> None:
    problems: list[str] = []
    policy = parse_access_settings(
        {}, tenant_id=TID, required_role="Canvas.User", owner_role="Canvas.Owner", problems=problems
    )
    assert problems == []
    assert policy == acc.default_policy("Canvas.User", "Canvas.Owner")
    assert policy.bootstrap_via_token_admin is False
