"""Every provider uses the v1 ceremony, route resolver and JSON session API."""

import pytest

from ..authz.stack import ALICE, Browser
from .stack_providers import provider_stack


@pytest.mark.parametrize('provider', ['entra', 'google', 'github', 'school'])
def test_all_providers_complete_the_same_session_flow(tmp_path, monkeypatch, provider):
    with provider_stack(tmp_path, monkeypatch) as ps:
        person = ps.person()
        if provider == 'entra':
            response = person.sign_in_entra(ALICE)
        else:
            response = person.sign_in(provider)
        assert response.status_code == 303
        assert response.headers['location'] == '/account/'
        me = Browser(ps.stack, client=person.client).api('GET', '/me')
        assert me.status_code == 200
        assert person.account()
        assert 'consent' not in me.json()['features']
        assert 'connected_apps' not in me.json()['features']


def test_multiple_providers_choose_in_react_without_creating_ceremony(tmp_path, monkeypatch):
    with provider_stack(tmp_path, monkeypatch) as ps:
        response = ps.stack.client.get('/auth/login?return_to=/account/token')
        assert response.status_code == 303
        assert response.headers['location'] == '/account/sign-in?return_to=%2Faccount%2Ftoken'
        assert '__Host-cmcp_flow' not in response.headers.get('set-cookie', '')
        providers = ps.stack.client.get('/api/v1/providers').json()['providers']
        assert [p['start_url'] for p in providers] == [
            '/auth/login/entra', '/auth/login/google', '/auth/login/github', '/auth/login/oidc/school',
        ]


def test_callback_for_a_different_provider_never_exchanges_code(tmp_path, monkeypatch):
    with provider_stack(tmp_path, monkeypatch) as ps:
        person = ps.person()
        start = person.start('google')
        url = person.callback_url('google', start)
        wrong = person.get(url.replace('/auth/callback/google', '/auth/callback/github'))
        assert wrong.status_code == 303
        assert wrong.headers['location'] == '/account/sign-in?error=state_invalid'
        assert ps.google.counts['token'] == 0
        assert not ps.net.requests_to('github.com', '/login/oauth/access_token')
