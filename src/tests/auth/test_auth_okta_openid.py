import pytest
from unittest.mock import AsyncMock, MagicMock, patch, Mock

from auth.auth_okta_openid import OktaOpenIDAuthenticator
from auth.oauth_token_response import OAuthTokenResponse

@pytest.fixture
def okta_config():
    return {
        'issuer': 'https://dev-123456.okta.com',
        'client_id': 'test_client',
        'redirect_uri': 'http://localhost/callback'
    }

@pytest.fixture
def mock_okta(okta_config):
    with patch('auth.auth_okta_openid.OktaOpenIDAuthenticator._fetch_token') as mock_fetch:
        authenticator = OktaOpenIDAuthenticator(okta_config)
        authenticator._token_manager = MagicMock()
        yield authenticator, mock_fetch

@pytest.fixture
def mock_request_handler():
    handler = MagicMock()
    handler.get_argument = Mock(return_value='test_state')
    return handler

@pytest.mark.asyncio
async def test_authenticate(mock_okta):
    authenticator, mock_fetch = mock_okta
    
    mock_fetch.return_value = OAuthTokenResponse(
        access_token='test_access',
        refresh_token='test_refresh',
        expires_in=3600
    )
    
    with patch.object(authenticator, 'fetch_user_info', 
                    new=AsyncMock(return_value=MagicMock(username='test@okta.com'))):
        username = await authenticator.authenticate(MagicMock())
        assert username == 'test@okta.com'
        mock_fetch.assert_called_once()

@pytest.mark.asyncio
async def test_refresh_token(mock_okta):
    authenticator, mock_fetch = mock_okta
    mock_fetch.return_value = OAuthTokenResponse(access_token='new_token')

    result = await authenticator._fetch_token_by_refresh('old_refresh', 'test@okta.com')
    assert result.access_token == 'new_token'

def test_pkce_flow(okta_config):
    # Test without client_secret
    auth = OktaOpenIDAuthenticator(okta_config)
    url = auth.get_authorization_url("test_state")
    assert 'code_challenge=' in url
    assert 'code_challenge_method=S256' in url

def test_non_pkce_flow():
    # Test with client_secret
    auth = OktaOpenIDAuthenticator({
        'issuer': 'https://test.okta.com',
        'client_id': 'test',
        'redirect_uri': 'http://localhost/callback',
        'client_secret': 'secret'
    })
    url = auth.get_authorization_url("test_state")
    assert 'code_challenge=' not in url

@pytest.mark.asyncio
async def test_token_exchange(mock_okta, mock_request_handler):
    authenticator, mock_fetch = mock_okta
    authenticator._pkce_verifiers = {'test_state': 'test_verifier'}
    
    mock_fetch.return_value = OAuthTokenResponse(
        access_token='new_token',
        refresh_token='new_refresh'
    )
    
    result = await authenticator.fetch_access_token_by_code('test_code', mock_request_handler)
    assert result.access_token == 'new_token'
    mock_fetch.assert_called_once_with({
        'grant_type': 'authorization_code',
        'code': 'test_code',
        'redirect_uri': 'http://localhost/callback',
        'client_id': 'test_client',
        'code_verifier': 'test_verifier'
    })
