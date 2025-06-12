import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from auth.auth_okta_openid import OktaOpenIDAuthenticator
from auth.oauth_token_response import OAuthTokenResponse

@pytest.fixture
def okta_config():
    return {
        'type': 'okta_openid',
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

@pytest.mark.asyncio
async def test_authenticate(mock_okta):
    authenticator, mock_fetch = mock_okta
    
    # Mock token response
    mock_fetch.return_value = OAuthTokenResponse(
        access_token='test_access',
        refresh_token='test_refresh',
        expires_in=3600
    )
    
    # Mock user info
    with patch.object(authenticator, 'fetch_user_info', 
                    new=AsyncMock(return_value=MagicMock(username='test@okta.com')):

        # Test
        username = await authenticator.authenticate(MagicMock())
        assert username == 'test@okta.com'
        mock_fetch.assert_called_once()

@pytest.mark.asyncio
async def test_refresh_token(mock_okta):
    authenticator, mock_fetch = mock_okta
    mock_fetch.return_value = OAuthTokenResponse(access_token='new_token')

    result = await authenticator._fetch_token_by_refresh('old_refresh', 'test@okta.com')
    assert result.access_token == 'new_token'
