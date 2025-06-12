from unittest.mock import patch
from auth.auth_okta_openid import OktaOpenIDAuthenticator

@patch('auth.auth_okta_openid.requests')
def test_discovery(mock_requests):
    mock_response = mock_requests.get.return_value
    mock_response.json.return_value = {
        "authorization_endpoint": "https://okta.com/oauth2/v1/authorize",
        "token_endpoint": "https://okta.com/oauth2/v1/token"
    }
    
    authenticator = OktaOpenIDAuthenticator({
        'issuer': 'https://okta.com',
        'client_id': 'test',
        'redirect_uri': 'http://localhost/callback'
    })
    
    assert authenticator.auth_endpoint == "https://okta.com/oauth2/v1/authorize"
