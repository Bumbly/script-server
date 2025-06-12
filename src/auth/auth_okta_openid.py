import logging
import requests
from auth.auth_abstract_oauth import AbstractOauthAuthenticator
from model import user

logger = logging.getLogger('auth_okta_openid')

class OktaOpenIDAuthenticator(AbstractOauthAuthenticator):
    
    @staticmethod
    def get_required_config_fields():
        return ['issuer', 'client_id', 'redirect_uri']
    
    @staticmethod
    def get_optional_config_fields():
        return {
            'client_secret': None,
            'logout_redirect': None,
            'scope': 'openid profile email',
            'timeout': 10  # seconds
        }
    
    def get_client_visible_config(self):
        return {
            'name': 'Okta OpenID',
            'fields': [
                {
                    'name': 'issuer',
                    'type': 'text',
                    'title': 'Okta Issuer URL',
                    'placeholder': 'https://your-company.okta.com'
                },
                {
                    'name': 'client_id',
                    'type': 'text',
                    'title': 'Client ID'
                },
                {
                    'name': 'client_secret',
                    'type': 'password',
                    'title': 'Client Secret'
                },
                {
                    'name': 'redirect_uri',
                    'type': 'text',
                    'title': 'Redirect URI',
                    'placeholder': 'https://your-script-server/auth/callback'
                },
                {
                    'name': 'scope',
                    'type': 'text',
                    'title': 'OAuth Scopes',
                    'default': 'openid profile email'
                }
            ]
        }
    
    def __init__(self, params_dict):
        missing_fields = [field for field in self.get_required_config_fields() 
                        if field not in params_dict]
        if missing_fields:
            raise InvalidServerConfigException(
                f"Missing required Okta config fields: {', '.join(missing_fields)}")
        
        issuer = params_dict['issuer'].rstrip('/')
        if not issuer.startswith(('http://', 'https://')):
            raise ValueError("Issuer URL must include http/https protocol")
        
        super().__init__(
            oauth_authorize_url=f"{issuer}/v1/authorize",  
            oauth_token_url=f"{issuer}/v1/token",          
            oauth_scope=params_dict.get('scope', 'openid profile email'),  
            params_dict=params_dict                        
        )

        # Store Okta-specific endpoints (parent class may not expose these)
        self.issuer = issuer 
        self.userinfo_endpoint = f"{issuer}/v1/userinfo"
        self.jwks_uri = f"{issuer}/v1/keys"
        self.logout_endpoint = f"{issuer}/v1/logout"
        self.logout_redirect = params_dict.get('logout_redirect')

        # Discover endpoints dynamically
        self._discover_endpoints()

    def is_configured(self):
        """Required for admin UI health checks"""
        return bool(self.issuer and self.client_id)

    def _discover_endpoints(self):
        """Discover Okta's OIDC configuration"""
        try:
            discovery_url = f"{self.issuer}/.well-known/openid-configuration"
            response = self.session.get(discovery_url, timeout=10)
            response.raise_for_status()
            oidc_config = response.json()
            
            self.auth_endpoint = oidc_config['authorization_endpoint']
            self.token_endpoint = oidc_config['token_endpoint']
            self.userinfo_endpoint = oidc_config['userinfo_endpoint']
            self.jwks_uri = oidc_config['jwks_uri']
            self.logout_endpoint = oidc_config.get('end_session_endpoint', self.logout_endpoint)
            
            logger.debug("Discovered Okta endpoints:")
            logger.debug(f"Auth: {self.auth_endpoint}")
            logger.debug(f"Token: {self.token_endpoint}")
            logger.debug(f"UserInfo: {self.userinfo_endpoint}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Couldn't discover Okta OIDC config: {str(e)}")
            logger.info("Using default Okta endpoints")
            if not hasattr(self, 'auth_endpoint'):
                self.auth_endpoint = f'{self.issuer}/v1/authorize'
                self.token_endpoint = f'{self.issuer}/v1/token'
                self.userinfo_endpoint = f'{self.issuer}/v1/userinfo'
                self.jwks_uri = f'{self.issuer}/v1/keys'
                
        logger.debug('Final endpoints:')
        logger.debug(f'Auth: {self.auth_endpoint}')
        logger.debug(f'Token: {self.token_endpoint}')
        logger.debug(f'UserInfo: {self.userinfo_endpoint}')

    def _get_authorization_params(self, state):
        """Generates auth request with security enhancements"""
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
            'state': state,
            'nonce': self._generate_nonce(),
            'prompt': 'login'  # Force fresh login
        }
        if not self.client_secret:  # PKCE for public clients
            params.update({
                'code_challenge': self._generate_code_challenge(),
                'code_challenge_method': 'S256'
            })
        return params

    def _exchange_code(self, code):
        return {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope
        }

    async def _fetch_token_by_refresh(self, refresh_token, username):
        """Handle refresh token flow (called by OAuthTokenManager)"""
        try:
            return await self._fetch_token({
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            })
        except Exception as e:
            logger.error(f"Failed to refresh token for {username}: {str(e)}")
            return None

    def logout(self, user, request_handler):
        """Extended logout to clear tokens"""
        self._token_manager.logout(user, request_handler)
        super().logout(user, request_handler)

    def _map_user_info(self, user_info):
        username = user_info.get('preferred_username') or user_info.get('email') or user_info.get('sub')
        if not username:
          logger.error(f'No valid username found in user_info: {user_info}')
          raise ValueError('Missing valid username in user info')
        
        return user.User(
            username,
            user_info.get('name', ''),
            user_info.get('email', ''),
            self._extract_groups(user_info),
            user_info.get('sub'))

    def _extract_groups(self, user_info):
        """Extract groups from either top-level or in claims"""
        if 'groups' in user_info:
            return user_info['groups']
        if 'claims' in user_info and 'groups' in user_info['claims']:
            return user_info['claims']['groups']
        logger.debug('no group information found in user_info')  
        return []

    def get_logout_url(self, id_token=None):
        if not hasattr(self, 'logout_redirect') or not self.logout_redirect:
            return None
            
        params = {
            'client_id': self.client_id,
            'post_logout_redirect_uri': self.logout_redirect
        }
        
        if id_token:
            params['id_token_hint'] = id_token
            
        return self._build_url(self.logout_endpoint, params)
