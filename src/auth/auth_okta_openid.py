import logging
import requests
from auth.auth_abstract_oauth import AbstractOauthAuthenticator
from model import user

logger = logging.getLogger('auth_okta_openid')


class OktaOpenIDAuthenticator(AbstractOauthAuthenticator):
    def __init__(self, params_dict):
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
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
            'state': state,
            'nonce': self._generate_nonce()
        }
        if not self.client_secret:
            params['code_challenge'] = self._generate_code_challenge()
            params['code_challenge_method'] = 'S256'
        return params

    def _exchange_code(self, code):
        return {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope' : self.scope
        }

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
