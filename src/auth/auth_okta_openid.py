import logging
import requests
import hashlib
import base64
import secrets
import urllib.parse
import tornado.httpclient
import tornado.escape
import aiohttp
from tornado.httputil import url_concat
from auth.auth_abstract_oauth import _OauthUserInfo, AbstractOauthAuthenticator, OAuthCallbackHandler
from auth.auth_base import AuthRejectedError, AuthFailureError
from auth import user
from model.server_conf import InvalidServerConfigException

logger = logging.getLogger('auth_okta_openid')

class OktaAuthCallbackHandler(OAuthCallbackHandler):
    def initialize(self, auth):
        self.auth = auth
        self.token_manager = auth._token_manager 

    async def get(self):
        try:
            # Validate state first
            state = self.get_argument('state', '')
            if not self.auth.validate_state(state):
                raise AuthRejectedError("Invalid state parameter")

            # Use your existing token exchange logic
            code = self.get_argument('code')
            token_response = await self.auth.fetch_access_token_by_code(code, self)
            
            # Use your existing user info fetching
            user_info = await self.auth.fetch_user_info(token_response.access_token)
            
            # Create session using your existing mechanisms
            await self._create_session(user_info, token_response)
            
            # Redirect to original URL or default
            self.redirect(self.get_secure_cookie('post_auth_redirect', '/')) # type: ignore
            
        except AuthRejectedError as e:
            logger.warning(f"Auth rejected: {str(e)}")
            self.set_status(403)
            self.finish("Authentication rejected")
        except Exception as e:
            logger.exception("OAuth callback failed")
            self.set_status(500)
            self.finish("Authentication failed")

    async def _create_session(self, user_info, token_response):
        """Leverage your existing session creation logic"""

        user = self.auth._create_or_update_user(user_info)
        self.token_manager.save_token_response(user, token_response, self)
        

        self.set_secure_cookie("user_id", user.username)

class OktaOpenIDAuthenticator(AbstractOauthAuthenticator):
    
    def get_auth_handlers(self):
        """Returns list of (route, handler) tuples for all auth routes"""
        return [
            (r'/oauth/callback', OktaAuthCallbackHandler, {'auth': self}),
        ]
    
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
            'oauth_url': self.oauth_authorize_url,
            'client_id' : self.client_id,
            'redirect_uri': self.redirect_uri,
            'oauth_scope': self.oauth_scope,
            'type': 'okta_openid',
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
                    'placeholder': 'https://your-script-server/oauth/callback'
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
        params_dict = params_dict.get('okta', params_dict)
        
        logger.debug('Loaded Okta Config: %s', params_dict)

        missing_fields = [field for field in self.get_required_config_fields() 
                        if field not in params_dict]
        if missing_fields:
            raise InvalidServerConfigException(
                f"Missing required Okta config fields: {', '.join(missing_fields)}")
        
        self.redirect_uri = "PlaceHolder"
        
        issuer = params_dict['issuer'].rstrip('/')
        if not issuer.startswith(('http://', 'https://')):
            raise ValueError("Issuer URL must include http/https protocol")
            
        self.client_id = params_dict.get('client_id')
        if not self.client_id:
            raise ValueError('client_id is required')

        normalized_params = params_dict.copy()
        normalized_params['secret'] = params_dict.get('client_secret', '')
        oauth_authorize_url = f'{issuer}/v1/authorize'
        oauth_token_url = f'{issuer}/v1/token'
        oauth_scope = params_dict.get('scope', 'openid profile email')
        self.timeout = params_dict.get('timeout', 10)
        
        super().__init__(
            oauth_authorize_url=oauth_authorize_url, 
            oauth_token_url=oauth_token_url,          
            oauth_scope=oauth_scope,  
            params_dict=normalized_params                       
        )

        # Store Okta-specific endpoints
        self.issuer = issuer 
        self.redirect_uri = params_dict['redirect_uri']
        self.client_secret = params_dict.get('client_secret')
        self.userinfo_endpoint = f'{issuer}/v1/userinfo'
        self.jwks_uri = f'{issuer}/v1/keys'
        self.logout_endpoint = f'{issuer}/v1/logout'
        self.logout_redirect = params_dict.get('logout_redirect')

        self._pkce_verifiers = {}
        self._nonces = {}

        # Discover endpoints dynamically
        self._discover_endpoints()
        
        

    def is_configured(self):
        """Required for admin UI health checks"""
        return bool(self.issuer and self.client_id)

    def _discover_endpoints(self):
        """Discover Okta's OIDC configuration"""
        try:
            discovery_url = f"{self.issuer}/.well-known/openid-configuration"
            logger.debug(f"Attempting to discover endpoints with timeout {self.timeout}s")
            
            # Initialize with default endpoints
            self.oauth_authorize_url = f"{self.issuer}/v1/authorize"
            self.oauth_token_url = f"{self.issuer}/v1/token"
            self.userinfo_endpoint = f"{self.issuer}/v1/userinfo"
            self.jwks_uri = f"{self.issuer}/v1/keys"
            
            sync_client = tornado.httpclient.HTTPClient()
            try:
                response = sync_client.fetch(
                    discovery_url,
                    request_timeout=self.timeout,  # Use configured timeout
                    validate_cert=False 
                )
                oidc_config = tornado.escape.json_decode(response.body)
                
                # Update with discovered endpoints
                self.oauth_authorize_url = oidc_config['authorization_endpoint']
                self.oauth_token_url = oidc_config['token_endpoint']
                self.userinfo_endpoint = oidc_config['userinfo_endpoint']
                self.jwks_uri = oidc_config['jwks_uri']
                self.logout_endpoint = oidc_config.get('end_session_endpoint', self.logout_endpoint)
                
                logger.info(f"Discovered endpoints in {response.request_time}s")
                
            except tornado.httpclient.HTTPError as e:
                if e.response:
                    logger.warning(f"Discovery failed with status {e.response.code}")
                else:
                    logger.warning(f"Discovery failed: {str(e)}")
                logger.info("Using default endpoints")
                
            finally:
                sync_client.close()
                
        except Exception as e:
            logger.error(f"Endpoint discovery error: {str(e)}")
            raise
        
        logger.debug('Final endpoints:')
        logger.debug(f'Auth: {self.oauth_authorize_url}')
        logger.debug(f'Token: {self.oauth_token_url}')
        logger.debug(f'UserInfo: {self.userinfo_endpoint}')

    def _generate_nonce(self):
        """Generate cryptographically secure nonce"""
        return secrets.token_urlsafe(32)

    def _generate_code_verifier(self):
        """Generate PKCE code verifier"""
        return secrets.token_urlsafe(96)

    def _generate_code_challenge(self, verifier):
        """Generate PKCE code challenge from verifier"""
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

    def get_authorization_url(self, state):
        """Generate authorization URL with PKCE and security enhancements"""
        nonce = self._generate_nonce()
        self._nonces[state] = nonce
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.oauth_scope,
            'state': state,
            'nonce': nonce,
            'prompt': 'login'  # Force fresh login
        }
        
        # Add PKCE for public clients
        if not self.client_secret:
            code_verifier = self._generate_code_verifier()
            code_challenge = self._generate_code_challenge(code_verifier)
            self._pkce_verifiers[state] = code_verifier
            params.update({
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256'
            })
        
        return self._build_url(self.oauth_authorize_url, params)

    def _build_url(self, base_url, params):
        """Build URL with query parameters"""
        if not params:
            return base_url
        query_string = urllib.parse.urlencode(params)
        return f"{base_url}?{query_string}"
        
    async def fetch_access_token_by_code(self, code, request_handler):
        """Exchange authorization code for tokens with PKCE support"""
        state = request_handler.get_argument('state', None)
        
        logger.debug(f"Using redirect_uri: {self.redirect_uri}")
        body = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id
        }
        
        # Add client secret if available
        if self.client_secret:
            body['client_secret'] = self.client_secret
        
        # Add PKCE verifier if this was a PKCE flow
        if state and state in self._pkce_verifiers:
            body['code_verifier'] = self._pkce_verifiers[state]
            # Clean up stored verifier
            del self._pkce_verifiers[state]
        
        # Clean up stored nonce
        if state and state in self._nonces:
            del self._nonces[state]
        
        return await self._fetch_token(body)

    async def fetch_user_info(self, access_token: str):
        """Fetch user information from Okta userinfo endpoint"""
        try:
            request = tornado.httpclient.HTTPRequest(
                self.userinfo_endpoint,
                method='GET',
                headers={'Authorization': f'Bearer {access_token}'},
                request_timeout=10
            )
            
            response = await self.http_client.fetch(request)
            user_data = tornado.escape.json_decode(response.body)
            
            username = user_data.get('preferred_username') or user_data.get('email') or user_data.get('sub')
            if not username:
                logger.error(f'No valid username found in user_info: {user_data}')
                raise ValueError('Missing valid username in user info')
                
            enabled = user_data.get('active', True)
            
            groups = self._extract_groups(user_data)
            
            return _OauthUserInfo(
                username=username,
                enabled=enabled,
                oauth_response=user_data,
                eager_groups=groups
            )
            
        except tornado.httpclient.HTTPError as e:
            if e.code == 401:
                raise AuthRejectedError("Invalid Access Token")
            logger.error(f'Okta API error: {str(e)}')
            raise AuthFailureError("Failed to fetch user info")

    async def fetch_user_groups(self, access_token):
        """Fetch user groups - Okta includes groups in userinfo by default"""
        try:
            request = tornado.httpclient.HTTPRequest(
                self.userinfo_endpoint,
                method='GET',
                headers={'Authorization': f'Bearer {access_token}'},
                request_timeout=10
            )
            
            response = await self.http_client.fetch(request)
            user_data = tornado.escape.json_decode(response.body)
            
            return self._extract_groups(user_data)
            
        except Exception as e:
            logger.error(f"Failed to fetch user groups: {str(e)}")
            return []

    def _extract_groups(self, user_info):
        """Extract groups from either top-level or in claims"""
        if 'groups' in user_info:
            return user_info['groups']
        if 'claims' in user_info and 'groups' in user_info['claims']:
            return user_info['claims']['groups']
        logger.debug('no group information found in user_info')  
        return []

    async def _fetch_token_by_refresh(self, refresh_token, username):
        """Handle refresh token flow (called by OAuthTokenManager)"""
        try:
            body = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': self.client_id
            }
            
            if self.client_secret:
                body['client_secret'] = self.client_secret
            
            return await self._fetch_token(body)
            
        except Exception as e:
            logger.error(f"Failed to refresh token for {username}: {str(e)}")
            return None

    def logout(self, user, request_handler):
        # Get id_token before clearing tokens if available
        token_response = self._token_manager._restore_token_response_from_cookies(request_handler)
        id_token = None
        if token_response and hasattr(token_response, 'oauth_response'):
            id_token = token_response.oauth_response.get('id_token') # type: ignore
        
        # Clear all authentication artifacts in proper order
        self._token_manager.logout(user, request_handler)
        self._pkce_verifiers.clear()
        self._nonces.clear()
        
        # Call parent logout (which clears user state)
        super().logout(user, request_handler)
        
        # Redirect to Okta logout if configured
        logout_url = self.get_logout_url(id_token)
        if logout_url:
            request_handler.redirect(logout_url)

    def get_logout_url(self, id_token=None):
        """Generate Okta logout URL"""
        if not getattr(self, 'logout_redirect', None):
            logger.debug("No logout_redirect configured -- ending logout chain")
            return None
            
        params = {
            'client_id': self.client_id,
            'post_logout_redirect_uri': self.logout_redirect
        }
        
        if id_token:
            params['id_token_hint'] = id_token
        
        logout_url = self._build_url(self.logout_endpoint, params)
        logger.debug(f'Generated Logout URL: {logout_url}')
        return logout_url
