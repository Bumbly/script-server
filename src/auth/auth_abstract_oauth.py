import abc
import asyncio
import datetime
import json
import logging
import os
import threading
import time
import urllib.parse as urllib_parse
from collections import defaultdict
from typing import Dict

import tornado
import tornado.ioloop
from tornado import httpclient, escape
from tornado.httpclient import HTTPClientError
from tornado.web import RequestHandler

from auth import auth_base
from auth.auth_base import AuthFailureError, AuthBadRequestException, AuthRejectedError
from auth.oauth_token_manager import OAuthTokenManager
from auth.oauth_token_response import OAuthTokenResponse
from model import model_helper
from model.model_helper import read_bool_from_config, read_int_from_config
from model.server_conf import InvalidServerConfigException
from utils import file_utils

LOGGER = logging.getLogger('script_server.AbstractOauthAuthenticator')


class _UserState:
    def __init__(self, username) -> None:
        self.username = username
        self.groups = []
        self.last_auth_update = None
        self.last_visit = None

class OAuthCallbackHandler(RequestHandler):
    """
    Base handler for OAuth callbacks
    """
    async def get(self):
        try:
            state = self.get_argument('state', '')
            if not self.auth.validate_state(state):
                raise ValueError('Invalid State Parameter')
            
            callback_url = self.auth.redirect_uri
                
            user_data = await self.auth.handle_oauth_callback(
                self.get_argument('code'),
                callback_url
            )
            
            await self.auth.create_session(self, user_data)
            self.redirect(self.get_secure_cookie('post_auth_redirect') or '/')

            LOGGER.debug(f"Callback received at: {self.request.full_url()}")
            LOGGER.debug(f"Using configured redirect_uri: {self.auth.redirect_uri}")
        except Exception as e:
            logging.exception("OAuth callback failed")
            self.set_status(400)
            self.finish(f'Authentication failed: {str(e)}')

class _OauthUserInfo:
    def __init__(self, username, enabled, oauth_response, eager_groups=None):
        self.username = username
        self.enabled = enabled
        self.oauth_response = oauth_response
        self.eager_groups = eager_groups

    def __eq__(self, o: object) -> bool:
        return isinstance(o, _OauthUserInfo) and (self.username == o.username)

    def __str__(self) -> str:
        return f'_OauthUserInfo({self.username})'

    def __repr__(self) -> str:
        return f'_OauthUserInfo({self.__dict__})'


def _start_timer(callback):
    timer = threading.Timer(30, callback)
    timer.setDaemon(True)
    timer.start()
    return timer


class AbstractOauthAuthenticator(auth_base.Authenticator, metaclass=abc.ABCMeta):
    """
    Extend the abstract class with callback functionality
    """
    def get_oauth_handlers(self):
        """
        Returns list of (route, handler) tuples for OAuth routes
        Should be implemented by concrete classes
        """
        raise NotImplementedError()
    
    async def handle_oauth_callback(self, code, callback_url):
        """
        Process OAuth callback: exchange code for tokens and get user info
        """
        raise NotImplementedError()
    
    def validate_state(self, state):
        """
        Validate state parameter against stored state
        """
        # Implement state validation logic
        return True  # In production, compare with stored state
    
    async def create_session(self, handler, user_data):
        """
        Create user session after successful authentication
        """
        raise NotImplementedError()
    def __init__(self, oauth_authorize_url, oauth_token_url, oauth_scope, params_dict):
        super().__init__()

        self.oauth_token_url = oauth_token_url
        self.oauth_scope = oauth_scope

        self.client_id = model_helper.read_obligatory(params_dict, 'client_id', ' for OAuth')
        secret_value = model_helper.read_obligatory(params_dict, 'secret', ' for OAuth')
        self.secret = model_helper.resolve_env_vars(secret_value, full_match=True)

        self._client_visible_config['client_id'] = self.client_id
        self._client_visible_config['oauth_url'] = oauth_authorize_url
        self._client_visible_config['oauth_scope'] = oauth_scope

        self.group_support = read_bool_from_config('group_support', params_dict, default=True)
        self.auth_info_ttl = params_dict.get('auth_info_ttl')
        self.session_expire = read_int_from_config('session_expire_minutes', params_dict, default=0) * 60
        self.dump_file = params_dict.get('state_dump_file')
        self.redirect_uri = model_helper.read_obligatory(params_dict, 'redirect_uri', ' for OAuth')

        if self.dump_file:
            self._validate_dump_file(self.dump_file)

        self._users = {}  # type: Dict[str, _UserState]
        self._user_locks = defaultdict(lambda: asyncio.locks.Lock())

        self.http_client = httpclient.AsyncHTTPClient()

        self.timer = None
        if self.dump_file:
            self._restore_state()

            self._schedule_dump_task()

        self._token_manager = OAuthTokenManager(
            enabled=bool(self.auth_info_ttl),
            fetch_token_callback=self._fetch_token_by_refresh)

        self.ioloop = tornado.ioloop.IOLoop.current()

    @staticmethod
    def _validate_dump_file(dump_file):
        if os.path.isdir(dump_file):
            raise InvalidServerConfigException('Please specify dump FILE instead of folder for OAuth')
        dump_folder = os.path.abspath(os.path.dirname(dump_file))
        if not os.path.exists(dump_folder):
            raise InvalidServerConfigException('OAuth dump file folder does not exist: ' + dump_folder)

    async def authenticate(self, request_handler):
        code = request_handler.get_argument('code', False)

        if not code:
            LOGGER.error('Code is not specified')
            raise AuthBadRequestException('Missing authorization information. Please contact your administrator')

        token_response = await self.fetch_access_token_by_code(code, request_handler)
        user_info = await self.fetch_user_info(token_response.access_token)

        username = user_info.username
        if not username:
            error_message = 'No email field in user response. The response: ' + str(user_info.oauth_response)
            LOGGER.error(error_message)
            raise AuthFailureError(error_message)

        if not user_info.enabled:
            error_message = 'User %s is not enabled in OAuth provider. The response: %s' \
                            % (username, str(user_info.oauth_response))
            LOGGER.error(error_message)
            raise AuthFailureError(error_message)

        user_state = _UserState(username)
        self._users[username] = user_state

        if self.group_support:
            await self.load_groups(token_response.access_token, username, user_info, user_state)

        now = time.time()

        self._token_manager.update_tokens(token_response, username, request_handler)

        if self.auth_info_ttl:
            user_state.last_auth_update = now

        user_state.last_visit = now

        return username

    async def load_groups(self, access_token, username, user_info, user_state):
        if user_info.eager_groups is not None:
            user_state.groups = user_info.eager_groups
        else:
            user_groups = await self.fetch_user_groups(access_token)
            user_state.groups = user_groups
        LOGGER.info('Loaded groups for ' + username + ': ' + str(user_state.groups))

    async def validate_user(self, user, request_handler):
        if not user:
            LOGGER.warning('Username is not available')
            return False

        now = time.time()

        user_state = self._users.get(user)
        validate_expiration = True
        if not user_state:
            # if nothing is enabled, it's ok not to have user state (e.g. after server restart)
            if self.session_expire <= 0 and not self.auth_info_ttl and not self.group_support:
                return True
            elif self._token_manager.can_restore_state(request_handler):
                validate_expiration = False
                user_state = _UserState(user)
                self._users[user] = user_state
            else:
                LOGGER.info('User %s state is missing', user)
                return False

        if (self.session_expire > 0) and validate_expiration:
            last_visit = user_state.last_visit
            if (last_visit is None) or ((last_visit + self.session_expire) < now):
                LOGGER.info('User %s state is expired', user)
                return False

        user_state.last_visit = now

        if self.auth_info_ttl:
            access_token = await self._token_manager.synchronize_user_tokens(user, request_handler)
            if access_token is None:
                LOGGER.info('User %s token is not available', user)
                self._remove_user(user)
                return False

            self.update_user_auth(user, user_state, access_token)

        return True

    def get_groups(self, user, known_groups=None):
        user_state = self._users.get(user)
        if not user_state:
            return []

        return user_state.groups

    def logout(self, user, request_handler):
        self._token_manager.logout(user, request_handler)
        self._remove_user(user)

        self._dump_state()

    def _remove_user(self, user):
        if user in self._users:
            del self._users[user]
            self._token_manager.remove_user(user)

    async def fetch_access_token_by_code(self, code, request_handler):
        return await self._fetch_token({
            'redirect_uri': self.redirect_uri,
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.secret,
            'grant_type': 'authorization_code',
        })

    async def _fetch_token_by_refresh(self, refresh_token, username):
        if username not in self._users:
            return None

        try:
            return await self._fetch_token({
                'refresh_token': refresh_token,
                'client_id': self.client_id,
                'client_secret': self.secret,
                'grant_type': 'refresh_token',
            })
        except AuthFailureError:
            LOGGER.info(f'Failed to refresh token for user {username}. Logging out')
            self._remove_user(username)
            return None

    def update_user_auth(self, username, user_state, access_token):
        now = time.time()
        ttl_expired = (user_state.last_auth_update is None) \
                      or ((user_state.last_auth_update + self.auth_info_ttl) < now)

        if not ttl_expired:
            return

        self.ioloop.spawn_callback(
            self._do_update_user_auth_async,
            username,
            user_state,
            access_token)

    async def _do_update_user_auth_async(self, username, user_state, access_token):
        lock = self._user_locks[username]

        async with lock:
            now = time.time()

            ttl_expired = (user_state.last_auth_update is None) \
                          or ((user_state.last_auth_update + self.auth_info_ttl) < now)

            if not ttl_expired:
                return

            LOGGER.info('User %s state expired, refreshing', username)

            try:
                user_info = await self.fetch_user_info(access_token)  # type: _OauthUserInfo
            except (AuthRejectedError, HTTPClientError) as e:
                if (not isinstance(e, HTTPClientError)) or (e.code == 401):
                    LOGGER.info(f'User {username} is not authenticated anymore. Logging out')
                    self._remove_user(username)
                    return
                else:
                    raise e

            if (not user_info) or (not user_info.username):
                LOGGER.error('Failed to fetch user info: %s', str(user_info))
                self._remove_user(username)
                return

            if not user_info.enabled:
                LOGGER.error('User %s, was deactivated on OAuth server. New state: %s', username,
                             str(user_info.oauth_response))
                self._remove_user(username)
                return

            if self.group_support:
                try:
                    await self.load_groups(access_token, username, user_info, user_state)
                except AuthFailureError:
                    LOGGER.error('Failed to fetch user %s groups', username)
                    self._remove_user(username)
                    return

            user_state.last_auth_update = now

    def _restore_state(self):
        if not os.path.exists(self.dump_file):
            LOGGER.info('OAuth dump file is missing. Nothing to restore')
            return

        dump_data = file_utils.read_file(self.dump_file)
        dump_json = json.loads(dump_data)

        for user_state in dump_json:
            username = user_state.get('username')
            if not username:
                LOGGER.warning('Missing username in ' + str(user_state))
                continue

            state = _UserState(username)
            self._users[username] = state
            state.groups = user_state.get('groups', [])
            state.last_auth_update = user_state.get('last_auth_update')
            state.last_visit = user_state.get('last_visit')

    def _schedule_dump_task(self):
        def repeating_dump():
            try:
                self._dump_state()
            finally:
                self._schedule_dump_task()

        self.timer = _start_timer(repeating_dump)

    def _dump_state(self):
        if self.dump_file:
            states = [s.__dict__ for s in self._users.values()]
            state_json = json.dumps(states)
            file_utils.write_file(self.dump_file, state_json)

    @abc.abstractmethod
    async def fetch_user_info(self, access_token: str) -> _OauthUserInfo:
        pass

    @abc.abstractmethod
    async def fetch_user_groups(self, access_token: str) -> list[str]:
        pass

    # Tests only
    def _cleanup(self):
        if self.timer:
            self.timer.cancel()

    async def _fetch_token(self, body):
        encoded_body = urllib_parse.urlencode(body)

        response = await self.http_client.fetch(
            self.oauth_token_url,
            method='POST',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            body=encoded_body,
            raise_error=False)

        response_values = {}
        if response.body:
            response_values = escape.json_decode(response.body)

        if response.error:
            if response_values.get('error_description'):
                error_text = response_values.get('error_description')
            elif response_values.get('error'):
                error_text = response_values.get('error')
            else:
                error_text = str(response.error)

            error_message = 'Failed to refresh access_token: ' + error_text
            LOGGER.error(error_message)
            raise AuthFailureError(error_message)

        token_response = OAuthTokenResponse.create(response_values, datetime.datetime.now())

        if not token_response.access_token:
            message = 'No access token in response: ' + str(response.body)
            LOGGER.error(message)
            raise AuthFailureError(message)

        return token_response

    def logout(self, user, request_handler):
        """Base logout implementation to be called by child classes"""
        # Clear token management
        self._token_manager.logout(user, request_handler)
        # Clear user state
        self._remove_user(user)
        # Persist state if needed
        self._dump_state()


def get_path_for_redirect(request_handler):
    referer = request_handler.request.headers.get('Referer')
    if not referer:
        LOGGER.error('No referer')
        raise AuthFailureError('Missing request header. Please contact system administrator')

    parse_result = urllib_parse.urlparse(referer)
    protocol = parse_result[0]
    host = parse_result[1]
    path = parse_result[2]

    return urllib_parse.urlunparse((protocol, host, path, '', '', ''))
