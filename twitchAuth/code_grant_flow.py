from httpx import Client
from urllib.parse import urlencode
from loguru import logger

from twitchAuth.consts import SESSION_STATE_INVALID, SESSION_STATE_VALID, SESSION_TYPE_USER, TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH
from twitchAuth.exceptions import InvalidAuthGrantCodeException, TokenNotFoundException, TwitchAuthorizeException, TwitchRefreshTokenException, TwitchSessionNotValidException, TwitchTokenFromCodeException
from twitchAuth.session import Session, SessionManager, SessionStore
from twitchAuth.token import Token, TokenStore

class CodeGrantFlow(SessionManager):
    """
    CodeGrantFlow provides the implementation for the twitch Code Grant Flow from https://dev.twitch.tv/docs/authentication/getting-tokens-oauth/
    The token from this method is a user token (see twitch docs for difference between user and app tokens).
    This method also gives us an expiration time for the access token, and a refresh token which can be used to extend the life of the access token.
    The refresh token will become invalid if the user changes their password or revokes the authorization given to your app.
    """
    def __init__(self, tokens: TokenStore, sessions: SessionStore, client_id: str, client_secret: str, redirect_url: str) -> None:
        self.tokens = tokens
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect = redirect_url
        self.client = Client()

        super().__init__(sessions=sessions, session_type=SESSION_TYPE_USER)

    def get_token(self ,session_id: str) -> Token:
        """
        get_token checks if the given session exists and has a valid token in the TokenStore.
        This function does not handle token expiration, so that has to be handled in your implementation of TokenStore.
        If a valid token cannot be returned, get_token() checks for a refresh token and tries to refresh the access token.
        If the token is refreshed, the new tokens are saved to the TokenStore, and the access_token is returned.
        """
        session = self.get_session(session_id)

        token = self.tokens.get(session_id, TOKEN_TYPE_ACCESS)
        if not token:

            refresh = self.tokens.get(session.id, TOKEN_TYPE_REFRESH)
            if not refresh:
                raise TokenNotFoundException(session_id=session_id, token_type=TOKEN_TYPE_ACCESS)

            return self._refresh_token(session=session, refresh=refresh)

        return token

    def _refresh_token(self, session: Session, refresh: Token) -> Token:
        """
        _refresh_token is an internal private method and is not meant to be used outside of the class.
        This method takes a refresh token and attempts to get a new access_token.
        """
        queries = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh.token,
        }

        try:
            resp = self.client.post(url="https://id.twitch.tv/oauth2/token", data=queries)
            resp.raise_for_status()

            data = resp.json()

            access_token = data["access_token"]
            expires_in = data["expires_in"]
            refresh_token = data["refresh_token"]

            self.tokens.save(id=session.id, token=Token(type=TOKEN_TYPE_ACCESS, token=access_token, token_expire=expires_in, scopes=session.scopes))
            self.tokens.save(id=session.id, token=Token(type=TOKEN_TYPE_REFRESH, token=refresh_token, token_expire=0, scopes=[]))
        except Exception as ex:
            logger.exception(ex)
            raise TwitchRefreshTokenException

        return Token()

    def auth_url(self, session_id: str, force_verify: bool = False) -> str:
        """
        auth_url generates the url the user has to navigate to in their browser in order to grant your app permissions for the given scopes.
        """
        session = self.get_session(id=session_id)

        queries = {
            "client_id": self.client_id,
            "force_verify": force_verify,
            "redirect_uri": self.redirect,
            "response_type": "code",
            "scope": "%20".join(session.scopes),
            "state": session_id
        }

        query = urlencode(queries, safe="%")

        return "https://id.twitch.tv/oauth2/authorize?" + query

    def callback_handler(self, state: str, code: str = "", scope: str = "", error: str = "", error_description: str = ""):
        """
        Once the user has granted your app the needed authorization using the url from the auth_url method, your app will recieve a request with all the needed info.
        If the authorization process was successful, and a grant code is present in that request, this method attempts to use it to get a new set of tokens.
        """
        if error:
            raise TwitchAuthorizeException(error, error_description)

        if not code:
            raise InvalidAuthGrantCodeException

        session = self.get_session(state)

        queries = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect
        }

        try:
            resp = self.client.post(url="https://id.twitch.tv/oauth2/token", data=queries)
            resp.raise_for_status()

            data = resp.json()

            access_token = data["access_token"]
            expires_in = data["expires_in"]
            refresh_token = data["refresh_token"]

            self.tokens.save(id=session.id, token=Token(type=TOKEN_TYPE_ACCESS, token=access_token, token_expire=expires_in, scopes=session.scopes))
            self.tokens.save(id=session.id, token=Token(type=TOKEN_TYPE_REFRESH, token=refresh_token, token_expire=0, scopes=[]))
        except Exception as ex:
            logger.exception(ex)
            raise TwitchTokenFromCodeException
