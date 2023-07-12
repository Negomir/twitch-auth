from httpx import Client
from typing import Union
from uuid import uuid4 as UUID
import urllib.parse

from twitchAuth.consts import *
from twitchAuth.consts import TOKEN_TYPE_ACCESS
from twitchAuth.token import Token, TokenStore
from twitchAuth.session import Session, SessionManager, SessionStore
from twitchAuth.exceptions import *

class ImplicitGrantFlow(SessionManager):
    def __init__(self, tokens: TokenStore, sessions: SessionStore, client_id: str, client_secret: str, redirect_url: str):
        self.tokens = tokens
        self.client_id=client_id
        self.client_secret = client_secret
        self.redirect_url = redirect_url

        super().__init__(sessions=sessions, session_type=SESSION_TYPE_USER)

    def get_token(self, session: str) -> Token:
        token = self.tokens.get(session, TOKEN_TYPE_ACCESS)
        if not token:
            raise TokenNotFoundException(session, TOKEN_TYPE_ACCESS)

        return token

    def auth_url(self, username: str, session_id: str) -> str:
        session = self.get_session(username=username, id=session_id)

        queries = {
            "client_id": "",
            "force_verify": False,
            "redirect_uri": self.redirect_url,
            "response_type": "token",
            "scope": "%20".join(session.scopes),
            "state": f'{username}:{session.id}'
        }

        query = urllib.parse.urlencode(queries, safe="%")

        return "https://id.twitch.tv/oauth2/authorize?"+query

    def callback_handler(self, state: str, access_token: str = "", scope: str = "", token_type: str = "", error: str = "", error_description: str = ""):
        if error != "":
            raise TwitchAuthorizeException(error, error_description)

        if access_token == "":
            raise InvalidTwitchTokenException

        try:
            username = state.split(":")[0]
            session_id = state.split(":")[1]
        except Exception as ex:
            raise InvalidAuthGrantStateException

        session = self.get_session(username=username, id=session_id)

        session.status = SESSION_STATE_VALID
        self.save_session(username=username, session=session)
        self.tokens.save(session.id, Token(type=TOKEN_TYPE_ACCESS, token=access_token, token_expire=0, scopes=session.scopes))
