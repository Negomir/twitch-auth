from dataclasses import dataclass, field
from uuid import uuid4 as UUID
from typing import Union

from twitchAuth.consts import *
from twitchAuth.exceptions import SaveSessionException, SessionNotFoundException

@dataclass()
class Session:
    id: str
    type: str
    scopes: list = field(default_factory=list)
    status: str = SESSION_STATE_PENDING

sessions = {}
class SessionStore:
    def save(self, username: str, session: Session):
        user = sessions.get("username")
        if not user:
            sessions["username"] = {}
        sessions[username][session.id] = session

    def get(self, username: str, id: str) -> Union[Session, None]:
        return sessions[username][id]

class SessionManager:
    def __init__(self, sessions: SessionStore, session_type: str) -> None:
        self.sessions = sessions
        self.token_type = session_type

    def new_session(self, username: str, scopes: list) -> Session:
        session = Session(id=UUID().__str__(), type=self.token_type, scopes=scopes)
        self.save_session(username=username, session=session)
        return session

    def get_session(self, username: str, id: str) -> Session:
        session = self.sessions.get(username=username, id=id)
        if not session:
            raise SessionNotFoundException(id)

        return session

    def save_session(self, username: str, session: Session):
        try:
            self.sessions.save(username=username, session=session)
        except Exception as ex:
            print(ex)
            raise SaveSessionException(session_id=session.id)
