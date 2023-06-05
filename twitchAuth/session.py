from dataclasses import dataclass, field
from uuid import uuid4 as UUID
from typing import Union

from twitchAuth.consts import *
from twitchAuth.exceptions import SaveSessionException, SessionNotFoundException

@dataclass()
class Session:
    id: str
    type: str
    scopes: list[str] = field(default_factory=list[str])
    status: str = SESSION_STATE_PENDING

sessions = {}
class SessionStore:
    def save(self, session: Session):
        sessions[session.id] = session

    def get(self, id: str) -> Union[Session, None]:
        return sessions[id]

class SessionManager:
    def __init__(self, sessions: SessionStore, session_type: str) -> None:
        self.sessions = sessions
        self.token_type = session_type

    def new_session(self, scopes: list[str]) -> Session:
        session = Session(id=UUID().__str__(), type=self.token_type, scopes=scopes)
        self.save_session(session=session)
        return session

    def get_session(self, id: str) -> Session:
        session = self.sessions.get(id=id)
        if not session:
            raise SessionNotFoundException(id)

        return session

    def save_session(self, session: Session):
        try:
            self.sessions.save(session=session)
        except Exception as ex:
            print(ex)
            raise SaveSessionException(session_id=session.id)
