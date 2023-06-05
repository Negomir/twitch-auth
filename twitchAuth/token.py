from typing import Union
from dataclasses import dataclass, field
from time import time

@dataclass()
class Token:
    type: str = ""
    token: str = ""
    token_expire: int = 0
    scopes: list[str] = field(default_factory=list[str])

    def access_expired(self) -> bool:
        return int(time()) > self.token_expire

    def has_scope(self, scope: str) -> bool:
        return self.scopes.__contains__(scope)

tokens = {}
class TokenStore:
    def save(self, id: str, token: Token):
        tokens[id][token.type] = token

    def get(self, id: str, type: str) -> Union[Token, None]:
        return tokens[id][type]

    def ttl(self, id: str) -> int:
        return -1
