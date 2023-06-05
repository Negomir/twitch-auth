class TokenNotFoundException(Exception):
    def __init__(self, session_id: str, token_type: str) -> None:
        self.session_id = session_id
        self.token_type = token_type
        self.message = f'session with the id {self.session_id} does not have a token of type {self.token_type}'

        super().__init__(self.message)

class SessionNotFoundException(Exception):
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.message = f'session with id {self.session_id} does not exist'

        super().__init__(self.message)

class SaveSessionException(Exception):
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.message = f'error saving session with id {self.session_id}'
        super().__init__(self.message)

class TwitchAuthorizeException(Exception):
    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = " ".join(description.split("+"))

        super().__init__(self.error, self.description)

class InvalidTwitchTokenException(Exception):
    pass

class InvalidAuthGrantCodeException(Exception):
    pass

class TwitchTokenFromCodeException(Exception):
    pass

class TwitchRefreshTokenException(Exception):
    pass

class TwitchSessionNotValidException(Exception):
    def __init__(self, session_id: str) -> None:
        self.session_id=session_id
        self.message = f'session with id {self.session_id} is not valid'

        super().__init__(self.message)
