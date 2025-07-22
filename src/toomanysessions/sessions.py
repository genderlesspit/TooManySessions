import time
from dataclasses import dataclass
from typing import Type, Any

from fastapi import APIRouter
from loguru import logger as log
from starlette.requests import Request

from . import DEBUG


@dataclass
class Session:
    token: str
    created_at: float
    expires_at: float
    authenticated: bool
    user: object = None

    @classmethod
    def create(cls, token: str, max_age: int = 3600 * 8) -> 'Session':
        if not isinstance(token, str): raise TypeError(f"Token must be a string!")
        now = time.time()
        return cls(
            token=token,
            created_at=now,
            expires_at=now + max_age,
            authenticated=False
        )

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


def authenticate(session: Session) -> Session:
    session.authenticated = True
    return session


class Sessions(APIRouter):
    verbose: bool
    cache: dict[str, Session] = {}
    session_model: Type[Session]
    authentication_model: Type[callable]

    def __init__(self, session_model: Type[Session] = Session, authentication_model: Type[callable] = authenticate,
                 verbose: bool = DEBUG):
        super().__init__(prefix="/sessions")
        self.session_model = session_model
        self.authentication_model = authentication_model
        self.verbose = verbose

        @self.get("")
        def get_session(request: Request):
            return self.cache

    def __getitem__(self, session_or_token: Any):
        if isinstance(session_or_token, Session): token: str = session_or_token.token
        token = session_or_token
        if isinstance(token, str):
            if self.verbose: log.debug(
                f"{self}: Attempting to retrieve cached session object by token:\n  - key={token}")
            cached = self.cache.get(token)
            if cached is None:
                if self.verbose: log.warning(f"{self}: Could not get session! Attempting to create...")
                self.cache[token] = self.authentication_model(self.session_model.create(token))
                cached = self.cache[token]
            if cached is None: raise RuntimeError
            if self.verbose: log.success(f"{self}: Successfully located:\nsession={cached}!")
            return cached
        else:
            raise TypeError(f"Expected token, got {type(session_or_token)}")
