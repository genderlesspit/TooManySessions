import time
from dataclasses import dataclass
from typing import Type, Any
import requests
import httpx
from fastapi import APIRouter
from httpx import request
from loguru import logger as log
from starlette.requests import Request

from . import DEBUG


@dataclass
class Session:
    token: str
    created_at: float = None
    expires_at: float = None
    authenticated: bool = False
    throttle: int = 0
    user: object = None
    code: str = None
    token_data: str = None

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


async def authenticate(session: Session, session_name: str, redirect_uri: str) -> Session:
    log.debug(f"[TooManySessions] Attempting to authenticate session {session.token}")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                redirect_uri,
                params={f"{session_name}": f"{session.token}"},
                timeout=5.0  # Add explicit timeout
            )
        log.debug(response)
    except httpx.TimeoutException:
        log.error(f"Authentication timeout for session {session.token}")
        session.authenticated = False
    except Exception as e:
        log.error(f"Authentication failed: {e}")
        session.authenticated = False
    return session


class Sessions(APIRouter):
    def __init__(
        self,
        session_model: Type[Session] = Session,
        session_name: str = "session",
        verbose: bool = DEBUG
    ):
        super().__init__(prefix="/sessions")
        self.session_model = session_model
        self.verbose = verbose
        self.cache: dict[str, Session] = {}
        self.session_name = session_name

        @self.get("")
        def get_session(request: Request):
            return self.cache

    def __getitem__(self, session_or_token: Any):
        if isinstance(session_or_token, Session): session_or_token: str = session_or_token.token
        token = session_or_token
        if isinstance(token, str):
            if self.verbose: log.debug(
                f"{self}: Attempting to retrieve cached session object by token:\n  - key={token}"
            )
            cached = self.cache.get(token)
            if cached is None:
                if self.verbose: log.warning(f"{self}: Could not get session! Attempting to create...")
                new_session = self.session_model.create(token)
                self.cache[token] = new_session
                cached = self.cache[token]
            if cached is None: raise RuntimeError
            if self.verbose: log.success(f"{self}: Successfully located:\nsession={cached}!")
            return cached
        else:
            raise TypeError(f"Expected token, got {type(session_or_token)}")
