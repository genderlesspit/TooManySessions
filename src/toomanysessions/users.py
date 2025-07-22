from dataclasses import dataclass
from typing import Any, Type

from fastapi import APIRouter
from loguru import logger as log
from starlette.requests import Request
from starlette.responses import Response

from . import DEBUG


@dataclass
class User:
    token: str

    @classmethod
    def create(cls, token):
        return cls(token)


class Users(APIRouter):
    verbose: bool
    cache: dict[str, User] = {}

    def __init__(
            self,
            user_model: Type[User] = User,
            user_setup: Type[callable] = User.create,
            verbose: bool = DEBUG
    ):
        super().__init__(prefix="/users")
        self.user_model = user_model
        self.user_setup = user_setup
        self.verbose = verbose

        @self.get("")
        def get_users(request: Request):
            return self.cache

    def __getitem__(self, token: Any):
        if isinstance(token, str):
            if self.verbose: log.debug(
                f"{self}: Attempting to retrieve user object by session token:\n  - key={token}")
            cached = self.cache.get(token)
            if cached is None:
                if self.verbose: log.warning(f"{self}: Could not get user! Attempting to create...")
                try:
                    self.cache[token] = self.user_setup(token)
                except Exception as e:
                    if self.verbose: log.warning(f"{self}: User creation failed!:\n{e}")
                    return Response(content="Login Failed!", status_code=401)
                cached = self.cache[token]
            if cached is None: raise RuntimeError
            if self.verbose: log.success(f"{self}: Successfully located:\nsession={cached}!")
            return cached
        else:
            raise TypeError(f"Expected token, got {type(token)}")
