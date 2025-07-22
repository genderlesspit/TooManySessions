import secrets
from typing import Callable, Any

from loguru import logger as log
from starlette.requests import Request
from starlette.responses import Response
from toomanyports import PortManager
from toomanythreads import ThreadedServer

from . import DEBUG, authenticate, Session, Sessions
from . import Users, User

class SessionedServer(ThreadedServer):
    def __repr__(self):
        return "[SessionedServer]"

    def __init__(
            self,
            host: str = "localhost",
            port: int = PortManager.random_port(),
            session_name: str = "session",
            session_age: int = (3600 * 8),
            session_model: type[Session] = Session,
            authentication_model: type[callable] = authenticate,
            user_model: type[User] = User,
            verbose: bool = DEBUG,
    ) -> None:
        self.host = host
        self.port = port
        self.session_name = session_name
        self.session_age = session_age
        self.session_model = session_model
        self.authentication_model = authentication_model
        self.sessions = Sessions(
            self.session_model,
            self.authentication_model,
            verbose,
        )
        self.user_model = user_model
        self.users = Users(
            self.user_model,
            self.user_model.create,
        )
        self.verbose = verbose

        if not self.session_model.create: raise ValueError(f"{self}: Session models require a create function!")
        # if not isinstance(self.session_model.create, classmethod): raise TypeError(f"{self}: Session models' create function must be a class method!")
        if not isinstance(self.authentication_model, Callable): raise TypeError(
            f"{self}: Authentication models must be a function!")
        if not self.user_model.create: raise ValueError(f"{self}: User models require a create function!")
        # if not isinstance(self.session_model.create, classmethod): raise TypeError(f"{self}: Session models' create function must be a class method!")

        super().__init__(verbose=self.verbose)
        if self.verbose:
            try:
                log.success(f"{self}: Initialized successfully!\n  - host={self.host}\n  - port={self.port}")
            except Exception:
                log.success(f"Initialized new ThreadedServer successfully!\n  - host={self.host}\n  - port={self.port}")

        self.include_router(self.sessions)
        self.include_router(self.users)

        @self.middleware("http")
        async def middleware(request: Request, call_next):
            response = await call_next(request)
            response, session = self.session_manager(request, response)
            session = self.auth_manager(session)
            if isinstance(session, Response): return session
            session = self.user_manager(session)
            if isinstance(session, Response): return session
            return response

    def session_manager(self, request: Request, response) -> tuple[Any, Session]:
        token = request.cookies.get(self.session_name)

        if not token:
            token = secrets.token_urlsafe(32)
        elif "token=" in token:
            log.warning(f"Token is dirty!: {token}")
            token = secrets.token_urlsafe(32)

        response.set_cookie(self.session_name, token, max_age=self.session_age)
        session = self.sessions[token]
        return response, session

    def auth_manager(self, session: Session) -> Session | Response:
        session = self.authentication_model(session)
        if not session.authenticated:
            return Response(content="Permission Error", status_code=401)
        return session

    def user_manager(self, session: Session) -> Session | Response:
        try:
            session.user = self.users[session.token]
        except Exception:
            return Response(content="Login Failed!", status_code=401)
        return session
