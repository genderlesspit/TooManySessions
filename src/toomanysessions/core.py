import asyncio
import secrets
import time
from functools import cached_property
from typing import Callable, Any, Type, List, Coroutine

from fastapi import APIRouter
from loguru import logger as log
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse, HTMLResponse, StreamingResponse, JSONResponse
from toomanyports import PortManager
from toomanythreads import ThreadedServer

from . import DEBUG, authenticate, Session, Sessions, CWD_TEMPLATER
from . import Users, User
from .msft_graph_api import GraphAPI
from .msft_oauth import MicrosoftOAuth, MSFTOAuthTokenResponse


def no_auth(session: Session):
    session.authenticated = True
    return session

REQUEST = None
# def callback(request: Request, **kwargs):
#     log.debug(f"Dummy callback method executed!")
#     return Response(f"{kwargs}")

class SessionedServer(ThreadedServer):
    def __init__(
        self,
        host: str = "localhost",
        port: int = None,
        session_name: str = "session",
        session_age: int = (3600 * 8),
        session_model: Type[Session] = Session,
        authentication_model: str | Type[APIRouter] | None = "msft",
        user_model: Type[User] = User,
        verbose: bool = DEBUG,
    ) -> None:
        """
        :param host:
        :param port:
        :param session_name:
        :param session_age:
        :param session_model:
        :param authentication_model: msft
        :param callback_method:
        :param user_model:
        :param verbose:
        """
        self.host = host
        self.port = port
        self.session_name = session_name
        self.session_age = session_age
        self.session_model = session_model
        self.authentication_model = authentication_model
        # self.auth_callback_method = callback_method
        self.verbose = verbose

        self.sessions = Sessions(
            session_model=self.session_model,
            session_name=self.session_name,
            verbose=self.verbose
        )

        if isinstance(authentication_model, str):
            if authentication_model == "msft":
                self.authentication_model: MicrosoftOAuth = MicrosoftOAuth(self.sessions, self.url)
        if isinstance(authentication_model, APIRouter):
            self.authentication_model = authentication_model
        if not authentication_model:
            self.authentication_model = no_auth
        log.debug(f"{self}: Initialized authentication model as {self.authentication_model}")

        self.user_model = user_model
        self.users = Users(
            self.user_model,
            self.user_model.create,
        )

        if not self.session_model.create:
            raise ValueError(f"{self}: Session models require a create function!")
        # if not isinstance(self.authentication_model, Callable):
        #     raise TypeError(f"{self}: Authentication models must be a function, got {type(self.authentication_model)} instead!")
        # if not isinstance(self.authentication_model(), Coroutine):
        #     raise TypeError(f"{self}: Authentication models must be async!, got {type(self.authentication_model)} instead!")
        if not self.user_model.create:
            raise ValueError(f"{self}: User models require a create function!")

        super().__init__(
            host = self.host,
            port = self.port,
            verbose=self.verbose
        )
        if self.verbose:
            try:
                log.success(f"{self}: Initialized successfully!\n  - host={self.host}\n  - port={self.port}")
            except Exception:
                log.success(f"Initialized new ThreadedServer successfully!\n  - host={self.host}\n  - port={self.port}")

        self.include_router(self.sessions)
        self.include_router(self.users)
        if isinstance(self.authentication_model, MicrosoftOAuth):
            self.include_router(self.authentication_model)

        for route in self.routes:
            log.debug(f"{self}: Initialized route {route.path}")

        @self.middleware("http")
        async def middleware(request: Request, call_next):
            log.info(f"{self}: Got request with following cookies:\n  - cookies={request.cookies.items()}")

            if getattr(self.authentication_model, "bypass_routes", None):
                log.debug(f"{self}: Acknowledged bypass_routes: {self.authentication_model.bypass_routes}")
                if request.url.path in self.authentication_model.bypass_routes:
                    log.debug(f"{self}: Bypassing auth middleware for {request.url}")
                    return await call_next(request)
            if "/authenticated/" in request.url.path:
                return await call_next(request)
            if "/favicon.ico" in request.url.path:
                return await call_next(request)

            try:

                session = self.session_manager(request)

                if not session.authenticated:
                    log.warning(f"{self}: Session is not authenticated!")
                    if self.authentication_model == no_auth:
                        self.authentication_model(session)
                    elif isinstance(self.authentication_model, MicrosoftOAuth):
                        auth: MicrosoftOAuth = self.authentication_model
                        oauth_request = auth.build_auth_code_request(session)
                        return HTMLResponse(self.redirect_html(oauth_request.url))

                if not session.user:
                    session.user = self.users.user_model.create(session)
                    user = session.user
                    if not session.user: raise RuntimeError
                    if self.authentication_model == no_auth:
                        pass
                    elif isinstance(self.authentication_model, MicrosoftOAuth):
                        metadata: MSFTOAuthTokenResponse = session.oauth_token_data
                        session.graph = GraphAPI(metadata.access_token)
                        user.me = await session.graph.me
                        return HTMLResponse(self.authentication_model.welcome(user.me.displayName))

                response = await call_next(request)

                # Handle 404s with animated popup
                if response.status_code == 404:
                    return HTMLResponse(
                        self.popup_404(
                            message=f"The page '{request.url.path}' could not be found."
                        ),
                        status_code=404
                    )

                return response

            except Exception as e:
                log.error(f"{self}: Error processing request: {e}")
                return HTMLResponse(
                    self.popup_error(
                        error_code=500,
                        message="An unexpected error occurred while processing your request."
                    ),
                    status_code=500
                )


    def session_manager(self, request: Request) -> Session:
        if "/microsoft_oauth/callback" in request.url.path:
            token = request.query_params.get("state")
            log.warning(token)
            if not token:
                return Response("Missing state parameter", status_code=400), None
        else:
            token = request.cookies.get(self.session_name) #"session":
            if not token:
                token = secrets.token_urlsafe(32)
        session = self.sessions[token]
        setattr(session, "request", request)
        session.request.cookies[self.session_name] = session.token
        log.debug(f"{self}: Associated session with request, {request}\n  - cookies={request.cookies}")
        if session.authenticated:
            log.debug(f"{self}: This session was marked as authenticated!")
        return session

    @staticmethod
    def redirect_html(target_url):
       """Generate HTML that redirects to OAuth URL"""
       template = CWD_TEMPLATER.get_template('redirect.html')
       return template.render(redirect_url=target_url)

    def popup_404(self, message=None, redirect_delay=5000):
       """Generate 404 popup HTML"""
       template = CWD_TEMPLATER.get_template('popup.html')  # or whatever you name it

       return template.render(
           title="Page Not Found - 404",
           header="404 - Page Not Found",
           text=message or "The page you're looking for doesn't exist or has been moved.",
           icon_content="404",
           icon_color="linear-gradient(135deg, #ef4444, #dc2626)",
           buttons=[
               {
                   "text": "Go Home",
                   "onclick": f"window.location.href='{self.url or '/'}'",
                   "class": ""
               },
               {
                   "text": "Go Back",
                   "onclick": "window.history.back()",
                   "class": "secondary"
               }
           ],
           footer_text="You'll be redirected automatically in 5 seconds",
           redirect_url=self.url or "/",
           redirect_delay_ms=redirect_delay
       )

    def popup_error(self, error_code=500, message=None):
       """Generate generic error popup HTML"""
       error_messages = {
           400: "Bad request - something went wrong with your request.",
           401: "Unauthorized - you need to log in to access this.",
           403: "Forbidden - you don't have permission to access this.",
           404: "Page not found - this page doesn't exist.",
           500: "Internal server error - something went wrong on our end.",
           503: "Service unavailable - we're temporarily down for maintenance."
       }

       template = CWD_TEMPLATER.get_template('generic_popup.html')

       return template.render(
           title=f"Error {error_code}",
           header=f"Error {error_code}",
           text=message or error_messages.get(error_code, "An unexpected error occurred."),
           icon_content="⚠",
           icon_color="linear-gradient(135deg, #f59e0b, #d97706)",
           buttons=[
               {
                   "text": "Go Home",
                   "onclick": f"window.location.href='{self.url or '/'}'",
                   "class": ""
               },
               {
                   "text": "Try Again",
                   "onclick": "window.location.reload()",
                   "class": "secondary"
               }
           ],
           footer_text="Contact support if this problem persists"
       )