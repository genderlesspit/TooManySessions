import asyncio
import secrets
import time
from functools import cached_property
from typing import Callable, Any, Type, List, Coroutine

from fastapi import APIRouter
from loguru import logger as log
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse, HTMLResponse
from toomanyports import PortManager
from toomanythreads import ThreadedServer

from . import DEBUG, authenticate, Session, Sessions
from . import Users, User
from .oauth import MicrosoftOAuth

def no_auth(session: Session):
    session.authenticated = True
    return session

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
            self.session_model,
            verbose,
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
            # Skip auth middleware for bypass routes
            if getattr(self.authentication_model, "bypass_routes", None):
                log.debug(f"{self}: Acknowledged bypass_routes: {self.authentication_model.bypass_routes}")
                if request.url.path in self.authentication_model.bypass_routes:
                    log.debug(f"{self}: Bypassing auth middleware for {request.url}")
                    return await call_next(request)

            # Skip for static files
            if "/favicon.ico" in request.url.path:
                return await call_next(request)

            # Get session from request state (set by session middleware)
            session = getattr(request.state, 'session', None)
            if not session:
                # Fallback if session middleware didn't run
                temp_response, session = self.session_manager(request)

            if not session.authenticated:
                log.warning(f"{self}: Session is not authenticated!")
                if self.authentication_model == no_auth:
                    auth: no_auth = self.authentication_model
                    self.authentication_model(session)
                elif isinstance(self.authentication_model, MicrosoftOAuth):
                    auth: MicrosoftOAuth = self.authentication_model
                    oauth_request = auth.build_auth_code_request(session)
                    return HTMLResponse(self.redirect_html(oauth_request.url))

            response = await call_next(request)
            return response

    def session_manager(self, request: Request, response=None) -> tuple[Response, Session]:
        if response is None:
            response = Response()

        # For OAuth callback, use state parameter as session token
        if "/microsoft_oauth/callback" in request.url.path:
            token = request.query_params.get("state")
            if not token:
                return Response("Missing state parameter", status_code=400), None
        else:
            # Normal session management
            token = request.cookies.get(self.session_name)
            if not token:
                token = secrets.token_urlsafe(32)

        response.set_cookie(self.session_name, token, max_age=self.session_age)
        session = self.sessions[token]
        if session.authenticated:
            log.debug(f"{self}: This session was marked as authenticated!")
        return response, session

    @staticmethod
    def redirect_html(target_url):
        """Generate HTML that redirects to OAuth URL"""
        return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Redirecting to {target_url}...</title>
        <meta http-equiv="refresh" content="0;url={target_url}">
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                text-align: center; 
                padding: 50px;
                background: #f5f5f5;
            }}
            .container {{ 
                background: white; 
                padding: 30px; 
                border-radius: 8px; 
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                max-width: 400px;
                margin: 0 auto;
            }}
            .spinner {{ 
                border: 4px solid #f3f3f3;
                border-top: 4px solid #0078d4;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
            a {{ color: #0078d4; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Redirecting to Microsoft</h2>
            <div class="spinner"></div>
            <p>If you are not redirected automatically, <a href="{target_url}">click here</a></p>
        </div>
        
        <script>
            // Redirect in same window after a brief delay
            setTimeout(function() {{
                window.location.href = '{target_url}';
            }}, 1000);
        </script>
    </body>
    </html>
    """