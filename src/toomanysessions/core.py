import asyncio
import secrets
from functools import cached_property
from pathlib import Path
from typing import Type

from fastapi import APIRouter
from fastj2 import FastJ2
from loguru import logger as log
from pyzurecli import GraphAPI
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse
from toomanyconfigs import CWD
from toomanyports import PortManager
from toomanythreads import ThreadedServer

from . import DEBUG, Session, Sessions, CWD_TEMPLATER
from . import Users, User
from .msft_oauth import MicrosoftOAuth, MSFTOAuthTokenResponse
from .passkey import Passkey


def no_auth(session: Session):
    session.authenticated = True
    return session


REQUEST = None


class SessionedServer(CWD, ThreadedServer):
    def __init__(
            self,
            host: str = "localhost",
            port: int = PortManager().random_port(),
            session_name: str = "session",
            session_age: int = (3600 * 8),
            session_model: Type[Session] = Session,
            authentication_model: str | Type[APIRouter] | None = "msft",
            # available auth models are 'msft', 'pass', and None
            user_model: Type[User] | None = User,
            user_whitelist: list = None,
            tenant_whitelist: list = None,
            verbose: bool = DEBUG,
            **kwargs
    ):
        CWD.__init__(
            self
        )
        # simple declarations
        self.verbose = verbose
        self.host = host
        self.port = port
        self.session_name = session_name
        self.session_age = session_age
        for kwarg in kwargs:
            setattr(self, kwarg, kwargs.get(kwarg))

        if not getattr(self, "session_model", None):
            self.session_model = session_model
            if not self.session_model.create: raise ValueError(f"{self}: Session models require a create function!")

        log.debug(f"{self}: Initialized session_model as {self.session_model}!")

        if not getattr(self, "sessions", None):
            self.sessions = Sessions(
                session_model=self.session_model,
                session_name=self.session_name,
                verbose=self.verbose
            )

        log.debug(f"{self}: Initialized sessions as {self.sessions}!")

        if not getattr(self, "authentication_model", None):
            self.authentication_model = authentication_model
            self.is_passkey = False #isinstance(self.authentication_model, Passkey)
            self.is_msft = False #isinstance(self.authentication_model, MicrosoftOAuth)
            self.is_custom = False #isinstance(self.authentication_model, APIRouter)
            self.is_noauth = False #(self.authentication_model == no_auth)
            if isinstance(authentication_model, str):
                if authentication_model == "pass":
                    self.authentication_model: Passkey = Passkey(self)
                    user_model = None
                    self.is_passkey = True
                if authentication_model == "msft":
                    self.authentication_model: MicrosoftOAuth = MicrosoftOAuth(self)
                    if not getattr(self, "redirect_uri", None):
                        self.redirect_uri = f"{self.url}/microsoft_oauth/callback"
                    self.is_msft = True
            elif self.is_custom:
                self.authentication_model = authentication_model
                self.is_custom = True
            elif authentication_model is None:
                self.authentication_model = no_auth
                self.is_noauth = True

        log.debug(f"{self}: Initialized authentication model as {self.authentication_model}!")

        if not getattr(self, "user_model", None):
            self.user_model = user_model
            if self.user_model is None:
                if self.is_msft: raise RuntimeError("You can't have OAuth without a User Model!")
                log.warning(f"{self}: Launching without persisted users! Ignore if this is intentional.")
            else:
                self.users = Users(
                    self.user_model,
                    self.user_model.create,
                )
                if not self.user_model.create: raise ValueError(f"{self}: User models require a create function!")

                if self.is_msft:
                    self.user_whitelist = user_whitelist
                    log.debug(f"{self}: Initialized user_whitelist:\n  - whitelist={self.user_whitelist}")

                    if tenant_whitelist:
                        self.tenant_whitelist = [self.authentication_model.azure_cli.tenant_id] + tenant_whitelist
                    self.tenant_whitelist = tenant_whitelist
                    log.debug(f"{self}: Initialized tenant_whitelist:\n  - whitelist={self.tenant_whitelist}")

        log.debug(f"{self}: Initialized user model as {self.user_model}!")

        if not getattr(self, "sessioned_middleware", None):
            self.sessioned_middleware = self.default_middleware

        ThreadedServer.__init__(
            self,
            host=self.host,
            port=self.port,
            verbose=self.verbose,
            # database={}
        )

        self.include_router(self.sessions)
        if not self.authentication_model == no_auth: self.include_router(self.authentication_model)
        if getattr(self, "user_model", None): self.include_router(self.users)

        self.default_templater = FastJ2(error_method=self.renderer_error, cwd=Path(__file__).parent)

        if self.verbose: log.success(
            f"Initialized new Sessioned successfully!\n  - host={self.host}\n  - port={self.port}")

        @self.middleware("http")
        async def middleware(request: Request, call_next):
            log.info(f"{self}: Got request for '{request.url.path}':\n  - cookies={request.cookies.items()}")

            # Check if we should bypass auth entirely
            bypass_paths = ["/microsoft_oauth", "/authenticated/", "/favicon.ico", "/logout", "/passkey"]

            # Add custom bypass routes if they exist
            if getattr(self.authentication_model, "bypass_routes", None):
                bypass_paths.extend(self.authentication_model.bypass_routes)

            # Check if current path should bypass auth
            if any(path in request.url.path for path in bypass_paths):
                log.debug(f"{self}: Bypassing auth middleware for {request.url}")
                return await call_next(request)

            try:
                return await self.sessioned_middleware(request, call_next)
            except Exception as e:
                log.error(f"{self}: Error processing request: {e}")
                return self.popup_error(
                    error_code=500,
                    message="An unexpected error occurred while processing your request."
                )

        @self.get("/me")
        def me(request: Request):
            cookie = request.cookies.get(self.session_name)
            session = self.sessions.cache.get(cookie)
            if not session:
                return self.popup_error(401, "No user found")
            return self.render_user_profile(session)

        @self.get("/logout")
        def logout(request: Request):
            cookie = request.cookies.get(self.session_name)
            session = self.sessions.cache.get(cookie)
            if not session:
                return self.popup_error(401, "You are already logged out!")
            if session:
                log.debug(f"Logging out session: {cookie}")

                # Build Microsoft logout request
                if isinstance(self.authentication_model, MicrosoftOAuth):
                    post_logout_redirect_uri = self.logout_uri + "/complete"
                    logout_request = self.authentication_model.build_logout_request(session, post_logout_redirect_uri)
                    response = RedirectResponse(url=logout_request.url, status_code=302)
                    response.delete_cookie(self.session_name, path="/")
                else:
                    raise NotImplementedError

                del self.sessions.cache[cookie]
                return response

        @self.get("/logout/complete")
        def logout():
            return self.popup_generic(
                popup_type="success",
                header="Logged Out",
                message="You have been successfully logged out.",
                buttons=[
                    {
                        "text": "Go to Login",
                        "onclick": f"window.location.href='{self.url or '/'}'",
                        "class": ""
                    }
                ]
            )

    def __repr__(self):
        return f"{self.cwd.name.title()}.SessionedServer"

    async def default_middleware(self, request, call_next):
        session = self.session_manager(request)
        if session.throttle != 0:
            log.debug(f"{self}: Session '{session.token}' has been throttled for {session.throttle} seconds!")
            asyncio.wait(session.throttle)

        if not session.authenticated:
            log.warning(f"{self}: Session is not authenticated!")
            if self.is_noauth:
                log.warning(f"{self}: 'No authentication' is True! Bypassing authentication!")
                self.authentication_model(session)
            elif self.is_msft:
                oauth_request = self.authentication_model.build_auth_code_request(session)
                return self.redirect_html(oauth_request.url)
            elif self.is_passkey:
                return await self.authentication_model.show_passkey_prompt(request)

        if getattr(self, "user_model", None):
            if not session.user:
                setattr(session, "user", self.users.user_model.create(session))
                user: User = session.user
                if not session.user: raise RuntimeError(
                    "The user model create method does not persist user to session!")
                if self.is_msft:
                    metadata: MSFTOAuthTokenResponse = session.oauth_token_data
                    session.graph = GraphAPI(metadata.access_token)
                    setattr(user, "me", session.graph.me)
                    setattr(user, "org", session.graph.organization)
                    if (user.me is None) or (user.org is None): raise RuntimeError(
                        "Error fetching user's information!")
            if self.is_msft:
                if self.tenant_whitelist is not None or self.user_whitelist is not None:
                    if not session.whitelisted:
                        log.warning(f"{self}: Whitelist status is {session.whitelisted} for {session.token}!")
                        log.debug(f"{self}: Tenant whitelist:\n  - whitelist={self.tenant_whitelist}")
                        log.debug(f"{self}: User whitelist:\n  - whitelist={self.user_whitelist}")
                        user: User = session.user
                        if not session.user: raise RuntimeError(
                            "Can't check if user is whitelisted if users aren't persisted to session!")
                        tenant = user.org.id
                        email = user.me.userPrincipalName
                        if not (tenant and email): raise RuntimeError(
                            "TenantID and email weren't correctly retrieved using GraphAPI!")
                        log.debug(
                            f"{self}: Successfully found user's whitelist details!\n  - tenant={tenant}\n  - email={email}")
                        try:
                            # Check user's tenant
                            if getattr(self, 'tenant_whitelist', None) is not None:
                                log.debug(f"{self}: Checking tenant id...")
                                log.debug(
                                    f"{self}: Found tenant {tenant} for {session.user.me.userPrincipalName}")
                                if tenant not in self.tenant_whitelist:
                                    log.warning(
                                        f"{self}: Unauthorized tenant {tenant} attempted to access the website!")
                                    raise PermissionError
                            else:
                                log.debug(f"{self}: No tenant whitelist. Skipping...")

                            # Then check user whitelist
                            if getattr(self, 'user_whitelist', None) is not None:
                                log.debug(f"{self}: Checking user's email...")
                                if email not in self.user_whitelist:
                                    log.warning(
                                        f"{self}: Unauthorized user {email} attempted to access the website!")
                                    raise PermissionError
                            else:
                                log.debug(f"{self}: No user whitelist. Skipping...")

                        except PermissionError:
                            return self.popup_unauthorized("You're not authorized to access this website.\n"
                                                           "Either log into a different account or contact a system administrator.")
                        setattr(session, "whitelisted", True)

                if not session.welcomed:
                    log.warning(f"{self}: User has yet to be welcomed!")
                    if isinstance(self.authentication_model, MicrosoftOAuth):
                        setattr(session, "welcomed", True)
                        return self.authentication_model.welcome(session.user.me.displayName)

        response = await call_next(request)

        # Handle 404s with animated popup
        if response.status_code == 404:
            return self.popup_404(
                message=f"The page '{request.url.path}' could not be found."
            )

        return response

    def session_manager(self, request: Request) -> Session | Response:
        if "/microsoft_oauth/callback" in request.url.path:
            token = request.query_params.get("state")
            log.warning(token)
            if not token:
                return Response("Missing state parameter", status_code=400)
        else:
            token = request.cookies.get(self.session_name)  # "session":
            if not token:
                token = secrets.token_urlsafe(32)
        session = self.sessions[token]
        setattr(session, "request", request)
        session.request.cookies[self.session_name] = session.token
        log.debug(f"{self}: Associated session with request, {request}\n  - cookies={request.cookies}")
        if session.authenticated:
            log.debug(f"{self}: This session was marked as authenticated!")
        return session

    def redirect_html(self, target_url):
        """Generate HTML that redirects to OAuth URL"""
        return self.default_templater.safe_render('redirect.html', redirect_url=target_url)

    @cached_property
    def logout_uri(self):
        return self.url + "/logout"

    def popup_404(self, message=None, redirect_delay=5000):
        """Generate 404 popup HTML"""
        return self.default_templater.safe_render(
            'popup.html',
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

        return self.default_templater.safe_render(
            'popup.html',
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

    def popup_unauthorized(self, message=None):
        """Generate unauthorized popup HTML"""
        return self.default_templater.safe_render(
            'popup.html',
            title="Unauthorized Access",
            header="Unauthorized Access",
            text=message or "You do not have permission to access this resource. Please check your credentials and try again.",
            icon_content="⚠",
            icon_color="linear-gradient(135deg, #dc2626, #991b1b)",
            buttons=[
                {
                    "text": "Try Again",
                    "onclick": "window.location.reload()",
                    "class": ""
                },
                {
                    "text": "Logout",
                    "onclick": f"window.location.href='{self.logout_uri}'",
                    "class": "secondary"
                }
            ],
            footer_text="Contact support if this issue persists"
        )

    def popup_generic(self, popup_type="info", title=None, header=None, message=None,
                      icon_content=None, icon_color=None, buttons=None, footer_text=None,
                      auto_close_ms=None, redirect_url=None, redirect_delay_ms=None,
                      show_loading_dots=False):
        """Generate generic popup HTML with customizable styling and content"""
        from loguru import logger as log

        log.debug(f"Generating {popup_type} popup with title: {title}")

        # Default configurations for different popup types
        popup_configs = {
            "info": {
                "title": "Information",
                "header": "Information",
                "message": "Here's some information for you.",
                "icon_content": "ℹ",
                "icon_color": "linear-gradient(135deg, #0078d4, #005a9e)",
                "footer_text": None
            },
            "success": {
                "title": "Success",
                "header": "Success",
                "message": "Operation completed successfully!",
                "icon_content": "✓",
                "icon_color": "linear-gradient(135deg, #10b981, #059669)",
                "footer_text": None
            },
            "warning": {
                "title": "Warning",
                "header": "Warning",
                "message": "Please review this information carefully.",
                "icon_content": "⚠",
                "icon_color": "linear-gradient(135deg, #f59e0b, #d97706)",
                "footer_text": "Proceed with caution"
            },
            "error": {
                "title": "Error",
                "header": "Error",
                "message": "Something went wrong. Please try again.",
                "icon_content": "✕",
                "icon_color": "linear-gradient(135deg, #dc2626, #991b1b)",
                "footer_text": "Contact support if this problem persists"
            },
            "loading": {
                "title": "Loading",
                "header": "Loading",
                "message": "Please wait while we process your request",
                "icon_content": "⟳",
                "icon_color": "linear-gradient(135deg, #6366f1, #4f46e5)",
                "footer_text": None,
                "show_loading_dots": True
            }
        }

        # Get default config for popup type
        config = popup_configs.get(popup_type, popup_configs["info"])

        # Default buttons if none provided
        if buttons is None:
            buttons = [
                {
                    "text": "OK",
                    "onclick": "window.close() || window.history.back()",
                    "class": ""
                }
            ]

        return self.default_templater.safe_render(
            'popup.html',
            title=title or config["title"],
            header=header or config["header"],
            text=message or config["message"],
            icon_content=icon_content or config["icon_content"],
            icon_color=icon_color or config["icon_color"],
            buttons=buttons,
            footer_text=footer_text or config.get("footer_text"),
            auto_close_ms=auto_close_ms,
            redirect_url=redirect_url,
            redirect_delay_ms=redirect_delay_ms,
            show_loading_dots=show_loading_dots or config.get("show_loading_dots", False)
        )

    def renderer_error(self, e, template_name, context):
        template = CWD_TEMPLATER.get_template('popup.html')
        return template.render(
            title=f"Error 500",
            header=f"Error 500",
            text=e,
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

    def render_user_profile(self, session: Session):
        me = getattr(session.user, "me", None)
        if me is None: return self.popup_404("This user does not have a detail view!")
        return self.default_templater.safe_render('user.html', logout_uri=self.logout_uri, **me.__dict__)
