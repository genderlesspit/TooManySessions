import secrets
from functools import cached_property
from typing import Type

from fastapi import APIRouter
from loguru import logger as log
from starlette.requests import Request
from starlette.responses import Response, RedirectResponse, HTMLResponse
from toomanyports import PortManager
from toomanythreads import ThreadedServer

from . import DEBUG, Session, Sessions, CWD_TEMPLATER
from . import Users, User
from .msft_graph_api import GraphAPI
from .msft_oauth import MicrosoftOAuth, MSFTOAuthTokenResponse
from .passkey import Passkey


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
            port: int = PortManager().random_port(),
            session_name: str = "session",
            session_age: int = (3600 * 8),
            session_model: Type[Session] = Session,
            authentication_model: str | Type[APIRouter] | None = "msft", #available auth models are 'msft', 'pass', and None
            user_model: Type[User] | None = User,
            user_whitelist: list = None,
            tenant_whitelist: list = None,
            verbose: bool = DEBUG,
            **kwargs
    ) -> None:
        #simple declarations
        self.verbose = verbose
        self.host = host
        self.port = port
        self.session_name = session_name
        self.session_age = session_age

        #session model - must be of the Session class
        self.session_model = session_model
        if not self.session_model.create:
            raise ValueError(f"{self}: Session models require a create function!")
        for kwarg in kwargs:
            setattr(self, kwarg, kwargs.get(kwarg))

        #setup sessions architecture
        if not getattr(self, "sessions", None):
            self.sessions = Sessions(
                session_model=self.session_model,
                session_name=self.session_name,
                verbose=self.verbose
            )

        #initialize authentication model
        self.authentication_model = authentication_model
        if isinstance(authentication_model, str):
            if authentication_model == "pass":
                self.authentication_model: Passkey = Passkey(self)
                user_model = None
            if authentication_model == "msft":
                self.authentication_model: MicrosoftOAuth = MicrosoftOAuth(self)
        if isinstance(authentication_model, APIRouter):
            self.authentication_model = authentication_model
        if authentication_model is None:
            self.authentication_model = no_auth

        log.debug(f"{self}: Initialized authentication model as {self.authentication_model}")

        self.user_model = user_model
        if self.user_model is None:
            if (isinstance(self.authentication_model, MicrosoftOAuth)): raise RuntimeError("You can't have OAuth without a User Model!")
            log.warning(f"{self}: Launching without users! Ignore if this is intentional.")
        else:
            self.users = Users(
                self.user_model,
                self.user_model.create,
            )
            if not self.user_model.create:
                raise ValueError(f"{self}: User models require a create function!")

            self.user_whitelist = user_whitelist
            log.debug(f"{self}: Initialized user_whitelist:\n  - whitelist={self.user_whitelist}")
            self.tenant_whitelist = tenant_whitelist
            log.debug(f"{self}: Initialized tenant_whitelist:\n  - whitelist={self.tenant_whitelist}")

        super().__init__(
            host=self.host,
            port=self.port,
            verbose=self.verbose
        )
        #these must be after super().__init__
        self.include_router(self.sessions)
        if not self.authentication_model == no_auth: self.include_router(self.authentication_model)
        if getattr(self, "user_model", None): self.include_router(self.users)

        if self.verbose:
            try:
                log.success(f"{self}: Initialized successfully!\n  - host={self.host}\n  - port={self.port}")
            except Exception:
                log.success(f"Initialized new ThreadedServer successfully!\n  - host={self.host}\n  - port={self.port}")

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
            if "/logout" in request.url.path:
                return await call_next(request)
            if "/passkey" in request.url.path:
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
                    elif isinstance(self.authentication_model, Passkey):
                        auth: Passkey = self.authentication_model
                        return await auth.show_passkey_prompt(request)

                if getattr(self, "user_model", None):
                    if not session.user:
                        setattr(session, "user", self.users.user_model.create(session))
                        user: User = session.user
                        if not session.user: raise RuntimeError
                        if self.authentication_model == no_auth:
                            pass
                        elif isinstance(self.authentication_model, MicrosoftOAuth):
                            metadata: MSFTOAuthTokenResponse = session.oauth_token_data
                            session.graph = GraphAPI(metadata.access_token)
                            setattr(user, "me", session.graph.me)
                            setattr(user, "org", session.graph.organization)
                            if (user.me is None) or (user.org is None): raise RuntimeError("Error fetching user's information!")

                    if (getattr(self, 'tenant_whitelist', None) is not None) or (getattr(self, 'user_whitelist', None) is not None):
                        log.warning(f"{self}: Whitelist status is {session.whitelisted} for {session.token}!")
                        log.debug(f"{self}: Tenant whitelist:\n  - whitelist={self.tenant_whitelist}")
                        log.debug(f"{self}: User whitelist:\n  - whitelist={self.user_whitelist}")
                        user: User = session.user
                        if not session.user: raise RuntimeError
                        log.debug(f"{self}: Successfully found user setup!\n  - user={user}")
                        if isinstance(self.authentication_model, MicrosoftOAuth):
                            tenant = user.org.id
                            email = user.me.userPrincipalName
                            if not (tenant and email): raise RuntimeError
                            log.debug(f"{self}: Successfully found user's whitelist details!\n  - tenant={tenant}\n  - email={email}")
                            if not session.whitelisted:
                                try:
                                    if getattr(self, 'tenant_whitelist', None) is not None:
                                        log.debug(f"{self}: Checking tenant id...")
                                        log.debug(f"{self}: Found tenant {tenant} for {session.user.me.userPrincipalName}")
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
                                    return HTMLResponse(
                                        self.popup_unauthorized("You're not authorized to access this website.\n"
                                                                "Either log into a different account or contact a system administrator."))
                                setattr(session, "whitelisted", True)

                    if not session.welcomed:
                        log.warning(f"{self}: User has yet to be welcomed!")
                        if isinstance(self.authentication_model, MicrosoftOAuth):
                            setattr(session, "welcomed", True)
                            return HTMLResponse(self.authentication_model.welcome(session.user.me.displayName))

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

        @self.get("/me")
        def me(request: Request):
            cookie = request.cookies.get(self.session_name)
            session = self.sessions.cache.get(cookie)
            if not session:
                return HTMLResponse(self.popup_error(401, "No user found"))
            return HTMLResponse(self.render_user_profile(session))

        @self.get("/logout")
        def logout(request: Request):
            cookie = request.cookies.get(self.session_name)
            session = self.sessions.cache.get(cookie)
            if not session:
                return HTMLResponse(self.popup_error(401, "You are already logged out!"))
            if session:
                log.debug(f"Logging out session: {cookie}")

                # Build Microsoft logout request
                if isinstance(self.authentication_model, MicrosoftOAuth):
                    post_logout_redirect_uri = self.logout_uri + "/complete"
                    logout_request = self.authentication_model.build_logout_request(session, post_logout_redirect_uri)

                # Delete session from cache
                del self.sessions.cache[cookie]

                # Create redirect response and delete cookie
                response = RedirectResponse(url=logout_request.url, status_code=302)
                response.delete_cookie(self.session_name, path="/")
                return response

        @self.get("/logout/complete")
        def logout(request: Request):
            popup_html = self.popup_generic(
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
            return HTMLResponse(popup_html)

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

    @staticmethod
    def redirect_html(target_url):
        """Generate HTML that redirects to OAuth URL"""
        template = CWD_TEMPLATER.get_template('redirect.html')
        return template.render(redirect_url=target_url)

    @cached_property
    def logout_uri(self):
        return self.url + "/logout"

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

        template = CWD_TEMPLATER.get_template('popup.html')

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

    def popup_unauthorized(self, message=None):
        """Generate unauthorized popup HTML"""
        template = CWD_TEMPLATER.get_template('popup.html')

        return template.render(
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

        template = CWD_TEMPLATER.get_template('popup.html')

        return template.render(
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

    def render_user_profile(self, session: Session) -> str:
        """
        Render user profile HTML using the Me dataclass data.

        Args:
            user: Me dataclass instance with user data
            env: Jinja2 Environment instance
            template_name: Template filename (default: "user.html")
            logout_uri: URI for logout link (default: "/logout")

        Returns:
            Rendered HTML string
        """
        # Convert dataclass to dict and add logout_uri
        me = getattr(session.user, "me", None)
        if me is None:
            return self.popup_404("This user does not have a detail view!")
        # Load and render template
        template = CWD_TEMPLATER.get_template("user.html")
        return template.render(logout_uri=self.logout_uri, **me.__dict__)