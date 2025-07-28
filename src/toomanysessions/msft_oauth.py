from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import httpx
import pyperclip

import time

import pkce
import toml
from fastapi import APIRouter
from starlette.requests import Request
from loguru import logger as log
from starlette.responses import RedirectResponse, HTMLResponse
from toomanyconfigs.core import TOMLConfig

from . import CWD_TEMPLATER
from .sessions import Sessions, Session

DEBUG = True


# noinspection PyUnresolvedReferences
@dataclass
class MSFTOAuthCFG(TOMLConfig):
    client_id: str = None
    tenant_id: str = "common"
    scopes: str = "User.Read"

@dataclass
class MSFTOAuthCallback:
    code: str
    state: str
    session_state: str

@dataclass
class MSFTOAuthTokenResponse:
    token_type: str
    scope: str
    expires_in: int
    ext_expires_in: int
    access_token: str

class MicrosoftOAuth(APIRouter):
    def __init__(
        self, 
        server,
        **cfg_kwargs
    ):
        self.server = server
        from . import SessionedServer
        if not isinstance(server, SessionedServer): raise TypeError("Passed server is not an instance of Sessioned Server")

        _ = self.cwd
        self.cfg_kwargs = cfg_kwargs
        _ = self.cfg
        self.tenant_id = self.cfg.tenant_id
        self.scopes = self.cfg.scopes
        self.sessions = self.server.sessions
        self.url = self.server.url

        super().__init__(prefix="/microsoft_oauth")

        @self.get("/callback")
        async def callback(request: Request):
            params = request.query_params
            log.debug(f"{self}: Received auth callback with params: ")
            for param in params:
                log.debug(f"  - {param}={str(params[param])[:10]}...")
            try:
                params = MSFTOAuthCallback(**params)
                session = self.sessions[params.state]
                
                if not session:
                    log.error("Session not found for state")
                    raise ValueError("Invalid session state")
                    
                log.debug(f"Retrieved session: {session}")
                
                if not hasattr(session, 'verifier'):
                    log.error(f"{self}: Session missing verifier attribute")
                    log.debug(f"{self}: Session attributes: {[attr for attr in dir(session) if not attr.startswith('_')]}")
                    raise ValueError("OAuth session missing PKCE verifier")
                    
                if not session.verifier:
                    log.error("Session verifier is empty")
                    raise ValueError("OAuth session verifier is empty")
                    
                log.debug(f"Using verifier: {session.verifier[:10]}...")
                
            except Exception as e:
                log.error(f"OAuth callback failed: {type(e).__name__}: {str(e)}")
                from . import SessionedServer
                server: SessionedServer = self.server
                return server.popup_error(500, e)
        
            session.code = params.code

            token_request = self.build_access_token_request(session) #type: ignore
            async with httpx.AsyncClient() as client:
                response = await client.send(token_request)
                if response.status_code == 200:
                    creds = MSFTOAuthTokenResponse(**response.json())
                    setattr(session, "oauth_token_data", creds)
                    log.debug(f"{self}: Successfully exchanged code for token")
                    setattr(session, "authenticated", True)
                    log.debug(f"{self}: Updated session:\n  - {session}")
                    key = self.sessions.session_name
                    response = HTMLResponse(self.login_successful)
                    response.set_cookie(
                        key=key,
                        value=session.token,
                        httponly=True
                    )
                    return response
                else:
                    log.error(f"Token exchange failed: {response.status_code} - {response.text}")
                    raise Exception(f"Token exchange failed: {response.status_code}")

        self.bypass_routes = []
        for route in self.routes:
            self.bypass_routes.append(route.path)

    @cached_property
    def cwd(self) -> SimpleNamespace:
        ns = SimpleNamespace(
            path=Path.cwd(),
            cfg_file = Path.cwd() / "msftoauth2.toml"
        )
        #     cfg_file=Path.cwd() / "msftoauth2.toml"
        # )
        # for name, p in vars(ns).items():
        #     if p.suffix:
        #         p.parent.mkdir(parents=True, exist_ok=True)
        #         p.touch(exist_ok=True)
        #         if DEBUG:
        #             log.debug(f"[{self}]: Ensured file {p}")
        #     else:
        #         p.mkdir(parents=True, exist_ok=True)
        #         if DEBUG:
        #             log.debug(f"[{self}]: Ensured directory {p}")
        return ns

    @cached_property
    def cfg(self):
        return MSFTOAuthCFG.from_toml(self.cwd.cfg_file, **self.cfg_kwargs)

    @cached_property
    def client_id(self):
        return self.cfg.client_id

    @cached_property
    def redirect_uri(self):
        return f"{self.url}/microsoft_oauth/callback"

    def build_auth_code_request(self, session: Session):
        """Build Microsoft OAuth authorization URL with fresh PKCE"""
        code_verifier = pkce.generate_code_verifier(length=43)
        code_challenge = pkce.get_code_challenge(code_verifier)

        session.verifier = code_verifier  # Direct assignment instead of setattr
        log.debug(f"{self}: Stored verifier in session: {session.verifier}...")
        log.debug(f"{self}: Session after storing verifier: {session}")
        log.debug(f"{self}: Generated code_challenge: {code_challenge}")

        base_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"

        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": self.scopes,
            "state": session.token,
            "code_challenge": code_challenge,  # Only the challenge goes in URL
            "code_challenge_method": "S256"
        }

        log.debug(f"{self}: Building request with the following params:")
        for param in params:
            log.debug(f"  -{param}={params.get(param)[:10]}")

        url = f"{base_url}?{urlencode(params)}"
        log.debug(f"Built OAuth URL: {url}")

        client = httpx.Client()
        request = client.build_request("GET", url)

        return request  # Don't return the verifier - it's stored in session

    def build_access_token_request(self, session):
        """Build the POST request to exchange authorization code for access token"""
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        try:
            data = {
                "client_id": self.client_id,
                "scope": self.scopes,
                "code": session.code,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": session.verifier,
                # Note: No client_secret needed for public clients using PKCE
            }
        except Exception:
            raise Exception

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        client = httpx.Client()
        return client.build_request("POST", url, data=data, headers=headers)

    @cached_property
    def login_successful(self):
       template = CWD_TEMPLATER.get_template('redirect.html')
       return template.render(redirect_url=self.url)

    def welcome(self, name):
        template = CWD_TEMPLATER.get_template('welcome.html')
        return template.render(
            user=name,
            redirect_url=self.url
        )