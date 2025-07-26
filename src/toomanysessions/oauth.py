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

from .sessions import Sessions, Session

DEBUG = True


# noinspection PyUnresolvedReferences
@dataclass
class MSFTOAuthCFG(TOMLConfig):
    client_id: str = None

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
        self, sessions: Sessions,
        url: str,
        # client_id: str,
        tenant="common",
        scopes: str = "User.Read"
    ):
        self.sessions = sessions
        self.url = url
        self.tenant = tenant
        self.scopes = scopes

        _ = self.cwd
        _ = self.cfg

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
                if not session: raise Exception
                if not hasattr(session, 'verifier') or not session.verifier: raise Exception #type: ignore
            except Exception as e:
                return {"error": f"{e}"}
            session.code = params.code

            token_request = self.build_access_token_request(session) #type: ignore
            async with httpx.AsyncClient() as client:
                response = await client.send(token_request)
                if response.status_code == 200:
                    setattr(session, "oauth_token_data", response.json())
                    log.debug(f"{self}: Successfully exchanged code for token")
                    setattr(session, "authenticated", True)
                    log.debug(f"{self}: Updated session:\n  - {session}")
                    redirect = f"{self.url}/authenticated/{session.token}"
                    response = RedirectResponse(
                        url=self.url,
                        status_code=200,
                    )
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
        return MSFTOAuthCFG.from_toml(self.cwd.cfg_file)

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

        # Store the verifier in the session (server-side, secure)
        session.verifier = code_verifier

        log.debug(f"Generated code_verifier: {code_verifier}")
        log.debug(f"Generated code_challenge: {code_challenge}")

        base_url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize"

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
        url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"

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
        homepage = self.url
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Successful!</title>
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
                .success-icon {{
                    width: 60px;
                    height: 60px;
                    margin: 20px auto;
                    background: #28a745;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    animation: bounce 0.6s ease-in-out;
                }}
                .success-icon::after {{
                    content: "✓";
                    color: white;
                    font-size: 30px;
                    font-weight: bold;
                }}
                @keyframes bounce {{
                    0% {{ transform: scale(0); }}
                    50% {{ transform: scale(1.1); }}
                    100% {{ transform: scale(1); }}
                }}
                h2 {{
                    color: #28a745;
                    margin: 20px 0 10px 0;
                }}
                p {{
                    color: #666;
                    margin: 10px 0;
                }}
                .redirect-message {{
                    margin-top: 20px;
                    font-size: 14px;
                    color: #888;
                }}
                .home-button {{
                    background: #0078d4;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 4px;
                    font-size: 16px;
                    cursor: pointer;
                    margin-top: 20px;
                    transition: background 0.3s ease;
                }}
                .home-button:hover {{
                    background: #106ebe;
                }}
                a {{
                    color: #0078d4;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success-icon"></div>
                <h2>Login Successful!</h2>
                <p>You have been successfully authenticated with Microsoft.</p>
                <button class="home-button" onclick="returnHome()">Return to Homepage</button>
                <div class="redirect-message">
                    <p>You can also close this window and return to the application.</p>
                </div>
            </div>

            <script>
                function returnHome() {{
                    // If this is a popup window, close it and redirect parent
                    if (window.opener && window.opener !== window) {{
                        window.opener.location.href = '{homepage}';
                        window.close();
                    }} else {{
                        // If normal window, just redirect
                        window.location.href = '{homepage}';
                    }}
                }}

                // Optional: Auto-close window after a few seconds if it was opened as a popup
            setTimeout(function() {{
                // Check if this window was opened as a popup
                if (window.opener && window.opener !== window) {{
                    window.close();
                }}
            }}, 10000);
        </script>
    </body>
    </html>
    """