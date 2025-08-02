import asyncio
import time
from functools import cached_property

import bcrypt
from fastapi import APIRouter, FastAPI
from loguru import logger as log
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse
from toomanyconfigs import CWD, TOMLConfig, REPR

from . import Session, CWD_TEMPLATER


def prompt_and_hash_password():
    """Prompt user for password and return bcrypt hash"""
    log.debug(f"{REPR}: Prompting user for password")
    time.sleep(0.02)
    password = input(f"{REPR}: Enter new password: ")
    time.sleep(0.02)
    log.debug(f"{REPR}: Password entered, generating hash")

    # Generate salt and hash password
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

    log.info(f"{REPR}: Password hashed successfully")
    return password_hash.decode('utf-8')


class PasskeyConfig(TOMLConfig):
    hashed_pass: str


class Passkey(APIRouter):
    def __init__(
        self,
        server,
    ):
        #server type-checking
        from . import SessionedServer
        self.server: SessionedServer = server
        if not isinstance(server, SessionedServer): raise TypeError("Passed server is not an instance of Sessioned Server")

        # config setup
        self.default_passkey = "!@#$%PASSWORDNOTSET!@#$%"
        self.cwd = CWD({"passkey.toml": f'hashed_pass = "{self.default_passkey}"'})
        self.cfg_file = self.cwd.passkey  # type: ignore
        self.cfg = PasskeyConfig.create(self.cfg_file)
        self.callback_url = self.server.url + "/passkey" + "/callback"

        # ensure hashed password is set
        _ = self.hashed_password

        # initialize api router
        super().__init__(prefix="/passkey")

        @self.post("/callback")
        async def callback(request: Request):
            log.warning(f"{self}: Someone attempted to input a passkey!")
            #check if the session exists first to prevent automatic creation of a new one
            session = request.cookies.get(self.server.session_name)
            if not session:
                return JSONResponse({"success": True, "message": "There was an issue retrieving your session. "
                                                                  "If the error persists, Please contact a "
                                                                  "system administrator."})
            session = self.server.session_manager(request)
            data = await request.json()
            input_password = data["passkey"]

            # Pass it to your validate method
            try:
                if await self.validate(session, input_password):
                    setattr(session, "authenticated", True)
                    return JSONResponse({"success": True, "message": "Successfully authenticated!"})
                else:
                    return JSONResponse({"success": False, "message": "Invalid passkey"})
            except Exception as e:
                return JSONResponse({"success": False, "message": f"There was an unexpected issue!: {e}. "
                                                                  f"Please alert your system administrator."})

    def __repr__(self):
        return "[TooManySessions.Passkey]"

    @cached_property
    def hashed_password(self):
        self.cfg.read()
        if self.cfg.hashed_pass == "!@#$%PASSWORDNOTSET!@#$%":
            log.warning(f"{self}: You must set a secure password for your passkey authentication method!")
            hash = prompt_and_hash_password()
            setattr(self.cfg, "hashed_pass", hash)
            self.cfg.write()
            if self.cfg.hashed_pass != hash:  # Fixed comparison
                raise ValueError("Failed to save hashed password")
        return self.cfg.hashed_pass

    def _validate(self, input_password):
        """Validate input password against stored hash"""
        log.debug(f"{self}: Validating password")
        stored_hash = self.cfg.hashed_pass.encode('utf-8')  # Convert string to bytes
        is_valid = bcrypt.checkpw(input_password.encode('utf-8'), stored_hash)
        log.debug(f"{self}: Password validation result: {is_valid}")
        return is_valid

    async def validate(self, session: Session, input_password):
        throttle = session.throttle
        await asyncio.sleep(throttle)
        return self._validate(input_password)

    async def show_passkey_prompt(self, request: Request):
        template = CWD_TEMPLATER.get_template('prompt_for_passkey.html')
        forward = self.server.url + request.url.path
        log.debug(f"{self}: Showing passkey prompt for request:\n  - cookies={request.cookies}\n  - redirect_url={forward}\n  - callback_url={self.callback_url}")
        rendered = template.render(
            redirect_url=forward,
            callback_uri=self.callback_url,
        )
        response = HTMLResponse(rendered)
        name = self.server.session_name
        cookie = request.cookies.get(name)
        response.set_cookie(self.server.session_name, cookie)
        log.debug(f"{self}: Response has been prepared with cookie '{name}: {cookie}'")
        return response