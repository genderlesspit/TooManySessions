from pathlib import Path
from jinja2 import Environment, FileSystemLoader

DEBUG = True
CWD_TEMPLATER = Environment(loader=FileSystemLoader(Path(__file__).parent))

from .sessions import Session, Sessions, authenticate
from .users import User, Users
from .core import SessionedServer
from .msft_oauth import MicrosoftOAuth
