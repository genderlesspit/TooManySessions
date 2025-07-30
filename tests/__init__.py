import time
from toomanysessions.src.toomanysessions import SessionedServer

s = SessionedServer(port=8000, user_whitelist=None)
s.thread.start()
time.sleep(100)