import time
from toomanysessions.src.toomanysessions import SessionedServer

SessionedServer().thread.start()
time.sleep(100)