import time
from toomanysessions.src.toomanysessions import SessionedServer

SessionedServer(port=8000).thread.start()
time.sleep(100)