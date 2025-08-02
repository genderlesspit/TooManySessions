import time
from toomanysessions.src.toomanysessions import SessionedServer

#msft oauth testing
# s = SessionedServer(port=8000, tenant_whitelist=["e58f9482-1a00-4559-b3b7-42cd6038c43e"])
# s.thread.start()
# time.sleep(100)

#pass key testing
s = SessionedServer(port=8000, authentication_model="pass", user_model=None)
s.thread.start()
time.sleep(100)
