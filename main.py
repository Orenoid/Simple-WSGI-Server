import signal
import sys
from server import WebServer

### MAIN ###
def shutdownServer(sig, unused):
    """
    Shutsdown server from a SIGINT recieved signal
    """
    server.shutdown()
    sys.exit(1)

signal.signal(signal.SIGINT, shutdownServer)
server = WebServer()
server.start()
print("Press Ctrl+C to shut down server.")