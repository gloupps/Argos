import logging
from app import PivotLenApp

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Init the instance
app_instance = PivotLenApp()

# Get Flask serveur app (frontend->backend)
app = app_instance.app
# Get Socket IO app (backend->frontend)
socketio = app_instance.socketio

if __name__ == "__main__":
    # Run the webserver and choose IP:PORT
    socketio.run(app, host="127.0.0.1", port=5555, debug=True)
