import logging
from app import PivotLenApp

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

app_instance = PivotLenApp()
app          = app_instance.app
socketio     = app_instance.socketio

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5555, debug=True)
