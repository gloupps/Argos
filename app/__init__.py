from flask import Flask
from flask_socketio import SocketIO

from .services.routes import register_routes
from .services.services import Services
from .services.job_manager import JobManager
from .services.requester import Requester
from .services.database import Database


class PivotLenApp:

    def __init__(self):
        self.app      = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.app.socketio = self.socketio

        self.job_manager = JobManager(self.socketio)
        self.database    = Database()
        self.requester   = Requester()

        self.services = Services(
            self.database,
            self.requester,
            self.job_manager,
            self.socketio,
        )

        self._configure_routes()

    def _configure_routes(self):
        register_routes(self.app, self.services, self.job_manager)
