# Import webserver
from flask import Flask  # Frontend->Backend
from flask_socketio import SocketIO  # Backend->Frontend

# Import local Class
from .services.routes import register_routes  # webserver endpoints
from .services.services import Services  # Services
from .services.job_manager import JobManager  # Manage services tasks
from .services.requester import Requester  # Handle API requests
from .services.database import Database  # Handle DB connection


class PivotLenApp:

    def __init__(self):
        """
        Init the app
        """
        self.app = Flask(__name__)  # Init web server
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")  # Init socket IO
        self.app.socketio = self.socketio

        self.job_manager = JobManager(self.socketio)  # Init Job Manager

        self.database = Database()  # Init DB
        self.requester = Requester()  # Init requester

        # Init services
        self.services = Services(
            self.database, self.requester, self.job_manager, self.socketio
        )

        self.configure_routes()  # Load webserver endpoints

    def configure_routes(self):
        """
        Configure endpoints to run Job for each tasks service
        """
        register_routes(self.app, self.services, self.job_manager)
