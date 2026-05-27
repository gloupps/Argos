import uuid


class JobManager:

    def __init__(self, socketio):
        self.jobs     = {}
        self.socketio = socketio

    def create_job(self):
        job_id = str(uuid.uuid4())
        self.jobs[job_id] = {"status": "running", "logs": []}
        return job_id

    def add_log(self, job_id, message, status="running"):
        print(f"[JOB {job_id[:8]}] {message}")
        self.socketio.emit("job_update", {
            "job_id": job_id, "message": message, "status": status
        })

    def complete_job(self, job_id):
        if job_id in self.jobs:
            self.jobs[job_id]["status"] = "completed"
        self.socketio.emit("job_update", {
            "job_id": job_id, "message": "Job finished", "status": "done"
        })

    def fail_job(self, job_id, error):
        if job_id in self.jobs:
            self.jobs[job_id]["status"] = "error"
            self.jobs[job_id]["logs"].append(str(error))
        self.socketio.emit("job_update", {
            "job_id": job_id, "message": str(error), "status": "failed"
        })

    def get_job(self, job_id):
        return self.jobs.get(job_id)
