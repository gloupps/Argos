import asyncio
import re
from datetime import datetime, timedelta, UTC
from collections import defaultdict


class Services:

    def __init__(
        self,
        database,
        requester,
        job_manager,
        socketio,
    ):
        """Initialize service with integration clients and job manager."""

        self.database = database
        self.requester = requester
        self.job_manager = job_manager
        self.socketio = socketio

    # ------------------------------------------------
    # GENERIC JOB LAUNCHER
    # ------------------------------------------------
    def start_job(self, data):

        action = data.get("action")

        job_id = self.job_manager.create_job()
        print(f"DEBUG: new job - {action}")

        # 🔥 SocketIO gère le thread
        self.socketio.start_background_task(self._run_async_job, job_id, data)

        return job_id

    def _run_async_job(self, job_id, data):
        # Run the async workflow inside a background thread/task for SocketIO.
        try:
            asyncio.run(self._run_job(job_id, data))
            self.job_manager.complete_job(job_id)

        except Exception as e:
            self.job_manager.fail_job(job_id, str(e))

    # ------------------------------------------------
    # MAIN ASYNC ROUTER
    # ------------------------------------------------

    async def _run_job(self, job_id, data):
        """Dispatch the requested action and log progress for the job.

        The router receives an action name and forwards it to the matching
        worker method. Each worker is responsible for its own progress logs.
        """

        action = data.get("action")

        self.job_manager.add_log(job_id, f"Running action: {action}")

        try:

            if action == "indicators":
                await self._create_indicators(
                    job_id, data.get("report_url") or data.get("url")
                )

            elif action == "detection":
                await self._enable_detection(
                    job_id, data.get("report_url") or data.get("url")
                )

            elif action == "disable_detection":
                await self._disable_detection(
                    job_id, data.get("report_url") or data.get("url")
                )

            elif action == "relations":
                await self._create_relations(
                    job_id, data.get("report_url") or data.get("url")
                )

            elif action == "create_report_from_ioc":
                await self._create_report_from_ioc(job_id, data)

            elif action == "siem":
                await self._run_siem(job_id, data)

            elif action == "siem_create_report":
                await self._siem_create_report(job_id, data)

            elif action in ["siem_create_note", "qualify_create_note"]:
                await self._siem_create_note(job_id, data)

            elif action in ["siem_add_detection", "qualify_add_detection"]:
                await self._siem_add_detection(job_id, data)

            elif action in ["siem_create_sightings", "qualify_create_sightings"]:
                await self._siem_create_sightings(job_id, data)

            elif action in ["qualify_add_ioc_to_report", "siem_add_ioc_to_report"]:
                await self._add_ioc_to_report(job_id, data)

            elif action == "qualify":
                await self._run_qualification(job_id, data)

            elif action == "qualify_create_report":
                await self._qualify_create_report(job_id, data)

            elif action == "qualify_enrich_report":
                await self._qualify_enrich_report(job_id, data)

            elif action == "enrich":
                await self._run_enrichment(job_id, data)

            elif action == "vt_stream":
                await self._run_vt_stream(job_id, data)

            elif action == "offense":
                await self._offense(job_id, data)

            elif action == "import_stix":
                await self._import_stix(job_id, data)

            elif action == "analyze_stix":
                await self._analyze_stix(job_id, data)

            elif action == "report_offense":
                await self._report_offense(job_id, data)

            elif action == "check_quotas":
                await self._check_quotas(job_id)

            else:
                msg = f"❌ Unknown action: {action}"
                self.job_manager.add_log(job_id, msg)
                return

        except Exception as e:
            self.job_manager.add_log(job_id, f"❌ Error: {str(e)}")
            raise
