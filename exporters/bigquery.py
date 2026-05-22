import json
import os
import logging
from datetime import datetime, timezone
from .base import BaseExporter

logger = logging.getLogger("BGP-Monitor.Exporters")

class BigQueryExporter(BaseExporter):
    """
    Exporter for Google Cloud BigQuery.
    Requires google-cloud-bigquery package.
    """
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.get("enabled", False)
        self.project_id = config.get("project_id")
        self.dataset_id = config.get("dataset_id")
        self.table_id = config.get("table_id")
        self.client = None

        if self.enabled:
            try:
                from google.cloud import bigquery
                
                # Check for explicit credentials file in config
                creds_path = config.get("credentials_file")
                if creds_path and os.path.exists(creds_path):
                    self.client = bigquery.Client.from_service_account_json(creds_path, project=self.project_id)
                else:
                    # Fallback to default environment-based authentication
                    self.client = bigquery.Client(project=self.project_id)
                
                logger.info(f"BigQuery Exporter initialized for {self.project_id}.{self.dataset_id}.{self.table_id}")
            except ImportError:
                logger.error("BigQuery Exporter: 'google-cloud-bigquery' package not found. Disabling.")
                self.enabled = False
            except Exception as e:
                logger.error(f"BigQuery Exporter: Failed to initialize: {e}")
                self.enabled = False

    def export_event(self, event_data):
        if not self.enabled or not self.client:
            return

        # Flatten the data for BigQuery
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": event_data['alert_type'],
            "prefix": event_data['announced_prefix'],
            "origin_asn": int(event_data['origin_asn']),
            "expected_prefix": event_data['expected_prefix'],
            "expected_asn": int(event_data['expected_asn']),
            "description": event_data['description'],
            "rpki_status": event_data['rpki_status'],
            "peer": event_data.get('peer', 'unknown')
        }

        try:
            table_ref = f"{self.project_id}.{self.dataset_id}.{self.table_id}"
            errors = self.client.insert_rows_json(table_ref, [row])
            if errors:
                logger.error(f"BigQuery Insert Errors: {errors}")
        except Exception as e:
            logger.error(f"BigQuery Export Failed: {e}")

    def export_health_check(self, health_data):
        if not self.enabled or not self.client:
            return

        if health_data.get("is_startup_test"):
            # Skip startup test notifications in BigQuery history
            return

        # We'll use a slightly different table or suffix for health checks
        # if the user hasn't specified one, we'll default to 'rpki_health_history'
        health_table_id = self.config.get("health_table_id", "rpki_health_history")
        
        # Create a record for each asset in the audit
        # This allows for granular reporting on which specific IPs are missing ROAs
        rows = []
        timestamp = datetime.now(timezone.utc).isoformat()

        # We'll need to pass more granular data if we want to log every single asset,
        # but for now, let's at least log the summary and the specific invalids/missing.
        # Let's adjust the health_data structure in main.py to support this better.
        
        summary_row = {
            "timestamp": timestamp,
            "total_assets": health_data['total_assets'],
            "valid_count": health_data['valid'],
            "invalid_count": health_data['invalid'],
            "not_found_count": health_data['not_found']
        }

        try:
            table_ref = f"{self.project_id}.{self.dataset_id}.{health_table_id}"
            errors = self.client.insert_rows_json(table_ref, [summary_row])
            if errors:
                logger.error(f"BigQuery Health Summary Insert Errors: {errors}")
        except Exception as e:
            logger.error(f"BigQuery Health Export Failed: {e}")
