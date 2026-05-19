import logging
import os
from .base import BaseExporter

logger = logging.getLogger("BGP-Monitor.Exporters")

class SendGridExporter(BaseExporter):
    """
    Exporter for SendGrid Email API.
    Requires 'sendgrid' package.
    """
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.get("enabled", False)
        self.api_key = config.get("api_key")
        self.from_email = config.get("from_email")
        self.to_email = config.get("to_email")
        self.sg_client = None

        if self.enabled:
            if not self.api_key or "YOUR_SENDGRID_API_KEY" in self.api_key:
                logger.warning("SendGrid Exporter: API Key is missing or placeholder. Disabling.")
                self.enabled = False
                return

            try:
                from sendgrid import SendGridAPIClient
                self.sg_client = SendGridAPIClient(self.api_key)
                logger.info(f"SendGrid Exporter initialized. Alerts will be sent to {self.to_email}")
            except ImportError:
                logger.error("SendGrid Exporter: 'sendgrid' package not found. Disabling.")
                self.enabled = False
            except Exception as e:
                logger.error(f"SendGrid Exporter: Failed to initialize: {e}")
                self.enabled = False

    def export_event(self, event_data):
        if not self.enabled or not self.sg_client:
            return

        subject = f"🚨 BGP ALERT: {event_data['alert_type']} for {event_data['announced_prefix']}"
        
        content = (
            f"<h3>BGP Security Alert</h3>"
            f"<ul>"
            f"<li><b>Type:</b> {event_data['alert_type']}</li>"
            f"<li><b>Asset:</b> {event_data['description']}</li>"
            f"<li><b>Event:</b> {event_data['announced_prefix']} by AS{event_data['origin_asn']}</li>"
            f"<li><b>Expected:</b> {event_data['expected_prefix']} via AS{event_data['expected_asn']}</li>"
            f"<li><b>RPKI Status:</b> {event_data['rpki_status']}</li>"
            f"<li><b>Peer:</b> {event_data.get('peer', 'unknown')}</li>"
            f"<li><b>Occurrences:</b> {event_data['total_occurrences']} (within 24h)</li>"
            f"</ul>"
            f"<p><small>Sent via RPKI-Guardian Monitor</small></p>"
        )
        
        self._send_email(subject, content)

    def export_health_check(self, health_data):
        if not self.enabled or not self.sg_client:
            return

        subject = f"📊 RPKI Health Audit: {health_data['invalid']} Invalids Found"
        
        content = (
            f"<h3>RPKI Health Audit Summary</h3>"
            f"<p>Checked {health_data['total_assets']} monitored assets:</p>"
            f"<ul>"
            f"<li><b>Valid:</b> {health_data['valid']}</li>"
            f"<li><b>Invalid:</b> {health_data['invalid']}</li>"
            f"<li><b>No ROA:</b> {health_data['not_found']}</li>"
            f"</ul>"
        )
        
        if health_data['invalid'] > 0:
            content += "<h4>Critical Invalids:</h4><ul>"
            for detail in health_data['invalid_details'][:20]:
                content += f"<li>{detail}</li>"
            content += "</ul>"
            
        content += f"<p><small>Sent via RPKI-Guardian Monitor</small></p>"
        
        self._send_email(subject, content)

    def _send_email(self, subject, html_content):
        from sendgrid.helpers.mail import Mail
        
        message = Mail(
            from_email=self.from_email,
            to_emails=self.to_email,
            subject=subject,
            html_content=html_content
        )
        
        try:
            response = self.sg_client.send(message)
            if response.status_code >= 400:
                logger.error(f"SendGrid send failed with status {response.status_code}")
        except Exception as e:
            logger.error(f"SendGrid Export Failed: {e}")
