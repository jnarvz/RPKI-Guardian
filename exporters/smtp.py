import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from .base import BaseExporter

logger = logging.getLogger("BGP-Monitor.Exporters")

class SMTPExporter(BaseExporter):
    """
    Exporter for SMTP Mail Server.
    Uses Python's built-in smtplib.
    """
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.get("enabled", False)
        self.server = config.get("server")
        self.port = config.get("port", 587)
        self.user = config.get("username")
        self.password = config.get("password")
        self.encryption = config.get("encryption", "starttls")  # 'starttls', 'ssl', or 'none'
        self.from_email = config.get("from_email")
        self.to_email = config.get("to_email")

        if self.enabled:
            if not self.server or not self.from_email or not self.to_email:
                logger.warning("SMTP Exporter: Missing server, from_email, or to_email. Disabling.")
                self.enabled = False

    def export_event(self, event_data):
        if not self.enabled:
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
        if not self.enabled:
            return

        if health_data.get("is_startup_test"):
            subject = f"🚀 RPKI-Guardian Initialized / Restarted"
            content = (
                f"<h3>RPKI-Guardian Started</h3>"
                f"<p>The BGP route security monitor has successfully started/restarted.</p>"
                f"<p><b>Monitoring:</b> {health_data['total_assets']} parent IP block assets in real-time.</p>"
                f"<p><b>Currently ingesting/processing:</b> {health_data.get('total_rpki_vrps', 0):,} RPKI ROAs (VRPs) from Routinator.</p>"
                f"<p><small>Sent via RPKI-Guardian Monitor</small></p>"
            )
            self._send_email(subject, content)
            return

        subject = f"📊 RPKI Health Audit: {health_data['invalid']} Invalids Found"
        if health_data.get("is_initial_report"):
            subject = f"📊 RPKI Health Audit (Initial Report): {health_data['invalid']} Invalids Found"
        
        content = (
            f"<h3>RPKI Health Audit Summary</h3>"
            f"<p>Checked {health_data['total_assets']} monitored assets:</p>"
            f"<ul>"
            f"<li><b>Repository Active ROAs:</b> {health_data['valid']}</li>"
            f"<li><b>Invalid ROAs:</b> {health_data['invalid']}</li>"
            f"<li><b>No ROA Found:</b> {health_data['not_found']}</li>"
        )
        
        if not health_data.get("is_initial_report"):
            content += f"<li><b>Live Valid ROAs:</b> {health_data['live_valid']} (out of {health_data['active_announcements']} active announcements)</li>"
            
        content += "</ul>"
        
        if health_data.get("is_initial_report"):
            content += f"<p><i>Note: This is the initial health summary since the monitor started/restarted.</i></p>"
        
        if health_data['invalid'] > 0:
            content += "<h4>Critical Invalids:</h4><ul>"
            for detail in health_data['invalid_details'][:20]:
                content += f"<li>{detail}</li>"
            content += "</ul>"

        if health_data['not_found'] > 0:
            content += "<h4>No ROAs Found for Prefixes:</h4><ul>"
            for p in health_data['not_found_prefixes'][:20]:
                content += f"<li>{p}</li>"
            content += "</ul>"
            
        content += f"<p><small>Sent via RPKI-Guardian Monitor</small></p>"
        
        self._send_email(subject, content)

    def _send_email(self, subject, html_content):
        # Create message container
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.from_email
        msg['To'] = self.to_email

        # HTML content
        part_html = MIMEText(html_content, 'html')
        msg.attach(part_html)

        try:
            # Connect to SMTP server
            if self.encryption == "ssl":
                smtp = smtplib.SMTP_SSL(self.server, self.port, timeout=10)
            else:
                smtp = smtplib.SMTP(self.server, self.port, timeout=10)

            # Ehlo and StartTLS if configured
            smtp.ehlo()
            if self.encryption == "starttls":
                smtp.starttls()
                smtp.ehlo()

            # Login if user credentials are provided
            if self.user and self.password:
                smtp.login(self.user, self.password)

            # Send the email
            smtp.sendmail(self.from_email, self.to_email, msg.as_string())
            smtp.quit()
            logger.debug(f"SMTP Exporter: Successfully sent email alert to {self.to_email}")
        except Exception as e:
            logger.error(f"SMTP Export Failed: {e}")
