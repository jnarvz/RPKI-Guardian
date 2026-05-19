import json
import urllib.request
import logging
from .base import BaseExporter

logger = logging.getLogger("BGP-Monitor.Exporters")

class SlackExporter(BaseExporter):
    """Exporter for Slack/Discord-style webhooks."""
    def __init__(self, config):
        super().__init__(config)
        self.webhook_url = config.get("chat_webhook")

    def export_event(self, event_data):
        if not self.webhook_url or "YOUR_CHAT_WEBHOOK" in self.webhook_url:
            return

        chat_msg = (
            f"🚨 *BGP SECURITY ALERT*\n"
            f"*Type:* {event_data['alert_type']}\n"
            f"*Asset:* {event_data['description']}\n"
            f"*Event:* {event_data['announced_prefix']} by AS{event_data['origin_asn']}\n"
            f"*Expected:* {event_data['expected_prefix']} via AS{event_data['expected_asn']}\n"
            f"*RPKI:* {event_data['rpki_status']}\n"
            f"*Stats:* Seen {event_data['total_occurrences']} times (Cooldowned for 24hrs)"
        )
        self._send(chat_msg)

    def export_health_check(self, health_data):
        if not self.webhook_url or "YOUR_CHAT_WEBHOOK" in self.webhook_url:
            return

        report = (
            f"📊 *RPKI Health Audit Summary*\n"
            f"Checked {health_data['total_assets']} monitored assets:\n"
            f"✅ *Valid ROAs:* {health_data['valid']}\n"
            f"❌ *Invalid ROAs:* {health_data['invalid']}\n"
            f"⚠️ *No ROA Found:* {health_data['not_found']}"
        )
        
        if health_data['invalid'] > 0:
            report += "\n\n*Critical Invalids:*\n" + "\n".join(health_data['invalid_details'][:10])
            if health_data['invalid'] > 10:
                report += f"\n...and {health_data['invalid'] - 10} more."
        
        self._send(report)

    def _send(self, text):
        payload = {"text": text}
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json; charset=UTF-8",
                    "User-Agent": "RPKI-Guardian-Monitor/1.0"
                }
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                pass
        except Exception as e:
            logger.error(f"SlackExporter failed to send: {e}")
