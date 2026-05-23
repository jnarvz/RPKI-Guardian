import json
import urllib.request
import logging
from .base import BaseExporter

logger = logging.getLogger("BGP-Monitor.Exporters")

class ChatExporter(BaseExporter):
    """Exporter for Chat (Slack, Discord, Mattermost, etc.) webhook integrations."""
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

        if health_data.get("is_startup_test"):
            msg = (
                f"🚀 *RPKI-Guardian Monitor Initialized / Restarted*\n"
                f"Monitoring {health_data['total_assets']} parent IP block assets in real-time.\n"
                f"Currently ingesting/processing {health_data.get('total_rpki_vrps', 0):,} RPKI ROAs (VRPs) from Routinator."
            )
            self._send(msg)
            return

        report = (
            f"📊 *RPKI Health Audit Summary*\n"
            f"Checked {health_data['total_assets']} monitored assets:\n"
            f"✅ *Repository Active ROAs:* {health_data['valid']}\n"
            f"❌ *Invalid ROAs:* {health_data['invalid']}\n"
            f"⚠️ *No ROA Found:* {health_data['not_found']}"
        )
        
        if health_data.get("include_live_stats"):
            report += f"\n🟢 *Live Valid ROAs:* {health_data['live_valid']} (out of {health_data['active_announcements']} active announcements)"
        
        if health_data.get("is_initial_report"):
            report += "\n\n_*Note: This is the initial health summary since the monitor started/restarted._*"
        
        if health_data['invalid'] > 0:
            report += "\n\n*Critical Invalids:*\n" + "\n".join(health_data['invalid_details'][:10])
            if health_data['invalid'] > 10:
                report += f"\n...and {health_data['invalid'] - 10} more."

        if health_data['not_found'] > 0:
            report += "\n\n*No ROAs Found for Prefixes:*\n" + "\n".join(f"• {p}" for p in health_data['not_found_prefixes'][:10])
            if health_data['not_found'] > 10:
                report += f"\n...and {health_data['not_found'] - 10} more."
        
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
            logger.error(f"ChatExporter failed to send: {e}")
