import asyncio
import json
import logging
import os
import radix
import websockets
import urllib.request
from datetime import datetime, timezone

# Import Exporters
from exporters.slack import SlackExporter
from exporters.bigquery import BigQueryExporter
from exporters.sendgrid import SendGridExporter

# -------------------------------------------------------------------------
# Logging Configuration
# -------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("BGP-Monitor")

# -------------------------------------------------------------------------
# Core Engine Class
# -------------------------------------------------------------------------
class BGPMonitorEngine:
    def __init__(self, config_path="config.json"):
        self.config = self.load_config(config_path)
        self.rtree = radix.Radix()
        self.rpki_cache = {}

        # Alert tracking for noise reduction
        self.alert_history = {}
        self.alert_cooldown = 86400  # 24 hour cooldown

        # Health reporting state
        self.last_health_report_time = 0
        self.last_health_report_data = {}
        self.health_report_interval = 14400  # 4 hours

        # Initialize Exporters
        self.exporters = []
        self._init_exporters()

        self.build_radix_tree()
        self.load_rpki_cache()

        # Test Connectivity on Startup
        self.broadcast_health_check({
            "total_assets": len(self.config.get("monitored_assets", [])),
            "valid": "N/A",
            "invalid": 0,
            "not_found": "N/A",
            "invalid_details": [],
            "is_startup_test": True
        })

    def _init_exporters(self):
        """Initializes all enabled exporters from config."""
        alert_cfg = self.config.get("alerting", {})
        
        # Slack/Chat Exporter
        if alert_cfg.get("chat_webhook"):
            self.exporters.append(SlackExporter(alert_cfg))
        
        # BigQuery Exporter
        bq_cfg = self.config.get("bigquery")
        if bq_cfg and bq_cfg.get("enabled"):
            self.exporters.append(BigQueryExporter(bq_cfg))
        
        logger.info(f"Initialized {len(self.exporters)} exporters.")

    def load_config(self, path):
        if not os.path.exists(path):
            logger.error(f"Configuration file not found at {path}. Exiting.")
            exit(1)
        with open(path, "r") as f:
            return json.load(f)

    def build_radix_tree(self):
        """Seeds the C-optimized Radix tree with user-defined monitored assets."""
        assets = self.config.get("monitored_assets", [])
        for asset in assets:
            rnode = self.rtree.add(asset["prefix"])
            rnode.data["expected_asn"] = asset["expected_asn"]
            rnode.data["description"] = asset["description"]
            rnode.data["prefix"] = asset["prefix"]
        logger.info(f"Loaded {len(assets)} prefixes into the Radix Tree.")

    def broadcast_event(self, event_data):
        """Sends a security event to all active exporters."""
        for exporter in self.exporters:
            try:
                exporter.export_event(event_data)
            except Exception as e:
                logger.error(f"Exporter {exporter.__class__.__name__} failed: {e}")

    def broadcast_health_check(self, health_data):
        """Sends a health audit report to all active exporters."""
        for exporter in self.exporters:
            try:
                exporter.export_health_check(health_data)
            except Exception as e:
                logger.error(f"Exporter {exporter.__class__.__name__} failed: {e}")

    def check_rpki_health(self):
        """Analyzes all monitored assets and checks their RPKI status."""
        import time
        now = time.time()
        
        assets = self.config.get("monitored_assets", [])
        valid = 0
        invalid = 0
        not_found = 0
        invalid_details = []
        not_found_prefixes = []

        for asset in assets:
            if asset.get("skip_rpki_audit"):
                continue

            prefix = asset["prefix"]
            expected_asn = asset["expected_asn"]
            status = self.check_rpki(prefix, expected_asn)
            
            if status == "VALID":
                valid += 1
            elif "INVALID" in status:
                invalid += 1
                invalid_details.append(f"• {prefix}: {status}")
            else:
                not_found += 1
                not_found_prefixes.append(prefix)
        
        logger.info(f"RPKI Health Audit: {valid} Valid, {invalid} Invalid, {not_found} Not Found.")
        
        # Prepare the health data payload
        current_health_data = {
            "total_assets": len(assets),
            "valid": valid,
            "invalid": invalid,
            "not_found": not_found,
            "invalid_details": sorted(invalid_details),
            "not_found_prefixes": sorted(not_found_prefixes)
        }

        # Deduplication Logic:
        # 1. Send if it's the first time and we have data.
        # 2. Send if the 24-hour interval has passed.
        # 3. Send if the content (invalids or missing ROAs) has changed since last report.
        
        time_since_last = now - self.last_health_report_time
        has_changed = current_health_data != self.last_health_report_data
        
        should_broadcast = (self.last_health_report_time == 0 and self.rpki_cache) or \
                           (time_since_last > self.health_report_interval) or \
                           has_changed

        if should_broadcast:
            self.last_health_report_time = now
            self.last_health_report_data = current_health_data
            self.broadcast_health_check(current_health_data)
        else:
            logger.info("RPKI Health Summary unchanged and within cooldown. Skipping notification.")

    def load_rpki_cache(self):
        """Loads an RPKI JSON cache from Routinator and builds a lookup table."""
        rpki_path = self.config.get("rpki_cache_path")
        if os.path.exists(rpki_path):
            try:
                with open(rpki_path, "r") as f:
                    data = json.load(f)
                    roas = data.get("roas", [])
                    
                    # Use a Radix tree for RPKI lookups to support ROV (Route Origin Validation)
                    new_tree = radix.Radix()
                    
                    for roa in roas:
                        prefix = roa.get("prefix")
                        max_len = roa.get("maxLength", int(prefix.split("/")[1]))
                        asn_str = str(roa.get("asn", "")).upper().replace("AS", "")
                        
                        if not asn_str.isdigit():
                            continue
                            
                        asn = int(asn_str)
                        
                        rnode = new_tree.add(prefix)
                        if "vrps" not in rnode.data:
                            rnode.data["vrps"] = []
                        
                        rnode.data["vrps"].append({
                            "asn": asn,
                            "maxLength": max_len
                        })
                    
                    self.rpki_cache = new_tree
                logger.info(f"Local RPKI cache loaded: {len(self.rpki_cache.prefixes())} VRPs found.")
                
                # Perform a health check every time the cache is loaded
                self.check_rpki_health()
                
            except Exception as e:
                logger.error(f"Failed to parse RPKI cache: {e}")
        else:
            logger.warning(f"RPKI cache not found at {rpki_path}. Falling back to 'UNKNOWN' RPKI status.")

    def check_rpki(self, prefix, origin_asn):
        """
        Validates the route against the local RPKI cache using standard ROV logic.
        - VALID: At least one VRP matches prefix, ASN, and length <= maxLength.
        - INVALID: VRPs exist for prefix, but none match ASN/length.
        - NOT FOUND: No VRPs cover this prefix.
        """
        if not self.rpki_cache:
            return "UNKNOWN (No Local Cache)"
        
        # Find all VRPs that cover this announcement (could be exact or parent)
        # Note: In a real ROV implementation, we check all covering VRPs.
        covering_nodes = self.rpki_cache.search_covering(prefix)
        
        if not covering_nodes:
            return "NOT FOUND (No ROA for this prefix)"

        # Standard RPKI ROV logic
        prefix_len = int(prefix.split("/")[1])
        origin_asn = int(origin_asn)
        
        has_covering_roa = False
        for node in covering_nodes:
            for vrp in node.data.get("vrps", []):
                has_covering_roa = True
                # Check if this VRP makes the route VALID
                if vrp["asn"] == origin_asn and prefix_len <= vrp["maxLength"]:
                    return "VALID"

        # If we found ROAs but none matched the criteria, it's INVALID
        if has_covering_roa:
            return f"INVALID (Origin AS {origin_asn} or length {prefix_len} does not match ROA)"
        
        return "NOT FOUND (No ROA for this prefix)"

    def trigger_alert(self, alert_type, announced_prefix, origin_asn, peer, rnode):
        """Formats and outputs the security alert with noise reduction."""
        import time
        
        # Unique key for this specific event
        alert_key = (announced_prefix, origin_asn, alert_type)
        now = time.time()
        
        # Initialize or update history
        if alert_key not in self.alert_history:
            self.alert_history[alert_key] = {"count": 0, "last_alerted": 0}
        
        self.alert_history[alert_key]["count"] += 1
        total_occurrences = self.alert_history[alert_key]["count"]
        time_since_last = now - self.alert_history[alert_key]["last_alerted"]
        
        # Check if we should broadcast (first time OR after cooldown)
        should_broadcast = (time_since_last > self.alert_cooldown)

        # Always log to console for debugging
        logger.warning(f"BGP ALERT [{total_occurrences}]: {alert_type} - {announced_prefix} via AS{origin_asn}")

        if should_broadcast:
            self.alert_history[alert_key]["last_alerted"] = now
            
            event_data = {
                "alert_type": alert_type,
                "description": rnode.data["description"],
                "announced_prefix": announced_prefix,
                "origin_asn": origin_asn,
                "expected_prefix": rnode.data["prefix"],
                "expected_asn": rnode.data["expected_asn"],
                "rpki_status": self.check_rpki(announced_prefix, origin_asn),
                "total_occurrences": total_occurrences,
                "peer": peer
            }
            self.broadcast_event(event_data)

    def process_bgp_message(self, message):
        """Parses RIPE RIS Live JSON messages and cross-references via Longest Prefix Match."""
        try:
            msg_data = json.loads(message)
            if msg_data.get("type") != "ris_message":
                return

            data = msg_data.get("data", {})
            peer = data.get("peer", "Unknown")
            announcements = data.get("announcements", [])
            path = data.get("path", [])
            
            if not announcements or not path:
                return

            origin_asn = path[-1]  # The last ASN in the path is the origin

            for announcement in announcements:
                prefixes = announcement.get("prefixes", [])
                for prefix in prefixes:
                    # O(k) Longest Prefix Match via py-radix
                    match = self.rtree.search_best(prefix)
                    
                    if match:
                        is_exact_match = (prefix == match.data["prefix"])
                        is_expected_asn = (origin_asn == match.data["expected_asn"])
                        rpki_status = self.check_rpki(prefix, origin_asn)

                        if not is_expected_asn:
                            # 1. Hijack case: Wrong ASN
                            alert_type = "SUB-PREFIX HIJACK" if not is_exact_match else "EXACT-PREFIX ORIGIN HIJACK"
                            self.trigger_alert(alert_type, prefix, origin_asn, peer, match)
                        elif "INVALID" in rpki_status:
                            # 2. Self-Misconfig case: Correct ASN but RPKI Invalid (e.g., missing ROA for sub-prefix)
                            self.trigger_alert("RPKI INVALID (Self-Announcement)", prefix, origin_asn, peer, match)
                        elif not is_exact_match:
                            # 3. Valid Sub-prefix: Correct ASN and RPKI Valid
                            # Log to console for TE visibility, but don't blast Slack/BigQuery unless it's a security event
                            logger.info(f"Legitimate Traffic Engineering: {prefix} via AS{origin_asn} (Matches parent {match.data['prefix']})")

        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    async def reload_rpki_periodically(self):
        """Task to periodically reload the RPKI cache from disk."""
        while True:
            await asyncio.sleep(900)  # Reload every 15 minutes
            logger.info("Reloading RPKI cache from disk...")
            self.load_rpki_cache()

    async def stream_ris_live(self):
        """Establishes an asynchronous WebSocket connection to RIPE RIS Live."""
        url = "wss://ris-live.ripe.net/v1/ws/"
        
        # Start the RPKI reload task in the background
        asyncio.create_task(self.reload_rpki_periodically())
        
        while True:
            try:
                logger.info(f"Connecting to RIPE RIS Live at {url}...")
                async with websockets.connect(url) as websocket:
                    logger.info("Connected. Subscribing to global BGP stream...")
                    
                    subscribe_msg = {
                        "type": "ris_subscribe",
                        "data": {
                            "moreSpecific": True
                        }
                    }
                    await websocket.send(json.dumps(subscribe_msg))

                    async for message in websocket:
                        self.process_bgp_message(message)
                        
            except websockets.exceptions.ConnectionClosed:
                logger.warning("WebSocket connection closed. Reconnecting in 5 seconds...")
                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"WebSocket error: {e}. Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

# -------------------------------------------------------------------------
# Entry Point
# -------------------------------------------------------------------------
if __name__ == "__main__":
    # Ensure times are standard UTC
    logging.Formatter.converter = lambda *args: datetime.now(timezone.utc).timetuple()
    
    logger.info("Starting RPKI-Guardian: BGP Route Security Monitor...")
    engine = BGPMonitorEngine()
    
    # Run the asyncio event loop
    try:
        asyncio.run(engine.stream_ris_live())
    except KeyboardInterrupt:
        logger.info("Shutting down monitor gracefully.")
