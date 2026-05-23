import asyncio
import json
import logging
import os
import radix
import websockets
import urllib.request
from datetime import datetime, timezone
import ipaddress
import time

# Import Exporters
from exporters.chat import ChatExporter
from exporters.bigquery import BigQueryExporter
from exporters.sendgrid import SendGridExporter
from exporters.smtp import SMTPExporter

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
        self.config_path = config_path
        self.config_last_modified = os.path.getmtime(config_path) if os.path.exists(config_path) else 0
        self.config = self.load_config(config_path)
        self.rtree = radix.Radix()
        self.rpki_cache = {}
        self.active_announcements = {}
        self.rpki_cache_loaded = False

        # Stats and State for Web UI / Metrics
        self.recent_alerts = []
        self.stats_total_announcements = 0
        self.stats_total_alerts = 0
        self.ws_connected = False
        self.rpki_valid_count = 0
        self.rpki_invalid_count = 0
        self.rpki_not_found_count = 0

        # Alert tracking for noise reduction
        self.alert_history = {}
        self.alert_cooldown = 86400  # 24 hour cooldown

        # Health reporting state
        self.last_health_report_time = 0
        self.last_health_report_data = {}
        self.health_report_interval = 86400  # 24 hours
        self.is_first_health_report = True

        # Warmup and startup tracking
        self.startup_time = time.time()
        self.warmup_period = 900  # 15 minutes warmup window
        self.total_rpki_vrps = 0

        # Initialize Exporters
        self.exporters = []
        self._init_exporters()

        self.build_radix_tree()
        self.load_rpki_cache()

        # Test Connectivity on Startup
        self.broadcast_health_check({
            "total_assets": len(self.config.get("monitored_assets", [])),
            "total_rpki_vrps": self.total_rpki_vrps,
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
            self.exporters.append(ChatExporter(alert_cfg))
        
        # BigQuery Exporter
        bq_cfg = self.config.get("bigquery")
        if bq_cfg and bq_cfg.get("enabled"):
            self.exporters.append(BigQueryExporter(bq_cfg))
        
        # SendGrid Exporter
        sg_cfg = self.config.get("sendgrid")
        if sg_cfg and sg_cfg.get("enabled"):
            exporter = SendGridExporter(sg_cfg)
            if exporter.enabled:
                self.exporters.append(exporter)

        # SMTP Exporter
        smtp_cfg = self.config.get("smtp")
        if smtp_cfg and smtp_cfg.get("enabled"):
            exporter = SMTPExporter(smtp_cfg)
            if exporter.enabled:
                self.exporters.append(exporter)

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
            rnode.data["skip_rpki_audit"] = asset.get("skip_rpki_audit", False)
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

    def recalculate_active_counts(self):
        """Recalculates the active RPKI metrics based on currently advertised child prefixes."""
        valid = 0
        invalid = 0
        not_found = 0
        for prefix, info in self.active_announcements.items():
            match = self.rtree.search_best(prefix)
            if match and match.data.get("skip_rpki_audit"):
                continue
            status = info["rpki_status"]
            if status == "VALID":
                valid += 1
            elif "INVALID" in status:
                invalid += 1
            else:
                not_found += 1
        self.rpki_valid_count = valid
        self.rpki_invalid_count = invalid
        self.rpki_not_found_count = not_found

    def schedule_health_check(self):
        """Schedules a health check to run after a short delay (debounce)."""
        try:
            loop = asyncio.get_running_loop()
            if not hasattr(self, "_health_check_task") or self._health_check_task is None or self._health_check_task.done():
                self._health_check_task = loop.create_task(self._delayed_health_check())
        except RuntimeError:
            pass

    async def _delayed_health_check(self):
        await asyncio.sleep(5)  # 5-second debounce window
        self.check_rpki_health()

    def check_rpki_health(self):
        """Analyzes monitored assets and checks their RPKI health status."""
        import time
        now = time.time()
        
        # 1. Refresh RPKI status for all active announcements using the latest cache
        for prefix in list(self.active_announcements.keys()):
            origin_asn = self.active_announcements[prefix]["origin_asn"]
            self.active_announcements[prefix]["rpki_status"] = self.check_rpki(prefix, origin_asn)

        # 2. Compute Repository RPKI counts (based on configured monitored assets)
        valid = 0
        invalid = 0
        not_found = 0
        invalid_details = []
        not_found_prefixes = []

        for asset in self.config.get("monitored_assets", []):
            if asset.get("skip_rpki_audit"):
                continue
            
            prefix = asset["prefix"]
            expected_asn = asset["expected_asn"]
            
            try:
                parent_net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                parent_net = None

            is_routed = False
            if parent_net:
                for info in self.active_announcements.values():
                    try:
                        announced_net = ipaddress.ip_network(info["prefix"], strict=False)
                        if announced_net.version == parent_net.version and announced_net.subnet_of(parent_net):
                            is_routed = True
                            break
                    except (ValueError, TypeError):
                        continue

            status_suffix = " (Routed)" if is_routed else " (No External Advertisements)"

            if not self.rpki_cache:
                not_found += 1
                not_found_prefixes.append(f"{prefix}{status_suffix}")
                continue
                
            covering = self.rpki_cache.search_covering(prefix)
            covered = self.rpki_cache.search_covered(prefix)
            
            # Deduplicate nodes by prefix
            nodes = {}
            for node in covering + covered:
                nodes[node.prefix] = node
                
            if not nodes:
                not_found += 1
                not_found_prefixes.append(f"{prefix}{status_suffix}")
                continue
                
            # Count the VRPs under these nodes
            asset_valid = 0
            asset_invalid = 0
            for node in nodes.values():
                for vrp in node.data.get("vrps", []):
                    vrp_asn = vrp["asn"]
                    if vrp_asn == expected_asn:
                        asset_valid += 1
                    else:
                        asset_invalid += 1
                        invalid_details.append(
                            f"• {node.prefix} (Expected AS{expected_asn}, VRP AS{vrp_asn})"
                        )
                        
            valid += asset_valid
            invalid += asset_invalid
        
        logger.info(f"RPKI Health Audit (Monitored Assets): {valid} Valid, {invalid} Invalid, {not_found} Not Found.")
        
        # 3. Compute Live RPKI counts (based on active BGP announcements)
        live_valid = 0
        live_invalid = 0
        live_not_found = 0

        for prefix, info in list(self.active_announcements.items()):
            match = self.rtree.search_best(prefix)
            if match and match.data.get("skip_rpki_audit"):
                continue
            
            status = info["rpki_status"]
            if status == "VALID":
                live_valid += 1
            elif "INVALID" in status:
                live_invalid += 1
            else:
                live_not_found += 1

        self.rpki_valid_count = live_valid
        self.rpki_invalid_count = live_invalid
        self.rpki_not_found_count = live_not_found
        
        # Prepare the health data payload
        current_health_data = {
            "total_assets": len(self.config.get("monitored_assets", [])),
            "active_announcements": len(self.active_announcements),
            "valid": valid,
            "invalid": invalid,
            "not_found": not_found,
            "invalid_details": sorted(invalid_details),
            "not_found_prefixes": sorted(not_found_prefixes),
            "live_valid": live_valid,
            "live_invalid": live_invalid,
            "live_not_found": live_not_found,
            "is_initial_report": self.is_first_health_report,
            "include_live_stats": (now - self.startup_time >= 86400)
        }

        # Deduplication Logic:
        # 1. Send if it's the first time.
        # 2. Send if the 24-hour interval has passed.
        # 3. Send if anything outside of Valid ROAs (invalids or not_found prefixes) has changed since last report.
        
        def get_anomaly_state(data):
            if not data:
                return {}
            return {
                "invalid": data.get("invalid", 0),
                "not_found": data.get("not_found", 0),
                "invalid_details": data.get("invalid_details", []),
                "not_found_prefixes": data.get("not_found_prefixes", [])
            }
        
        time_since_last = now - self.last_health_report_time
        has_anomalies_changed = get_anomaly_state(current_health_data) != get_anomaly_state(self.last_health_report_data)
        
        # Warmup delay check:
        # If we are within the warmup period, do not broadcast.
        if now - self.startup_time < self.warmup_period:
            logger.info(f"RPKI Health Summary deferred during warmup period ({int(self.warmup_period - (now - self.startup_time))}s remaining).")
            return

        should_broadcast = (self.last_health_report_time == 0) or \
                           (time_since_last > self.health_report_interval) or \
                           (has_anomalies_changed)

        if should_broadcast:
            self.last_health_report_time = now
            self.last_health_report_data = current_health_data
            self.broadcast_health_check(current_health_data)
            self.is_first_health_report = False
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
                    self.total_rpki_vrps = len(roas)
                    
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
                    
                    vrp_count = len(new_tree.prefixes())
                    min_vrps = self.config.get("min_rpki_vrps", 0)
                    
                    if vrp_count >= min_vrps:
                        self.rpki_cache = new_tree
                        self.rpki_cache_loaded = True
                        logger.info(f"Local RPKI cache loaded: {vrp_count} VRPs found.")
                        # Perform a health check every time the cache is loaded
                        self.check_rpki_health()
                    else:
                        logger.warning(f"Local RPKI cache has too few VRPs ({vrp_count} < {min_vrps}). Cache is considered incomplete.")
                        self.rpki_cache_loaded = False
                
            except Exception as e:
                logger.error(f"Failed to parse RPKI cache: {e}")
                self.rpki_cache_loaded = False
        else:
            logger.warning(f"RPKI cache not found at {rpki_path}. Falling back to 'UNKNOWN' RPKI status.")
            self.rpki_cache_loaded = False

    def check_rpki(self, prefix, origin_asn):
        """
        Validates the route against the local RPKI cache using standard ROV logic.
        - VALID: At least one VRP matches prefix, ASN, and length <= maxLength.
        - INVALID: VRPs exist for prefix, but none match ASN/length.
        - NOT FOUND: No VRPs cover this prefix.
        """
        # Check if RPKI audit is skipped for this prefix
        if hasattr(self, "rtree") and self.rtree:
            match = self.rtree.search_best(prefix)
            if match and match.data.get("skip_rpki_audit"):
                return "SKIPPED"

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
            self.stats_total_alerts += 1
            
            event_data = {
                "alert_type": alert_type,
                "description": rnode.data["description"],
                "announced_prefix": announced_prefix,
                "origin_asn": origin_asn,
                "expected_prefix": rnode.data["prefix"],
                "expected_asn": rnode.data["expected_asn"],
                "rpki_status": self.check_rpki(announced_prefix, origin_asn),
                "total_occurrences": total_occurrences,
                "peer": peer,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            self.recent_alerts.insert(0, event_data)
            if len(self.recent_alerts) > 50:
                self.recent_alerts.pop()
                
            self.broadcast_event(event_data)

    def process_bgp_message(self, message):
        """Parses RIPE RIS Live JSON messages and cross-references via Longest Prefix Match."""
        try:
            self.ws_connected = True
            msg_data = json.loads(message)
            if msg_data.get("type") != "ris_message":
                return

            data = msg_data.get("data", {})
            peer = data.get("peer", "Unknown")
            announcements = data.get("announcements", [])
            withdrawals = data.get("withdrawals", [])
            path = data.get("path", [])
            
            active_changed = False

            # Process announcements
            if announcements and path:
                # Safety check: Ensure path has elements before accessing the origin
                if isinstance(path, list) and len(path) > 0:
                    origin_asn = path[-1]  # The last ASN in the path is the origin

                    for announcement in announcements:
                        prefixes = announcement.get("prefixes", [])
                        for prefix in prefixes:
                            self.stats_total_announcements += 1
                            # O(k) Longest Prefix Match via py-radix
                            match = self.rtree.search_best(prefix)
                            
                            if match:
                                rpki_status = self.check_rpki(prefix, origin_asn)
                                
                                # Save or update in active announcements
                                if prefix not in self.active_announcements:
                                    self.active_announcements[prefix] = {
                                        "prefix": prefix,
                                        "origin_asn": origin_asn,
                                        "rpki_status": rpki_status,
                                        "peers": set(),
                                        "parent_prefix": match.data["prefix"],
                                        "description": match.data["description"],
                                        "last_seen": datetime.now(timezone.utc).isoformat()
                                    }
                                    active_changed = True
                                else:
                                    # If the origin ASN or RPKI status changed, note it
                                    old_asn = self.active_announcements[prefix]["origin_asn"]
                                    old_status = self.active_announcements[prefix]["rpki_status"]
                                    if old_asn != origin_asn or old_status != rpki_status:
                                        active_changed = True
                                
                                self.active_announcements[prefix]["peers"].add(peer)
                                self.active_announcements[prefix]["last_seen"] = datetime.now(timezone.utc).isoformat()
                                self.active_announcements[prefix]["origin_asn"] = origin_asn
                                self.active_announcements[prefix]["rpki_status"] = rpki_status

                                # Run Alert Checks
                                is_exact_match = (prefix == match.data["prefix"])
                                is_expected_asn = (origin_asn == match.data["expected_asn"])

                                if not is_expected_asn:
                                    # 1. Hijack case: Wrong ASN
                                    alert_type = "SUB-PREFIX HIJACK" if not is_exact_match else "EXACT-PREFIX ORIGIN HIJACK"
                                    self.trigger_alert(alert_type, prefix, origin_asn, peer, match)
                                elif self.rpki_cache_loaded and rpki_status != "VALID" and not match.data.get("skip_rpki_audit"):
                                    # 2. Missing or Invalid ROA
                                    self.trigger_alert("RPKI MISSING/INVALID ROA (Self-Announcement)", prefix, origin_asn, peer, match)

            # Process withdrawals
            for prefix in withdrawals:
                if prefix in self.active_announcements:
                    self.active_announcements[prefix]["peers"].discard(peer)
                    if not self.active_announcements[prefix]["peers"]:
                        del self.active_announcements[prefix]
                        active_changed = True

            if active_changed:
                self.recalculate_active_counts()
                self.schedule_health_check()

        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.error(f"Error processing message: {e}")

        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    async def reload_rpki_periodically(self):
        """Task to periodically reload the RPKI cache from disk."""
        while True:
            if not self.rpki_cache_loaded:
                await asyncio.sleep(10)
            else:
                await asyncio.sleep(900)  # Reload every 15 minutes
            logger.info("Reloading RPKI cache from disk...")
            self.load_rpki_cache()

    async def watch_config_file(self):
        """Monitors config.json for changes and reloads dynamically."""
        while True:
            await asyncio.sleep(5)
            if not os.path.exists(self.config_path):
                continue
            
            try:
                mtime = os.path.getmtime(self.config_path)
                if mtime > self.config_last_modified:
                    logger.info("Config file change detected! Reloading configuration dynamically...")
                    self.config_last_modified = mtime
                    
                    # Load and rebuild tree
                    new_config = self.load_config(self.config_path)
                    self.config = new_config
                    
                    # Clear and rebuild radix tree
                    self.rtree = radix.Radix()
                    self.build_radix_tree()
                    
                    # Re-initialize exporters
                    self.exporters = []
                    self._init_exporters()
                    
                    # Re-trigger audit
                    self.check_rpki_health()
                    
                    logger.info("Dynamic configuration reload completed successfully.")
            except Exception as e:
                logger.error(f"Failed to reload config file dynamically: {e}")

    async def start_web_server(self):
        """Starts a lightweight web server for API endpoints and dashboard."""
        dashboard_cfg = self.config.get("dashboard", {})
        if not dashboard_cfg.get("enabled", True):
            return

        try:
            from aiohttp import web
        except ImportError:
            logger.warning("Web Dashboard: 'aiohttp' package not found. Web interface is disabled.")
            return

        app = web.Application()
        
        # Register routes
        app.router.add_get('/', self._handle_index)
        app.router.add_get('/api/status', self._handle_status)
        app.router.add_get('/metrics', self._handle_metrics)

        port = dashboard_cfg.get("port", 8080)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        try:
            await site.start()
            logger.info(f"Web Dashboard started on http://0.0.0.0:{port}")
        except Exception as e:
            logger.error(f"Failed to start web server on port {port}: {e}")

    async def _handle_index(self, request):
        from aiohttp import web
        dash_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard", "index.html")
        if os.path.exists(dash_path):
            try:
                with open(dash_path, "r", encoding="utf-8") as f:
                    content = f.read()
                return web.Response(text=content, content_type='text/html')
            except Exception as e:
                return web.Response(text=f"<h1>Error loading dashboard</h1><p>{e}</p>", content_type='text/html')
        return web.Response(text="<h1>RPKI-Guardian Dashboard</h1><p>index.html not found</p>", content_type='text/html')

    async def _handle_status(self, request):
        from aiohttp import web
        assets = []
        for prefix in self.config.get("monitored_assets", []):
            parent_prefix = prefix["prefix"]
            rpki_status = self.check_rpki(parent_prefix, prefix["expected_asn"])
            
            # If the status is NOT FOUND, check if we have any active advertisements under this parent block
            if rpki_status.startswith("NOT FOUND"):
                try:
                    parent_net = ipaddress.ip_network(parent_prefix, strict=False)
                except ValueError:
                    parent_net = None

                has_active = False
                if parent_net:
                    for info in self.active_announcements.values():
                        try:
                            announced_net = ipaddress.ip_network(info["prefix"], strict=False)
                            if announced_net.version == parent_net.version and announced_net.subnet_of(parent_net):
                                has_active = True
                                break
                        except (ValueError, TypeError):
                            continue

                is_parent_directly_advertised = parent_prefix in self.active_announcements
                
                if not has_active:
                    rpki_status = "No External Advertisements"
                elif not is_parent_directly_advertised:
                    rpki_status = "Parent Block Not Directly Routed"

            assets.append({
                "prefix": parent_prefix,
                "expected_asn": prefix["expected_asn"],
                "description": prefix["description"],
                "rpki_status": rpki_status
            })

        active_list = []
        for prefix, info in self.active_announcements.items():
            active_list.append({
                "prefix": info["prefix"],
                "origin_asn": info["origin_asn"],
                "rpki_status": info["rpki_status"],
                "peers_count": len(info["peers"]),
                "parent_prefix": info["parent_prefix"],
                "description": info["description"],
                "last_seen": info["last_seen"]
            })
        active_list.sort(key=lambda x: x["prefix"])

        data = {
            "ws_connected": self.ws_connected,
            "total_assets": len(self.config.get("monitored_assets", [])),
            "rpki_valid_count": self.rpki_valid_count,
            "rpki_invalid_count": self.rpki_invalid_count,
            "rpki_not_found_count": self.rpki_not_found_count,
            "total_announcements": self.stats_total_announcements,
            "total_alerts": self.stats_total_alerts,
            "assets": assets,
            "active_announcements": active_list,
            "recent_alerts": self.recent_alerts
        }
        return web.json_response(data)

    async def _handle_metrics(self, request):
        from aiohttp import web
        lines = [
            "# HELP rpki_guardian_ws_connected Indicates if WebSocket is connected (1) or not (0).",
            "# TYPE rpki_guardian_ws_connected gauge",
            f"rpki_guardian_ws_connected {1 if self.ws_connected else 0}",
            
            "# HELP rpki_guardian_total_assets Total protected parent assets.",
            "# TYPE rpki_guardian_total_assets gauge",
            f"rpki_guardian_total_assets {len(self.config.get('monitored_assets', []))}",
            
            "# HELP rpki_guardian_active_announcements_count Count of currently advertised child prefixes.",
            "# TYPE rpki_guardian_active_announcements_count gauge",
            f"rpki_guardian_active_announcements_count {len(self.active_announcements)}",
            
            "# HELP rpki_guardian_rpki_valid_count Count of valid RPKI active child announcements.",
            "# TYPE rpki_guardian_rpki_valid_count gauge",
            f"rpki_guardian_rpki_valid_count {self.rpki_valid_count}",
            
            "# HELP rpki_guardian_rpki_invalid_count Count of invalid RPKI active child announcements.",
            "# TYPE rpki_guardian_rpki_invalid_count gauge",
            f"rpki_guardian_rpki_invalid_count {self.rpki_invalid_count}",
            
            "# HELP rpki_guardian_rpki_not_found_count Count of active child announcements with no ROA.",
            "# TYPE rpki_guardian_rpki_not_found_count gauge",
            f"rpki_guardian_rpki_not_found_count {self.rpki_not_found_count}",
            
            "# HELP rpki_guardian_total_announcements_processed Total BGP announcements processed.",
            "# TYPE rpki_guardian_total_announcements_processed counter",
            f"rpki_guardian_total_announcements_processed {self.stats_total_announcements}",
            
            "# HELP rpki_guardian_total_alerts_triggered Total security alerts triggered.",
            "# TYPE rpki_guardian_total_alerts_triggered counter",
            f"rpki_guardian_total_alerts_triggered {self.stats_total_alerts}",
        ]
        return web.Response(text="\n".join(lines) + "\n", content_type='text/plain')

    async def _initial_warmup_check(self):
        """Waits for the warmup period to finish, then triggers the first health summary."""
        await asyncio.sleep(self.warmup_period + 1)
        logger.info("Startup warmup period finished. Triggering initial health audit.")
        self.check_rpki_health()

    async def stream_ris_live(self):
        """Establishes an asynchronous WebSocket connection to RIPE RIS Live."""
        url = "wss://ris-live.ripe.net/v1/ws/"
        
        # Start background tasks
        asyncio.create_task(self.reload_rpki_periodically())
        asyncio.create_task(self.watch_config_file())
        asyncio.create_task(self.start_web_server())
        asyncio.create_task(self._initial_warmup_check())
        
        while True:
            try:
                logger.info(f"Connecting to RIPE RIS Live at {url}...")
                self.ws_connected = False
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
                self.ws_connected = False
                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"WebSocket error: {e}. Reconnecting in 5 seconds...")
                self.ws_connected = False
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
