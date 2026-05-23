import pytest
import json
import os
from main import BGPMonitorEngine

@pytest.fixture
def mock_config(tmp_path):
    # Create a mock RPKI cache file with a valid ROA covering the monitored asset
    rpki_file = tmp_path / "rpki.json"
    rpki_data = {
        "roas": [
            {"asn": "AS64496", "prefix": "192.0.2.0/22", "maxLength": 24}
        ]
    }
    with open(rpki_file, "w") as f:
        json.dump(rpki_data, f)

    config = {
        "rpki_cache_path": str(rpki_file),
        "alerting": {"log_level": "INFO"},
        "monitored_assets": [
            {
                "prefix": "192.0.2.0/22",
                "expected_asn": 64496,
                "description": "Test Prefix"
            }
        ]
    }
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f)
    return str(config_file)

def test_engine_initialization(mock_config):
    engine = BGPMonitorEngine(config_path=mock_config)
    assert len(engine.rtree.prefixes()) == 1
    assert engine.rtree.search_best("192.0.2.0/22") is not None

def test_exact_prefix_match(mock_config, caplog):
    engine = BGPMonitorEngine(config_path=mock_config)
    
    # Exact match, correct ASN -> No alert
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/22"]}]
        }
    })
    engine.process_bgp_message(msg)
    assert "BGP SECURITY ALERT DETECTED" not in caplog.text

def test_origin_hijack_alert(mock_config, caplog):
    engine = BGPMonitorEngine(config_path=mock_config)
    
    # Exact match, WRONG ASN -> Alert
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 666],
            "announcements": [{"prefixes": ["192.0.2.0/22"]}]
        }
    })
    engine.process_bgp_message(msg)
    assert "EXACT-PREFIX ORIGIN HIJACK" in caplog.text
    assert "via AS666" in caplog.text

def test_sub_prefix_hijack_alert(mock_config, caplog):
    engine = BGPMonitorEngine(config_path=mock_config)
    
    # Sub-prefix match -> Alert
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 777],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg)
    assert "SUB-PREFIX HIJACK" in caplog.text
    assert "192.0.2.0/24" in caplog.text

def test_sub_prefix_missing_roa(mock_config, caplog):
    engine = BGPMonitorEngine(config_path=mock_config)
    
    # Prefix 192.0.2.0/25 is announced.
    # The default mock_config ROA has maxLength 24, so /25 is invalid/missing a valid ROA.
    # Since origin_asn is correct (64496), it should trigger a MISSING/INVALID ROA alert.
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/25"]}]
        }
    })
    engine.process_bgp_message(msg)
    assert "RPKI MISSING/INVALID ROA (Self-Announcement)" in caplog.text
    assert "192.0.2.0/25" in caplog.text

def test_sub_prefix_valid_roa(mock_config, caplog):
    engine = BGPMonitorEngine(config_path=mock_config)
    
    # Prefix 192.0.2.0/24 is announced.
    # The default mock_config ROA covers 192.0.2.0/22 up to maxLength 24.
    # So it is VALID, and origin ASN is correct.
    # It should pass silently (no alerts, no traffic engineering logs).
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg)
    assert "BGP ALERT" not in caplog.text
    assert "Legitimate Traffic Engineering" not in caplog.text

def test_rpki_validation(tmp_path, caplog):
    # Create a mock RPKI cache file
    rpki_data = {
        "roas": [
            {"asn": "AS64496", "prefix": "192.0.2.0/24", "maxLength": 24},
            {"asn": "64500", "prefix": "198.51.100.0/24", "maxLength": 24}
        ]
    }
    rpki_file = tmp_path / "rpki.json"
    with open(rpki_file, "w") as f:
        json.dump(rpki_data, f)
    
    config = {
        "rpki_cache_path": str(rpki_file),
        "monitored_assets": [{"prefix": "192.0.0.0/8", "expected_asn": 0, "description": "Test"}]
    }
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f)
        
    engine = BGPMonitorEngine(config_path=str(config_file))
    
    # Test valid RPKI
    status = engine.check_rpki("192.0.2.0/24", 64496)
    assert status == "VALID"
    
    # Test invalid RPKI (wrong ASN)
    status = engine.check_rpki("192.0.2.0/24", 666)
    assert "INVALID" in status
    
    # Test unknown RPKI (prefix not in cache)
    status = engine.check_rpki("8.8.8.8/32", 15169)
    assert "NOT FOUND" in status

def test_min_rpki_vrps_threshold(tmp_path):
    # Create a mock RPKI cache file with exactly 1 ROA
    rpki_data = {
        "roas": [
            {"asn": "AS64496", "prefix": "192.0.2.0/24", "maxLength": 24}
        ]
    }
    rpki_file = tmp_path / "rpki.json"
    with open(rpki_file, "w") as f:
        json.dump(rpki_data, f)

    # 1. Test case: min_rpki_vrps is set to 2 (greater than actual ROA count of 1)
    config_under_threshold = {
        "rpki_cache_path": str(rpki_file),
        "min_rpki_vrps": 2,
        "monitored_assets": [{"prefix": "192.0.2.0/24", "expected_asn": 64496, "description": "Test"}]
    }
    config_file_1 = tmp_path / "config_1.json"
    with open(config_file_1, "w") as f:
        json.dump(config_under_threshold, f)

    engine_under = BGPMonitorEngine(config_path=str(config_file_1))
    # Since VRP count (1) < min_rpki_vrps (2), it should not mark cache as loaded
    assert engine_under.rpki_cache_loaded is False

    # 2. Test case: min_rpki_vrps is set to 1 (equal to actual ROA count of 1)
    config_at_threshold = {
        "rpki_cache_path": str(rpki_file),
        "min_rpki_vrps": 1,
        "monitored_assets": [{"prefix": "192.0.2.0/24", "expected_asn": 64496, "description": "Test"}]
    }
    config_file_2 = tmp_path / "config_2.json"
    with open(config_file_2, "w") as f:
        json.dump(config_at_threshold, f)

    engine_at = BGPMonitorEngine(config_path=str(config_file_2))
    # Since VRP count (1) >= min_rpki_vrps (1), it should mark cache as loaded
    assert engine_at.rpki_cache_loaded is True

def test_skip_rpki_audit_respected(tmp_path, caplog):
    # Create an empty mock RPKI cache
    rpki_file = tmp_path / "rpki.json"
    with open(rpki_file, "w") as f:
        json.dump({"roas": []}, f)
        
    config = {
        "rpki_cache_path": str(rpki_file),
        "min_rpki_vrps": 0,
        "monitored_assets": [
            {
                "prefix": "198.51.100.0/24",
                "expected_asn": 64500,
                "description": "Exempt Test Asset",
                "skip_rpki_audit": True
            }
        ]
    }
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f)
        
    engine = BGPMonitorEngine(config_path=str(config_file))
    
    # Process announcement with correct expected ASN but missing RPKI ROA
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64500],
            "announcements": [{"prefixes": ["198.51.100.0/24"]}]
        }
    })
    engine.process_bgp_message(msg)
    
    # Verify that NO alert is triggered for RPKI MISSING/INVALID
    assert "RPKI MISSING/INVALID ROA" not in caplog.text
    # Verify that the announcement was registered in active announcements
    assert "198.51.100.0/24" in engine.active_announcements
    # Verify that check_rpki returns SKIPPED
    assert engine.check_rpki("198.51.100.0/24", 64500) == "SKIPPED"

def test_no_external_advertisements_logic(tmp_path):
    import asyncio
    # Create empty RPKI cache (so we get NOT FOUND status)
    rpki_file = tmp_path / "rpki.json"
    with open(rpki_file, "w") as f:
        json.dump({"roas": []}, f)
        
    config = {
        "rpki_cache_path": str(rpki_file),
        "min_rpki_vrps": 0,
        "monitored_assets": [
            {
                "prefix": "192.0.2.0/22",
                "expected_asn": 64496,
                "description": "Test Parent Prefix"
            }
        ]
    }
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f)
        
    engine = BGPMonitorEngine(config_path=str(config_file))
    
    # 1. No active announcements -> check _handle_status output
    response = asyncio.run(engine._handle_status(None))
    data = json.loads(response.body.decode('utf-8'))
    asset = data["assets"][0]
    assert asset["prefix"] == "192.0.2.0/22"
    assert asset["rpki_status"] == "No External Advertisements"
    
    # 2. Now simulate a child announcement under the parent block (e.g. 192.0.2.0/24)
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg)
    
    # Verify child prefix is active
    assert "192.0.2.0/24" in engine.active_announcements
    
    # Run _handle_status again
    response_with_child = asyncio.run(engine._handle_status(None))
    data_with_child = json.loads(response_with_child.body.decode('utf-8'))
    asset_with_child = data_with_child["assets"][0]
    assert asset_with_child["rpki_status"] == "Parent Block Not Directly Routed"
    
    # 3. Now simulate direct parent announcement (192.0.2.0/22)
    msg_parent = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/22"]}]
        }
    })
    engine.process_bgp_message(msg_parent)
    
    # Run _handle_status again
    response_with_parent = asyncio.run(engine._handle_status(None))
    data_with_parent = json.loads(response_with_parent.body.decode('utf-8'))
    asset_with_parent = data_with_parent["assets"][0]
    assert asset_with_parent["rpki_status"] == "NOT FOUND (No ROA for this prefix)"

def test_health_report_deduplication_and_startup(mock_config):
    engine = BGPMonitorEngine(config_path=mock_config)
    engine.warmup_period = 0
    
    # Capture sent health checks
    sent_reports = []
    engine.broadcast_health_check = lambda data: sent_reports.append(data)
    
    # Clear the startup broadcast
    sent_reports.clear()
    
    # 1. Trigger initial health report (no active announcements yet)
    engine.check_rpki_health()
    
    # First health audit report should be sent
    assert len(sent_reports) == 1
    first_report = sent_reports[-1]
    assert first_report["valid"] == 1
    assert first_report["invalid"] == 0
    assert first_report["not_found"] == 0
    assert first_report["live_valid"] == 0
    assert first_report["is_initial_report"] is True
    
    # Clear reports list
    sent_reports.clear()
    
    # 2. Simulate a BGP announcement (valid, e.g. 192.0.2.0/24)
    msg_valid = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg_valid)
    engine.check_rpki_health()
    
    # Since only LIVE announcements changed (no anomalies in monitored assets changed), no report should be broadcasted (deduplication works)
    assert len(sent_reports) == 0
    
    # 3. Now simulate an invalid monitored asset by changing its expected ASN in config
    engine.config["monitored_assets"][0]["expected_asn"] = 666
    engine.check_rpki_health()
    
    # This introduces a new anomaly, so it should broadcast immediately!
    assert len(sent_reports) == 1
    assert sent_reports[-1]["invalid"] == 1
    assert sent_reports[-1]["valid"] == 0
    # Since the first report was already sent and cleared the flag, this should be False
    assert sent_reports[-1]["is_initial_report"] is False

def test_alert_cooldown_deduplication(mock_config):
    engine = BGPMonitorEngine(config_path=mock_config)
    
    # Verify that duplicate announcements of the same hijack event do not increment stats_total_alerts
    # or duplicate entries in recent_alerts when under cooldown.
    
    # 1. Trigger the hijack event
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 666],
            "announcements": [{"prefixes": ["192.0.2.0/22"]}]
        }
    })
    
    engine.process_bgp_message(msg)
    
    # Verify alert is counted
    assert engine.stats_total_alerts == 1
    assert len(engine.recent_alerts) == 1
    assert engine.recent_alerts[0]["announced_prefix"] == "192.0.2.0/22"
    
    # 2. Trigger the exact same hijack event again (duplicate)
    engine.process_bgp_message(msg)
    
    # Verify alert is cooldowned and NOT duplicated in dashboard stats or alarm log
    assert engine.stats_total_alerts == 1
    assert len(engine.recent_alerts) == 1


def test_overlapping_parent_child_config_logic(tmp_path):
    import asyncio
    # Create empty RPKI cache (so we get NOT FOUND status)
    rpki_file = tmp_path / "rpki.json"
    with open(rpki_file, "w") as f:
        json.dump({"roas": []}, f)
        
    config = {
        "rpki_cache_path": str(rpki_file),
        "min_rpki_vrps": 0,
        "monitored_assets": [
            {
                "prefix": "192.0.2.0/22",
                "expected_asn": 64496,
                "description": "Parent Block"
            },
            {
                "prefix": "192.0.2.0/24",
                "expected_asn": 64496,
                "description": "Child Block"
            }
        ]
    }
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f)
        
    engine = BGPMonitorEngine(config_path=str(config_file))
    engine.warmup_period = 0
    
    # Simulate a child announcement (192.0.2.0/24)
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg)
    
    # Run _handle_status
    response = asyncio.run(engine._handle_status(None))
    data = json.loads(response.body.decode('utf-8'))
    
    # We should have two assets in the response
    assert len(data["assets"]) == 2
    
    # Check parent asset
    parent_asset = next(a for a in data["assets"] if a["prefix"] == "192.0.2.0/22")
    assert parent_asset["rpki_status"] == "Parent Block Not Directly Routed"
    
    # Check child asset
    child_asset = next(a for a in data["assets"] if a["prefix"] == "192.0.2.0/24")
    assert child_asset["rpki_status"] == "NOT FOUND (No ROA for this prefix)"


def test_startup_warmup_delay(mock_config):
    import time
    engine = BGPMonitorEngine(config_path=mock_config)
    engine.warmup_period = 2  # 2 seconds warmup window
    
    sent_reports = []
    engine.broadcast_health_check = lambda data: sent_reports.append(data)
    sent_reports.clear()
    
    # Simulate a valid announcement
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg)
    
    # Run check_rpki_health immediately. It should be deferred since we are in the warmup window.
    engine.check_rpki_health()
    assert len(sent_reports) == 0
    
    # Sleep to exceed the warmup window
    time.sleep(2.5)
    
    # Run check_rpki_health again. Now it should broadcast!
    engine.check_rpki_health()
    assert len(sent_reports) == 1
    assert sent_reports[0]["is_initial_report"] is True


def test_ipv4_ipv6_version_mismatch_handling(tmp_path):
    import asyncio
    # Create empty RPKI cache
    rpki_file = tmp_path / "rpki.json"
    with open(rpki_file, "w") as f:
        json.dump({"roas": []}, f)
        
    config = {
        "rpki_cache_path": str(rpki_file),
        "min_rpki_vrps": 0,
        "monitored_assets": [
            {
                "prefix": "192.0.2.0/22",
                "expected_asn": 64496,
                "description": "IPv4 Parent"
            },
            {
                "prefix": "2001:db8:100::/40",
                "expected_asn": 64501,
                "description": "IPv6 Parent"
            }
        ]
    }
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f)
        
    engine = BGPMonitorEngine(config_path=str(config_file))
    engine.warmup_period = 0
    
    # Simulate an IPv4 announcement under the IPv4 parent
    msg_v4 = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg_v4)
    
    # Simulate an IPv6 announcement under the IPv6 parent
    msg_v6 = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64501],
            "announcements": [{"prefixes": ["2001:db8:100::/48"]}]
        }
    })
    engine.process_bgp_message(msg_v6)
    
    # Run _handle_status. This should execute without raising TypeError!
    response = asyncio.run(engine._handle_status(None))
    data = json.loads(response.body.decode('utf-8'))
    
    assert len(data["assets"]) == 2
    
    v4_asset = next(a for a in data["assets"] if a["prefix"] == "192.0.2.0/22")
    assert v4_asset["rpki_status"] == "Parent Block Not Directly Routed"
    
    v6_asset = next(a for a in data["assets"] if a["prefix"] == "2001:db8:100::/40")
    assert v6_asset["rpki_status"] == "Parent Block Not Directly Routed"


def test_not_found_prefixes_routing_suffix(tmp_path):
    # Create empty RPKI cache so all monitored assets are "Not Found"
    rpki_file = tmp_path / "rpki.json"
    with open(rpki_file, "w") as f:
        json.dump({"roas": []}, f)
        
    config = {
        "rpki_cache_path": str(rpki_file),
        "min_rpki_vrps": 0,
        "monitored_assets": [
            {
                "prefix": "192.0.2.0/22",
                "expected_asn": 64496,
                "description": "Routed Prefix"
            },
            {
                "prefix": "198.51.100.0/22",
                "expected_asn": 64496,
                "description": "Unrouted Prefix"
            }
        ]
    }
    config_file = tmp_path / "config.json"
    with open(config_file, "w") as f:
        json.dump(config, f)
        
    engine = BGPMonitorEngine(config_path=str(config_file))
    engine.warmup_period = 0
    
    # Capture sent health checks
    sent_reports = []
    engine.broadcast_health_check = lambda data: sent_reports.append(data)
    sent_reports.clear()
    
    # Simulate a BGP announcement for a sub-prefix of 192.0.2.0/22 (so it is Routed)
    msg = json.dumps({
        "type": "ris_message",
        "data": {
            "peer": "test-peer",
            "path": [1, 2, 64496],
            "announcements": [{"prefixes": ["192.0.2.0/24"]}]
        }
    })
    engine.process_bgp_message(msg)
    
    # Trigger health check
    engine.check_rpki_health()
    
    assert len(sent_reports) == 1
    report = sent_reports[0]
    
    # Check that both prefixes are in not_found_prefixes with correct routing suffixes
    prefixes = report["not_found_prefixes"]
    assert len(prefixes) == 2
    
    routed_entry = next(p for p in prefixes if "192.0.2.0/22" in p)
    assert routed_entry == "192.0.2.0/22 (Routed)"
    
    unrouted_entry = next(p for p in prefixes if "198.51.100.0/22" in p)
    assert unrouted_entry == "198.51.100.0/22 (No External Advertisements)"


def test_live_stats_time_limit(mock_config):
    import time
    from exporters.chat import ChatExporter
    from exporters.sendgrid import SendGridExporter
    from exporters.smtp import SMTPExporter

    engine = BGPMonitorEngine(config_path=mock_config)
    engine.warmup_period = 0
    
    # 1. Under 24 hours (default startup time is now)
    sent_reports = []
    engine.broadcast_health_check = lambda data: sent_reports.append(data)
    engine.check_rpki_health()
    
    assert len(sent_reports) == 1
    report_recent = sent_reports[0]
    assert report_recent["include_live_stats"] is False

    # 2. Over 24 hours (simulate startup 25 hours ago)
    engine.startup_time = time.time() - 90000
    engine.last_health_report_time = 0
    sent_reports.clear()
    engine.check_rpki_health()
    
    assert len(sent_reports) == 1
    report_old = sent_reports[0]
    assert report_old["include_live_stats"] is True

    # 3. Test exporters formatting
    # Chat Exporter
    chat_sent = []
    chat_exporter = ChatExporter({"chat_webhook": "http://mock-webhook"})
    chat_exporter._send = lambda msg: chat_sent.append(msg)
    
    # Check under 24 hours
    chat_exporter.export_health_check(report_recent)
    assert len(chat_sent) == 1
    assert "Live Valid ROAs" not in chat_sent[0]
    
    # Check over 24 hours
    chat_sent.clear()
    chat_exporter.export_health_check(report_old)
    assert len(chat_sent) == 1
    assert "Live Valid ROAs" in chat_sent[0]

    # SMTP Exporter
    smtp_sent = []
    smtp_exporter = SMTPExporter({"enabled": True, "server": "localhost", "from_email": "a@b.com", "to_email": "c@d.com"})
    smtp_exporter._send_email = lambda subject, content: smtp_sent.append(content)
    
    # Check under 24 hours
    smtp_exporter.export_health_check(report_recent)
    assert len(smtp_sent) == 1
    assert "Live Valid ROAs" not in smtp_sent[0]
    
    # Check over 24 hours
    smtp_sent.clear()
    smtp_exporter.export_health_check(report_old)
    assert len(smtp_sent) == 1
    assert "Live Valid ROAs" in smtp_sent[0]


