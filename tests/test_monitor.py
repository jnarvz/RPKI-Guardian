import pytest
import json
import os
from main import BGPMonitorEngine

@pytest.fixture
def mock_config(tmp_path):
    config = {
        "rpki_cache_path": str(tmp_path / "rpki.json"),
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
    # We need to trigger a mismatch. 
    # The prefix 192.0.2.0/24 matches 192.0.2.0/22 in the radix tree.
    # If the origin_asn is the SAME as expected, it won't trigger HIJACK unless RPKI is invalid.
    # To force a SUB-PREFIX HIJACK alert, we use a DIFFERENT ASN.
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
