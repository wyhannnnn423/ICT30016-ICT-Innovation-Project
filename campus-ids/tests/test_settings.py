"""
Tests for the dashboard settings (validation, IP matching, live changes, web API).

Run from the project root:
    python tests/test_settings.py
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dashboard"))

import ids_settings as S
from detection import Detector


def rule_event(src, dest="192.168.50.190"):
    return {"event_type": "alert", "timestamp": "2026-10-08T10:00:00+0800", "src_ip": src, "dest_ip": dest,
            "proto": "TCP", "alert": {"signature": "LOCAL SYN burst", "signature_id": 1000102, "severity": 2}}


def flow_event(src, dest_port, dest="192.168.50.190"):
    return {"event_type": "flow", "timestamp": "2026-10-08T10:00:00+0800", "src_ip": src, "dest_ip": dest,
            "dest_port": dest_port, "proto": "TCP",
            "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 60, "bytes_toclient": 60}}


class IpMatcherTests(unittest.TestCase):
    def test_single_ip_and_range(self):
        m = S.IpMatcher(["192.168.50.1", "10.0.0.0/28"])
        self.assertTrue(m.matches("192.168.50.1"))
        self.assertTrue(m.matches("10.0.0.7"))
        self.assertFalse(m.matches("10.0.0.99"))
        self.assertFalse(m.matches("192.168.50.2"))

    def test_ipv6_spellings_match(self):
        m = S.IpMatcher(["fe80::5e64:8eff:fe71:4420"])
        self.assertTrue(m.matches("fe80:0000:0000:0000:5e64:8eff:fe71:4420"))   # how Suricata writes it

    def test_bad_input_never_matches(self):
        m = S.IpMatcher(["192.168.50.1"])
        self.assertFalse(m.matches(None))
        self.assertFalse(m.matches(""))
        self.assertFalse(m.matches("not-an-ip"))


class ValidateTests(unittest.TestCase):
    def test_valid(self):
        clean, errors = S.validate({"own_ips": "192.168.50.190", "trusted_ips": ["192.168.50.0/28", "10.0.0.5"],
                                    "scan_ports": 20, "flood_flows": "200", "window": 10, "cooldown": 30})
        self.assertEqual(errors, [])
        self.assertEqual(clean["own_ips"], ["192.168.50.190"])
        self.assertEqual(clean["trusted_ips"], ["192.168.50.0/28", "10.0.0.5"])
        self.assertEqual(clean["flood_flows"], 200)

    def test_missing_keys_keep_current_values(self):
        clean, errors = S.validate({"scan_ports": 30}, current={"own_ips": ["1.2.3.4"], "flood_flows": 500})
        self.assertEqual(errors, [])
        self.assertEqual(clean["scan_ports"], 30)
        self.assertEqual(clean["own_ips"], ["1.2.3.4"])
        self.assertEqual(clean["flood_flows"], 500)

    def test_bad_ip(self):
        _, errors = S.validate({"own_ips": "192.168.50.999"})
        self.assertEqual(len(errors), 1)

    def test_range_not_allowed_for_own_ip(self):
        _, errors = S.validate({"own_ips": "192.168.50.0/24"})
        self.assertEqual(len(errors), 1)

    def test_huge_range_rejected(self):
        for bad in ("0.0.0.0/0", "10.0.0.0/7", "::/0"):
            _, errors = S.validate({"trusted_ips": bad})
            self.assertEqual(len(errors), 1, bad)

    def test_numbers(self):
        for bad in ({"scan_ports": 1}, {"scan_ports": 5000}, {"window": 0}, {"cooldown": -1},
                    {"flood_flows": "abc"}, {"scan_ports": True}, {"window": 2.5}):
            _, errors = S.validate(bad)
            self.assertEqual(len(errors), 1, bad)

    def test_auto_flag(self):
        clean, errors = S.validate({"auto_own_ip": False})
        self.assertEqual((errors, clean["auto_own_ip"]), ([], False))
        clean, errors = S.validate({})
        self.assertTrue(clean["auto_own_ip"])                    # on by default
        for bad in ("yes", 1, None):
            _, errors = S.validate({"auto_own_ip": bad})
            self.assertEqual(len(errors), 1, bad)

    def test_not_an_object(self):
        _, errors = S.validate([1, 2, 3])
        self.assertEqual(len(errors), 1)

    def test_duplicates_removed(self):
        clean, _ = S.validate({"trusted_ips": "10.0.0.5, 10.0.0.5"})
        self.assertEqual(clean["trusted_ips"], ["10.0.0.5"])


class StorageTests(unittest.TestCase):
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "data" / "settings.json"
            S.save(path, {"own_ips": ["1.2.3.4"], "trusted_ips": [], "scan_ports": 20,
                          "flood_flows": 150, "window": 10, "cooldown": 30})
            loaded = S.load(path)
            self.assertEqual(loaded["own_ips"], ["1.2.3.4"])
            self.assertEqual(loaded["scan_ports"], 20)

    def test_missing_or_broken_file_gives_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(S.load(Path(d) / "nope.json"), {})
            broken = Path(d) / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            self.assertEqual(S.load(broken), {})

    def test_invalid_values_in_file_are_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            path.write_text(json.dumps({"scan_ports": 5000, "window": 20, "unknown": 1}), encoding="utf-8")
            self.assertEqual(S.load(path), {"window": 20})

    def test_startup_order(self):
        # nothing set anywhere -> automatic mode with the detected IP
        settings, errors, auto = S.startup_settings({}, {}, "192.168.50.190")
        self.assertEqual((errors, auto, settings["own_ips"], settings["auto_own_ip"]),
                         ([], "192.168.50.190", ["192.168.50.190"], True))
        # automatic mode saved in the file: the stored address is replaced by the current one
        settings, _, auto = S.startup_settings({"auto_own_ip": True, "own_ips": ["1.1.1.1"]}, {}, "10.9.8.7")
        self.assertEqual((auto, settings["own_ips"]), ("10.9.8.7", ["10.9.8.7"]))
        # automatic mode switched off in the file: the typed address stays
        settings, _, auto = S.startup_settings({"auto_own_ip": False, "own_ips": ["1.1.1.1"]}, {}, "10.9.8.7")
        self.assertEqual((auto, settings["own_ips"]), (None, ["1.1.1.1"]))
        # file from before automatic mode existed: an own_ips value (even an empty one) is respected
        settings, _, auto = S.startup_settings({"own_ips": []}, {}, "192.168.50.190")
        self.assertEqual((auto, settings["own_ips"], settings["auto_own_ip"]), (None, [], False))
        # --own-ip wins over everything and turns automatic mode off
        settings, _, auto = S.startup_settings({"own_ips": ["1.1.1.1"], "scan_ports": 20},
                                               {"own_ips": ["2.2.2.2"], "scan_ports": 30}, "192.168.50.190")
        self.assertEqual((settings["own_ips"], settings["scan_ports"], settings["auto_own_ip"], auto),
                         (["2.2.2.2"], 30, False, None))
        # automatic mode but nothing could be detected: no address, no crash
        settings, _, auto = S.startup_settings({}, {}, None)
        self.assertEqual((settings["own_ips"], auto), ([], None))
        # bad command line value
        settings, errors, _ = S.startup_settings({}, {"scan_ports": 1})
        self.assertIsNone(settings)
        self.assertEqual(len(errors), 1)

    def test_resolve_own_ips(self):
        self.assertEqual(S.resolve_own_ips({"auto_own_ip": True, "own_ips": ["1.1.1.1"]}, "9.9.9.9")["own_ips"], ["9.9.9.9"])
        self.assertEqual(S.resolve_own_ips({"auto_own_ip": False, "own_ips": ["1.1.1.1"]}, "9.9.9.9")["own_ips"], ["1.1.1.1"])
        self.assertEqual(S.resolve_own_ips({"auto_own_ip": True, "own_ips": ["1.1.1.1"]}, None)["own_ips"], ["1.1.1.1"])

    def test_host_header(self):
        for ok in ("localhost:5000", "127.0.0.1:5000", "192.168.50.190:5000", "[::1]:5000", "localhost"):
            self.assertTrue(S.host_header_ok(ok), ok)
        for bad in ("evil.example.com:5000", "mypc:5000", "", None):
            self.assertFalse(S.host_header_ok(bad), bad)


class DetectorTests(unittest.TestCase):
    def make(self, **kw):
        return Detector(model_path=None, scaler_path=None, **kw)    # no ML model needed here

    def test_own_and_trusted_sources_are_ignored(self):
        d = self.make(own_ips=["192.168.50.190"], trusted_ips=["192.168.50.0/28"])
        self.assertEqual(d.process(rule_event("192.168.50.190")), [])     # own PC
        self.assertEqual(d.process(rule_event("192.168.50.5")), [])       # inside trusted range
        self.assertEqual(len(d.process(rule_event("192.168.50.204"))), 1) # anyone else is reported

    def test_stats_layer_also_ignores(self):
        d = self.make(trusted_ips=["10.0.0.9"], scan_ports=5)
        out = []
        for port in range(1, 30):
            out += d.process(flow_event("10.0.0.9", port))
        self.assertEqual(out, [])
        for port in range(1, 30):
            out += d.process(flow_event("10.0.0.10", port))
        self.assertEqual(len(out), 1)

    def test_settings_apply_while_running(self):
        d = self.make()
        out = []
        for port in range(1, 11):                       # 10 ports: below the default of 15
            out += d.process(flow_event("10.0.0.20", port))
        self.assertEqual(out, [])
        clean, errors = S.validate({"scan_ports": 8}, d.get_settings())
        self.assertEqual(errors, [])
        d.apply_settings(clean)
        out = []
        for port in range(100, 110):                    # same kind of traffic now crosses the new limit
            out += d.process(flow_event("10.0.0.21", port))
        self.assertEqual(len(out), 1)
        self.assertEqual(d.get_settings()["scan_ports"], 8)

    def test_ignore_list_changes_while_running(self):
        d = self.make()
        self.assertEqual(len(d.process(rule_event("10.0.0.50"))), 1)
        d.apply_settings({**d.get_settings(), "trusted_ips": ["10.0.0.50"]})
        self.assertEqual(d.process(rule_event("10.0.0.50", dest="192.168.50.77")), [])


class NetworkFollowTests(unittest.TestCase):
    def make(self, **kw):
        return Detector(model_path=None, scaler_path=None, **kw)

    def test_follows_network_change_in_automatic_mode(self):
        d = self.make(own_ips=["192.168.50.190"], auto_own_ip=True)
        self.assertFalse(d.refresh_own_ip("192.168.50.190"))      # same address: nothing to do
        self.assertTrue(d.refresh_own_ip("172.17.116.127"))       # joined another network
        self.assertEqual(d.get_settings()["own_ips"], ["172.17.116.127"])
        self.assertEqual(d.process(rule_event("172.17.116.127")), [])             # new address is hidden
        self.assertEqual(len(d.process(rule_event("192.168.50.190"))), 1)         # old address no longer is

    def test_manual_mode_never_changes(self):
        d = self.make(own_ips=["192.168.50.190"], auto_own_ip=False)
        self.assertFalse(d.refresh_own_ip("172.17.116.127"))
        self.assertEqual(d.get_settings()["own_ips"], ["192.168.50.190"])

    def test_nothing_detected_keeps_the_address(self):
        d = self.make(own_ips=["192.168.50.190"], auto_own_ip=True)
        self.assertFalse(d.refresh_own_ip(None))
        self.assertEqual(d.get_settings()["own_ips"], ["192.168.50.190"])

    def test_capture_check_states(self):
        d = self.make(own_ips=["192.168.50.190"])
        t0 = d.started
        self.assertEqual(d.capture_status(now=t0 + 5)["state"], "starting")
        self.assertEqual(d.capture_status(now=t0 + 120)["state"], "idle")
        # events that do not involve this PC (for example Suricata listens on another network)
        d.process(flow_event("10.5.5.5", 80, dest="10.5.5.6"), now=t0 + 130)
        status = d.capture_status(now=t0 + 131)
        self.assertEqual(status["state"], "other_traffic")
        self.assertIn("start_suricata.ps1", status["message"])
        self.assertIn("scripts\\start_suricata.ps1", status["message"])        # one backslash in the real text
        # traffic of this PC, as sender and as receiver
        d.process(flow_event("192.168.50.190", 443, dest="8.8.8.8"), now=t0 + 140)
        self.assertEqual(d.capture_status(now=t0 + 141)["state"], "ok")
        d2 = self.make(own_ips=["192.168.50.190"])
        d2.process(flow_event("8.8.8.8", 443, dest="192.168.50.190"), now=d2.started + 1)
        self.assertEqual(d2.capture_status(now=d2.started + 2)["state"], "ok")
        # it goes quiet again later
        self.assertEqual(d.capture_status(now=t0 + 400)["state"], "idle")

    def test_no_own_ip_means_no_check(self):
        self.assertEqual(self.make().capture_status()["state"], "unknown")


class ApiTests(unittest.TestCase):
    def setUp(self):
        from flask import Flask
        import settings_api
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "settings.json"
        self.detector = Detector(model_path=None, scaler_path=None, own_ips=["192.168.50.190"])
        app = Flask(__name__)
        settings_api.register(app, lambda: self.detector, str(self.path))
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_get(self):
        r = self.client.get("/api/settings")
        data = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(data["settings"]["own_ips"], ["192.168.50.190"])
        self.assertTrue(data["can_edit"])
        self.assertEqual(data["defaults"]["scan_ports"], 15)

    def test_post_applies_and_saves(self):
        r = self.client.post("/api/settings", json={"scan_ports": 20, "trusted_ips": "192.168.50.1"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(self.detector.get_settings()["scan_ports"], 20)
        self.assertTrue(self.detector.is_ignored("192.168.50.1"))
        self.assertEqual(S.load(self.path)["scan_ports"], 20)

    def test_status(self):
        data = self.client.get("/api/status").get_json()
        self.assertEqual(data["own_ips"], ["192.168.50.190"])
        self.assertFalse(data["auto_own_ip"])
        self.assertIn(data["capture"]["state"], ("starting", "idle", "ok", "other_traffic", "unknown"))

    def test_automatic_mode_overrides_the_typed_address(self):
        with mock.patch.object(S, "detect_lan_ip", return_value="10.1.2.3"):
            r = self.client.post("/api/settings", json={"auto_own_ip": True, "own_ips": "7.7.7.7"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["settings"]["own_ips"], ["10.1.2.3"])
        self.assertTrue(self.detector.auto_own_ip)
        self.assertTrue(S.load(self.path)["auto_own_ip"])

    def test_manual_address_is_kept_when_automatic_is_off(self):
        with mock.patch.object(S, "detect_lan_ip", return_value="10.1.2.3"):
            r = self.client.post("/api/settings", json={"auto_own_ip": False, "own_ips": "7.7.7.7"})
        self.assertEqual(r.get_json()["settings"]["own_ips"], ["7.7.7.7"])
        self.assertFalse(self.detector.auto_own_ip)

    def test_post_invalid_changes_nothing(self):
        r = self.client.post("/api/settings", json={"scan_ports": 20, "trusted_ips": "999.1.1.1"})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(r.get_json()["ok"])
        self.assertEqual(self.detector.get_settings()["scan_ports"], 15)     # unchanged
        self.assertFalse(self.path.exists())

    def test_post_needs_json(self):
        r = self.client.post("/api/settings", data="scan_ports=20", content_type="application/x-www-form-urlencoded")
        self.assertEqual(r.status_code, 415)

    def test_other_device_can_view_but_not_change(self):
        remote = {"REMOTE_ADDR": "192.168.50.77"}
        self.assertEqual(self.client.get("/api/settings", environ_overrides=remote).status_code, 200)
        self.assertFalse(self.client.get("/api/settings", environ_overrides=remote).get_json()["can_edit"])
        r = self.client.post("/api/settings", json={"scan_ports": 20}, environ_overrides=remote)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.detector.get_settings()["scan_ports"], 15)

    def test_odd_host_header_is_refused(self):
        r = self.client.post("/api/settings", json={"scan_ports": 20}, headers={"Host": "evil.example.com:5000"})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
