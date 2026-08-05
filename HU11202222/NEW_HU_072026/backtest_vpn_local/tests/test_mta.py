"""Testes para backtest_vpn.mta: parsing JSON, CIDR, dedup e regra."""

import ipaddress
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from backtest_vpn import mta
from backtest_vpn import rules


SAMPLE_JS_INF_CLI_STRUCTURED = (
    '[{"object":{"realm":"/bb","authLevel":0,'
    '"codigoUnicoTransacao":"abc","username":"F4476913"},'
    '"pointer":{"tokens":["sharedState"]}},'
    '{"ipCliente":"10.64.100.176","userAgent":"Mozilla/5.0"}]'
)
SAMPLE_JS_TRUNCATED = (
    '[{"object":{"realm":"/bb","authLevel":0,'
    '"codigoUnicoTransacao":"abc","username":"C1310324","metodosAutentic'
)


class ExtractionTest(unittest.TestCase):
    def test_extract_username_json_and_regex(self):
        self.assertEqual(mta.extract_username(SAMPLE_JS_INF_CLI_STRUCTURED), "F4476913")
        self.assertEqual(mta.extract_username(SAMPLE_JS_TRUNCATED), "C1310324")
        self.assertIsNone(mta.extract_username(""))
        self.assertIsNone(mta.extract_username(None))
        self.assertIsNone(mta.extract_username('{"other":"x"}'))

    def test_extract_ip_cliente(self):
        self.assertEqual(mta.extract_ip_cliente(SAMPLE_JS_INF_CLI_STRUCTURED), "10.64.100.176")
        self.assertIsNone(mta.extract_ip_cliente(SAMPLE_JS_TRUNCATED))
        self.assertIsNone(mta.extract_ip_cliente(None))


class CidrTest(unittest.TestCase):
    def setUp(self):
        self.nets = tuple(ipaddress.ip_network(c) for c in mta.DEFAULT_IP_CIDRS)

    def test_ip_in_networks(self):
        self.assertTrue(mta.ip_in_networks("10.64.100.176", self.nets))
        self.assertTrue(mta.ip_in_networks("172.29.212.150", self.nets))
        self.assertTrue(mta.ip_in_networks("192.168.168.123", self.nets))
        self.assertFalse(mta.ip_in_networks("8.8.8.8", self.nets))
        self.assertFalse(mta.ip_in_networks("172.15.0.1", self.nets))  # abaixo de 172.16/12
        self.assertFalse(mta.ip_in_networks(None, self.nets))
        self.assertFalse(mta.ip_in_networks("not-an-ip", self.nets))
        self.assertFalse(mta.ip_in_networks("10.0.0.1", tuple()))


class DedupTest(unittest.TestCase):
    def test_dedup_by_cd_unco_tran_keeps_earliest(self):
        t0 = datetime(2026, 7, 20, 15, 0, 0)
        rows = [
            {"cd_unco_tran": "u1", "ts_tran": t0 + timedelta(seconds=5), "cd_idfr_mta": 1},
            {"cd_unco_tran": "u1", "ts_tran": t0, "cd_idfr_mta": 2},
            {"cd_unco_tran": "u2", "ts_tran": t0 + timedelta(seconds=1), "cd_idfr_mta": 3},
            {"cd_unco_tran": "null", "ts_tran": t0, "cd_idfr_mta": 4},
            {"cd_unco_tran": "null", "ts_tran": t0, "cd_idfr_mta": 5},
        ]
        out = mta.dedup_matches(rows)
        keys = {r["cd_idfr_mta"] for r in out}
        # u1 -> keeps ts=t0 (id=2); u2 -> id=3; two 'null' rows keep both (fallback key uses cd_idfr_mta)
        self.assertIn(2, keys)
        self.assertIn(3, keys)
        self.assertIn(4, keys)
        self.assertIn(5, keys)
        self.assertNotIn(1, keys)


class LoadConfigTest(unittest.TestCase):
    def test_defaults(self):
        cfg = mta.load_mta_config_from_env(env={})
        self.assertEqual(cfg.schema, "DB2PEP")
        self.assertEqual(cfg.table, "MTA_AUT_CLI_TRAN")
        self.assertEqual(cfg.decision_nodes, mta.DEFAULT_DECISION_NODES)
        self.assertEqual(cfg.delta_minutes, 15)
        self.assertIn(ipaddress.ip_network("10.0.0.0/8"), cfg.ip_networks)

    def test_overrides(self):
        cfg = mta.load_mta_config_from_env(env={
            "MTA_DECISION_NODES": "BBOfdDecisionNode,BBTOTPDecisionNode",
            "PHYSICAL_IP_CIDRS": "10.0.0.0/24,192.168.0.0/16",
            "MTA_DELTA_MINUTES": "5",
            "MTA_MAX_USERS": "50",
            "MTA_USERS_PER_BATCH": "4",
        })
        self.assertEqual(cfg.decision_nodes, ("BBOfdDecisionNode", "BBTOTPDecisionNode"))
        self.assertEqual(len(cfg.ip_networks), 2)
        self.assertEqual(cfg.delta_minutes, 5)
        self.assertEqual(cfg.max_users_per_run, 50)
        self.assertEqual(cfg.users_per_batch, 4)

    def test_rejects_bad_ident(self):
        with self.assertRaises(ValueError):
            mta.load_mta_config_from_env(env={"MTA_TABLE": "invalid; DROP"})


class MatchVpnEventsTest(unittest.TestCase):
    def _fake_conn(self):
        return object()

    def test_match_filters_by_cptv_and_cidr_and_dedups(self):
        cfg = mta.load_mta_config_from_env(env={"MTA_DELTA_MINUTES": "10"})
        vpn_ts = datetime(2026, 7, 20, 15, 0, 0)
        events = {
            "F4476913": [{"ts": vpn_ts, "cptv_ip": "10.161.25.228"}],
            "C1310324": [{"ts": vpn_ts, "cptv_ip": "10.2.217.77"}],
        }

        fake_rows = [
            # F4476913 second flow, physical IP: should match
            {"cd_idfr_mta": 10, "cd_unco_tran": "flow-a", "ts_tran": vpn_ts,
             "nm_etp": "BBOfdDecisionNode", "username": "F4476913",
             "ip_cliente": "10.64.100.176"},
            # Duplicate flow (same cd_unco_tran) -> dedup should keep this one? already have flow-a
            {"cd_idfr_mta": 11, "cd_unco_tran": "flow-a", "ts_tran": vpn_ts + timedelta(seconds=3),
             "nm_etp": "BBPasswordDecisionNode", "username": "F4476913",
             "ip_cliente": "10.64.100.176"},
            # F4476913 same IP as VPN tunnel -> should be filtered out
            {"cd_idfr_mta": 12, "cd_unco_tran": "flow-b", "ts_tran": vpn_ts,
             "nm_etp": "BBOfdDecisionNode", "username": "F4476913",
             "ip_cliente": "10.161.25.228"},
            # C1310324 public IP -> filtered out (not in CIDRs)
            {"cd_idfr_mta": 13, "cd_unco_tran": "flow-c", "ts_tran": vpn_ts,
             "nm_etp": "BBOfdDecisionNode", "username": "C1310324",
             "ip_cliente": "200.1.2.3"},
            # C1310324 private IP -> match
            {"cd_idfr_mta": 14, "cd_unco_tran": "flow-d", "ts_tran": vpn_ts + timedelta(minutes=2),
             "nm_etp": "BBOfdDecisionNode", "username": "C1310324",
             "ip_cliente": "192.168.1.10"},
        ]

        with patch.object(mta, "estimate_pk_window", return_value=(1, 100)), \
             patch.object(mta, "find_mta_matches_for_users", return_value=fake_rows):
            result = mta.match_vpn_events(self._fake_conn(), cfg, events)

        self.assertEqual(len(result["F4476913"]), 1)
        self.assertEqual(result["F4476913"][0]["ip_cliente"], "10.64.100.176")
        self.assertEqual(result["F4476913"][0]["cd_unco_tran"], "flow-a")
        self.assertEqual(len(result["C1310324"]), 1)
        self.assertEqual(result["C1310324"][0]["ip_cliente"], "192.168.1.10")


class RuleWithFakeConnTest(unittest.TestCase):
    def _cfg(self):
        from backtest_vpn import config as cfg_mod
        db2c = cfg_mod.Db2ConnectionConfig("h", 1, "d", "u", "p")
        vpn = cfg_mod.VpnTableConfig("DB2PEP", "AUT_CPTV", "CD_USU_AUT", "TS_TRAN",
                                     "CD_END_LGC_OGM", "CD_END_LGC_CPTV", "NM_DSVO", "CD_IDFC_DSVO")
        return cfg_mod.BacktestConfig(
            db2=db2c, vpn_table=vpn, physical_table=None,
            start=datetime(2026, 7, 20, 14, 0, 0), end=datetime(2026, 7, 20, 16, 0, 0),
            active_window_hours=8, distinct_limit=2, daily_login_limit=10,
            sample_limit=5, output_dir="/tmp", sweep_distinct_limits=[1],
            sweep_daily_limits=[1], sweep_window_hours=[1], stability_granularity="week",
            velocity_minutes=5, dormancy_days=60, seed=1, clean_cohort_min_events=5,
            mta_table=mta.load_mta_config_from_env(env={}),
        )

    def test_case_ok_and_note_contains_users(self):
        cfg = self._cfg()
        vpn_ts = datetime(2026, 7, 20, 15, 0, 0)
        vpn_rows = [
            {"USER_KEY": "F4476913", "VPN_TS": vpn_ts, "CPTV_IP": "10.161.25.228"},
        ]
        matches = {"F4476913": [{
            "ts_vpn": vpn_ts, "cptv_ip": "10.161.25.228",
            "ts_mta": vpn_ts + timedelta(seconds=5),
            "ip_cliente": "10.64.100.176",
            "cd_unco_tran": "flow-a", "nm_etp": "BBOfdDecisionNode",
        }]}

        with patch("backtest_vpn.rules.fetch_all", return_value=vpn_rows), \
             patch("backtest_vpn.rules.mta_mod.match_vpn_events", return_value=matches):
            result = rules.run_vpn_plus_mta_physical_case(None, cfg)

        self.assertEqual(result.name, "vpn_ativa_com_login_em_rede_fisica_mta")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.count, 1)
        self.assertEqual(len(result.sample), 1)
        self.assertIn("F4476913", result.sample[0]["USER_KEY"])
        self.assertIn("Usuários distintos sinalizados: 1", result.note)

    def test_case_skipped_when_no_mta_config(self):
        cfg = self._cfg()
        cfg = cfg.__class__(**{**cfg.__dict__, "mta_table": None})
        result = rules.run_vpn_plus_mta_physical_case(None, cfg)
        self.assertEqual(result.status, "skipped")


if __name__ == "__main__":
    unittest.main()
