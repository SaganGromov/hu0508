import json
import re
import unittest

from backtest_vpn import htmlreport


def fixture_bundle():
    base_rule = {
        "name": "ips_distintos_acima_do_limite", "flagged": 2, "alert_rate": 0.02,
        "percentile_extremity": {"median": 0.99, "min": 0.95},
        "precision_ceiling": [{"pi": 0.001, "ceiling": 0.05, "assumptions": ["fraud prevalence <= 0.001"]}],
        "threshold_sweep": [{"threshold": 1, "flagged": 3}, {"threshold": 2, "flagged": 2}, {"threshold": 3, "flagged": 1}],
        "suggested_threshold": {"threshold": 2, "note": "maior segunda diferenca"},
        "temporal_stability": {"buckets": [{"bucket": "2026-20", "flagged": 1}], "cv": 0.0, "verdict": "stable"},
        "negative_control": {"fpr_bound_wilson95_upper": 0.01, "status": "bounded", "assumptions": ["cohort fraud prevalence ~ 0"]},
        "proxy_agreement": {"admissible_proxies": ["P3", "P4"], "agreement_precision_surrogate": {"value": 0.5, "ci95": [0.1, 0.9]}, "agreement_recall_surrogate": {"value": 0.5, "ci95": [0.1, 0.9]}, "status": "estimated", "assumptions": ["proxy"]},
        "injected_recall": {"status": "not_run", "value": None},
        "adjudicated_precision": {"status": "not_run", "value": None},
        "true_rates": "not_available_without_validated_labels",
        "status_tags": {"flagged": "measured", "alert_rate": "measured"},
    }
    rules = {"R1": dict(base_rule), "R2": dict(base_rule), "R3": dict(base_rule), "R4": dict(base_rule), "R5": dict(base_rule)}
    rules["R5"].update({"status": "skipped", "flagged": 0, "alert_rate": 0.0, "threshold_sweep": [], "note": "nao configurada"})
    return {
        "bundle_version": 1, "methodology_version": "next-best-thing/1.0", "generated_at": "2026-07-20 11:20:00",
        "git_commit": "abc", "parameters": {"start": "2026-05-07", "end": "2026-07-21", "credentials_file": "/secret/path", "jdbc_url": "jdbc:db2://host"},
        "summary": {"metrics": {"total_events_analyzed": 10, "total_users_analyzed": 5}},
        "rules": rules, "cross_rule": {"overlap_matrix": [{"rule": "R1", "R1": 2}], "convergent_total": 1, "convergent_users": [{"user": "U-abcdef123456", "rules": ["R1", "R4"]}], "lincoln_petersen": {"population_estimate": 3, "union_recall_estimate": 0.5}},
        "limitations": ["not_available_without_validated_labels"],
    }


class VerdictTest(unittest.TestCase):
    def test_outcomes_and_kappa_cap(self):
        high = {"adjudicated_precision": {"value": .8, "ci95": [.5, .9]}, "injected_recall": {"value": .9}, "negative_control": {"fpr_bound_wilson95_upper": .01}, "temporal_stability": {"verdict": "stable"}, "kappa": .4}
        self.assertEqual(htmlreport.verdict(high)[0], "alta")
        capped = dict(high); capped["reviewer_reliability"] = "low"
        self.assertEqual(htmlreport.verdict(capped)[0], "média")
        low = dict(high); low["negative_control"] = {"fpr_bound_wilson95_upper": .06}
        self.assertEqual(htmlreport.verdict(low)[0], "baixa")
        indef = {"adjudicated_precision": {"status": "not_run"}, "injected_recall": {"status": "not_run"}}
        self.assertEqual(htmlreport.verdict(indef)[0], "indefinida")
        medium = dict(high); medium["kappa"] = .2
        self.assertEqual(htmlreport.verdict(medium)[0], "média")


class HtmlReportTest(unittest.TestCase):
    def test_fragment_constraints_and_json(self):
        bundle = fixture_bundle()
        frag = htmlreport.render_fragment(bundle, "20260720_112200")
        self.assertNotIn("<html", frag.lower())
        self.assertNotIn("<body", frag.lower())
        self.assertNotIn("http://", frag)
        self.assertNotIn("https://", frag)
        self.assertIsNone(re.search(r'class="(?!vpnbt-)', frag))
        self.assertIn("not_available_without_validated_labels", frag)
        m = re.search(r'<script type="application/json" class="vpnbt-data">(.*?)</script>', frag, re.S)
        self.assertIsNotNone(m)
        data = json.loads(m.group(1))
        self.assertNotIn("credentials_file", data["parameters"])
        self.assertEqual(frag, htmlreport.render_fragment(bundle, "20260720_112200"))


if __name__ == "__main__":
    unittest.main()
