import unittest

from backtest_vpn import stats


class StatsTest(unittest.TestCase):
    def test_wilson_known_value(self):
        lo, hi = stats.wilson_interval(8, 10)
        self.assertAlmostEqual(lo, 0.490, places=3)
        self.assertAlmostEqual(hi, 0.943, places=3)

    def test_kappa_and_percentile(self):
        self.assertEqual(stats.cohen_kappa([("a", "a"), ("b", "b")]), 1.0)
        self.assertAlmostEqual(stats.percentile_of([1, 2, 2, 5], 2), 0.75)
        self.assertAlmostEqual(stats.jaccard({1, 2}, {2, 3}), 1/3)
        self.assertIsNone(stats.chapman_estimate(10, 10, 0))

    def test_rule_of_three(self):
        self.assertAlmostEqual(stats.rule_of_three_upper(100), 0.03)


if __name__ == "__main__":
    unittest.main()
