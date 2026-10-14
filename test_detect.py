import unittest

import numpy as np
import pandas as pd

from data import COLUMNS
from detect import (anomaly_detector, feature_columns, metrics, pick_threshold,
                    preprocessor)


def tiny_frame(n_normal, n_attack, seed):
    """Synthetic connections: attacks have huge byte counts and many errors."""
    rng = np.random.default_rng(seed)
    cols = [c for c in COLUMNS if c != "difficulty"]
    rows = []
    for attack in [0] * n_normal + [1] * n_attack:
        r = {c: 0.0 for c in cols}
        r.update({"protocol_type": "tcp", "service": "http", "flag": "SF",
                  "label": "neptune" if attack else "normal",
                  "src_bytes": rng.normal(200, 20) + attack * 5000,
                  "dst_bytes": rng.normal(500, 50),
                  "serror_rate": 0.9 if attack else 0.0,
                  "count": rng.integers(1, 5) + attack * 400})
        rows.append(r)
    df = pd.DataFrame(rows, columns=cols)
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df


class MetricTests(unittest.TestCase):
    def test_counts_and_rates(self):
        m = metrics([0, 0, 1, 1], [0, 1, 1, 0])
        self.assertEqual((m["tp"], m["fn"], m["fp"], m["tn"]), (1, 1, 1, 1))
        self.assertAlmostEqual(m["precision"], 0.5)
        self.assertAlmostEqual(m["false_positive_rate"], 0.5)

    def test_no_division_error_when_nothing_predicted(self):
        m = metrics([0, 1], [0, 0])
        self.assertEqual(m["precision"], 0.0)

    def test_threshold_flags_about_target_share_of_normal(self):
        scores = np.linspace(0, 1, 1000)
        t = pick_threshold(scores, 0.05)
        self.assertAlmostEqual((scores > t).mean(), 0.05, places=2)


class PipelineTests(unittest.TestCase):
    def test_unseen_category_does_not_crash(self):
        train = tiny_frame(50, 5, 1)
        test = tiny_frame(5, 1, 2)
        test["service"] = "never_seen_before"
        prep = preprocessor(train).fit(train[feature_columns(train)])
        self.assertEqual(prep.transform(test[feature_columns(test)]).shape[0], 6)

    def test_detector_finds_obvious_attacks_without_flagging_all_normals(self):
        train = tiny_frame(400, 40, 3)
        test = tiny_frame(100, 30, 4)
        m, _, _ = anomaly_detector(train, test, target_fpr=0.05)
        self.assertGreater(m["recall"], 0.9)
        self.assertLess(m["false_positive_rate"], 0.2)

    def test_threshold_is_not_taken_from_the_test_set(self):
        train = tiny_frame(400, 40, 5)
        test_a = tiny_frame(100, 30, 6)
        test_b = tiny_frame(100, 0, 7)       # no attacks at all
        _, t_a, _ = anomaly_detector(train, test_a)
        _, t_b, _ = anomaly_detector(train, test_b)
        self.assertEqual(t_a, t_b)


if __name__ == "__main__":
    unittest.main()
