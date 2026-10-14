# Network Intrusion & Anomaly Detection on NSL-KDD

A Python project that detects malicious network connections in the public NSL-KDD dataset and reports honest metrics on its test set.

Two approaches are compared:

1. **Anomaly detector (Isolation Forest).** Trained on normal traffic only, so it never sees an attack. It flags connections that look unlike normal traffic. The decision threshold is set on held-out normal training traffic so that about 5% of normal connections are flagged. The test set is never used to choose the threshold.
2. **Supervised baseline (Random Forest).** Trained on labelled normal and attack traffic, for comparison.

## Data

[NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) is a cleaned version of the KDD Cup 1999 intrusion data. Each row is one network connection with 41 features. This project uses the standard split: `KDDTrain+` (125,973 rows) for training and `KDDTest+` (22,544 rows) for testing. The test set contains attack types that do not appear in training, which makes it a realistic test of generalisation. The files are downloaded automatically into `data/` the first time you run it.

## Run

    py -m pip install pandas numpy scikit-learn
    py run.py

This writes `results.md`. Training takes under a minute on a normal laptop.

## Test

    py -m unittest test_detect.py

The tests use small synthetic data and need no download.

## Results

NSL-KDD `KDDTest+` (22,544 connections, 57% attacks), one run, fixed random seed.

| Model | Precision | Recall | F1 | False positive rate | ROC AUC |
|---|---|---|---|---|---|
| Isolation Forest (normal-only, 5% FPR threshold) | 0.931 | 0.658 | 0.771 | 0.065 | 0.940 |
| Random Forest (supervised) | 0.967 | 0.607 | 0.746 | 0.027 | 0.959 |

What the numbers show:

- The unsupervised detector, which never saw an attack, reached a slightly higher F1 than the supervised forest on this test set. The forest ranks traffic better (higher ROC AUC) and raises fewer false alarms, but it misses more attacks that are new in the test set.
- The detector is strong on volume and probe attacks (`neptune` 100%, `satan` 100%, `mscan` 96%) and weak on attacks that look like normal sessions (`guess_passwd` 2%, `back` 0%, `snmpguess` 0%, `mailbomb` 0%). Per-attack results are in `results.md`.
- The measured false positive rate (6.5%) is close to the 5% the threshold was set for, so calibration on held-out normal traffic roughly transferred to the test set.

## Limits

- NSL-KDD is derived from 1998 lab traffic. It is a standard benchmark, not a model of modern production networks.
- One run with fixed seeds, no cross-validation and no hyperparameter tuning. Exact numbers can differ slightly between library versions.
- Metrics are for the binary question "normal or attack". The anomaly detector does not name the attack type.
- No claim is made that this would work on real company traffic.
