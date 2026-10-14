"""Anomaly detection and a supervised baseline for network connections."""
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from data import CATEGORICAL

SEED = 42


def feature_columns(df):
    return [c for c in df.columns if c not in ("label", "is_attack")]


def preprocessor(df):
    numeric = [c for c in feature_columns(df) if c not in CATEGORICAL]
    return ColumnTransformer([
        ("num", StandardScaler(), numeric),
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
    ])


def metrics(y_true, y_pred, y_score=None):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {"precision": precision_score(y_true, y_pred, zero_division=0),
           "recall": recall_score(y_true, y_pred, zero_division=0),
           "f1": f1_score(y_true, y_pred, zero_division=0),
           "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
           "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    if y_score is not None:
        out["roc_auc"] = roc_auc_score(y_true, y_score)
    return out


def pick_threshold(normal_scores, target_fpr=0.05):
    """Score above which a connection is called an attack.

    Chosen on held-out NORMAL training traffic only, so that about
    target_fpr of normal connections are flagged. The test set is never used.
    """
    return float(np.quantile(normal_scores, 1 - target_fpr))


def anomaly_detector(train, test, target_fpr=0.05):
    """Train on normal traffic only, flag whatever looks unlike it."""
    normal = train[train["is_attack"] == 0]
    fit_part, calib_part = train_test_split(normal, test_size=0.2, random_state=SEED)
    model = Pipeline([("prep", preprocessor(train)),
                      ("iso", IsolationForest(n_estimators=200, random_state=SEED,
                                              n_jobs=-1))])
    cols = feature_columns(train)
    model.fit(fit_part[cols])
    # higher score = more anomalous
    score = lambda d: -model.score_samples(d[cols])
    threshold = pick_threshold(score(calib_part), target_fpr)
    test_score = score(test)
    pred = (test_score > threshold).astype(int)
    return metrics(test["is_attack"], pred, test_score), threshold, test_score


def supervised_baseline(train, test):
    """Random forest trained on labelled attacks, for comparison."""
    cols = feature_columns(train)
    model = Pipeline([("prep", preprocessor(train)),
                      ("rf", RandomForestClassifier(n_estimators=100, random_state=SEED,
                                                    n_jobs=-1))])
    model.fit(train[cols], train["is_attack"])
    prob = model.predict_proba(test[cols])[:, 1]
    pred = (prob > 0.5).astype(int)
    return metrics(test["is_attack"], pred, prob)


def recall_by_attack(test, scores, threshold):
    """Share of each attack type that the anomaly detector catches."""
    flagged = scores > threshold
    rows = []
    for name, grp in test[test["is_attack"] == 1].groupby("label"):
        rows.append((name, len(grp), float(flagged[grp.index].mean())))
    return sorted(rows, key=lambda r: -r[1])
