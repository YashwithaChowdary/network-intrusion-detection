"""Train and evaluate on NSL-KDD, then write results.md.

    py run.py
"""
import time

from data import load
from detect import anomaly_detector, recall_by_attack, supervised_baseline


def row(name, m):
    return (f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
            f"{m['false_positive_rate']:.3f} | {m.get('roc_auc', float('nan')):.3f} | "
            f"{m['tp']} / {m['fn']} / {m['fp']} / {m['tn']} |")


def main():
    t0 = time.time()
    train, test = load("train"), load("test")
    print(f"train {len(train)} rows ({train['is_attack'].mean():.0%} attacks), "
          f"test {len(test)} rows ({test['is_attack'].mean():.0%} attacks)")

    print("Anomaly detector (Isolation Forest, trained on normal traffic only) ...")
    iso, threshold, scores = anomaly_detector(train, test)
    print("Supervised baseline (Random Forest) ...")
    rf = supervised_baseline(train, test)

    lines = ["# Results", "",
             f"Dataset: NSL-KDD. Train {len(train)} rows, test {len(test)} rows "
             f"(KDDTest+, {test['is_attack'].mean():.0%} attacks).", "",
             "| Model | Precision | Recall | F1 | False positive rate | ROC AUC | TP / FN / FP / TN |",
             "|---|---|---|---|---|---|---|",
             row("Isolation Forest (normal-only training, threshold at 5% FPR on held-out normal traffic)", iso),
             row("Random Forest (supervised, labelled attacks)", rf),
             "", "## Anomaly detector: share of each attack type flagged (test set)", "",
             "| Attack | Count | Flagged |", "|---|---|---|"]
    for name, n, share in recall_by_attack(test, scores, threshold)[:12]:
        lines.append(f"| {name} | {n} | {share:.0%} |")
    text = "\n".join(lines) + "\n"
    print("\n" + text)
    open("results.md", "w", encoding="utf-8").write(text)
    print(f"Saved results.md ({time.time() - t0:.0f} s)")


if __name__ == "__main__":
    main()
