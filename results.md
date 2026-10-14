# Results

Dataset: NSL-KDD. Train 125973 rows, test 22544 rows (KDDTest+, 57% attacks).

| Model | Precision | Recall | F1 | False positive rate | ROC AUC | TP / FN / FP / TN |
|---|---|---|---|---|---|---|
| Isolation Forest (normal-only training, threshold at 5% FPR on held-out normal traffic) | 0.931 | 0.658 | 0.771 | 0.065 | 0.940 | 8442 / 4391 / 628 / 9083 |
| Random Forest (supervised, labelled attacks) | 0.967 | 0.607 | 0.746 | 0.027 | 0.959 | 7796 / 5037 / 266 / 9445 |

## Anomaly detector: share of each attack type flagged (test set)

| Attack | Count | Flagged |
|---|---|---|
| neptune | 4657 | 100% |
| guess_passwd | 1231 | 2% |
| mscan | 996 | 96% |
| warezmaster | 944 | 13% |
| apache2 | 737 | 87% |
| satan | 735 | 100% |
| processtable | 685 | 45% |
| smurf | 665 | 52% |
| back | 359 | 0% |
| snmpguess | 331 | 0% |
| saint | 319 | 70% |
| mailbomb | 293 | 0% |
