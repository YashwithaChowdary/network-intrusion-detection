"""Load the NSL-KDD dataset (public benchmark for network intrusion detection).

Files are downloaded once into ./data from the public GitHub mirror
defcom17/NSL_KDD. Each row is one network connection described by 41 features
and a label ('normal' or the name of an attack).
"""
import os
import urllib.request

import pandas as pd

BASE = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
FILES = {"train": "KDDTrain%2B.txt", "test": "KDDTest%2B.txt"}

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]
CATEGORICAL = ["protocol_type", "service", "flag"]


def _download(name, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    req = urllib.request.Request(BASE + FILES[name],
                                 headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(path, "wb") as out:
        out.write(resp.read())


def load(name, folder="data"):
    """Return a DataFrame with a binary column is_attack (1 = attack)."""
    path = os.path.join(folder, "KDD" + ("Train" if name == "train" else "Test") + "+.txt")
    if not os.path.exists(path):
        print(f"Downloading {name} set to {path} ...")
        _download(name, path)
    df = pd.read_csv(path, header=None, names=COLUMNS)
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df.drop(columns=["difficulty"])
