"""
Clustering Prototype (InnoLab 3, Sprint 2)
==========================================
First clustering run on the output of ml_features.py, as discussed with the supervisor:
  - K-Means and DBSCAN (unsupervised, no malicious/benign labels)
  - time-based train/test split inside the sample (first 70 % train, last 30 % test, no shuffling)
  - 98 % of sessions are exact duplicates, so the models are fitted on unique BEHAVIOR FAMILIES,
    weighted by how many sessions each family has (otherwise one bot script dominates everything)
  - new (test) sessions are assigned to the learned clusters; far-away ones are flagged as novel
  - clusters are compared with the rule-based intent profiles from db_analyzer.py

Requires: pip install pandas scikit-learn matplotlib

Usage:
    python scripts/ml_cluster.py          # chooses k by silhouette score
    python scripts/ml_cluster.py --k 6    # fixed number of clusters

Outputs in scripts-out/ml/:
    cluster_report.md       readable summary (paste into the report / project diary)
    k_selection.csv/.png    elbow (inertia) and silhouette per k
    clusters_pca.png        2D view of the families (PCA), size = number of sessions
    clusters_tsne.png       2D view with t-SNE
    family_clusters.csv     one row per behavior family with K-Means and DBSCAN cluster
    session_clusters.csv    one row per session (train + test) with cluster and novelty flag
"""
import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.cluster import DBSCAN, KMeans  # noqa: E402
from sklearn.decomposition import PCA, TruncatedSVD  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.manifold import TSNE  # noqa: E402
from sklearn.metrics import adjusted_rand_score, silhouette_score  # noqa: E402
from sklearn.neighbors import NearestNeighbors  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from db_analyzer import OUT_PATH, INTENT_ORDER  # noqa: E402

ML_DIR = Path(OUT_PATH).parent / "ml"
TRAIN_SHARE = 0.7
SEED = 42

NUMERIC = ["n_commands", "n_unique_commands", "duration_s", "mean_gap_s", "repetition_ratio",
           "max_cmd_len", "n_auth", "n_auth_success", "n_file_downloads"]
INTENTS = [f"intent_{i}" for i in INTENT_ORDER]
CLIENTS = ["go", "libssh", "paramiko", "asyncssh", "jsch", "putty", "dropbear", "openssh", "other", "unknown"]
CLIENT_COLS = [f"client_{c}" for c in CLIENTS]
TOKEN_PATTERN = r"<\w+>|[A-Za-z_./-][\w./-]*"


def family_table(df):
    """One row per behavior family: median numbers, share of intent flags and SSH clients, weight = sessions."""
    g = df.groupby("behavior", sort=False)
    fam = g[NUMERIC].median()
    fam[INTENTS] = g[INTENTS].mean()
    clients = pd.crosstab(df["behavior"], df["client"]).reindex(columns=CLIENTS, fill_value=0)
    fam[CLIENT_COLS] = clients.div(clients.sum(axis=1), axis=0).reindex(fam.index).to_numpy()
    fam["sessions"] = g.size()
    fam["ips"] = g["src_ip"].nunique()
    fam["first_seen"] = g["start"].min()
    return fam


class Encoder:
    """Numbers (log-scaled) + intent/client shares + text of the family (TF-IDF -> SVD), then standardised."""

    def fit(self, fam):
        self.tfidf = TfidfVectorizer(token_pattern=TOKEN_PATTERN, min_df=1).fit(fam.index)
        n_comp = max(1, min(15, len(fam) - 1, len(self.tfidf.vocabulary_) - 1))
        self.svd = TruncatedSVD(n_components=n_comp, random_state=SEED).fit(self.tfidf.transform(fam.index))
        self.scaler = StandardScaler().fit(self._raw(fam), sample_weight=fam["sessions"])
        return self

    def _raw(self, fam):
        text = self.svd.transform(self.tfidf.transform(fam.index))
        return np.hstack([np.log1p(fam[NUMERIC].to_numpy(float)), fam[INTENTS + CLIENT_COLS].to_numpy(float), text])

    def transform(self, fam):
        return self.scaler.transform(self._raw(fam))


def choose_k(X, w, k_fixed):
    rows = []
    for k in range(2, max(2, min(12, len(X) // 2)) + 1):
        km = KMeans(n_clusters=k, n_init=10, random_state=SEED).fit(X, sample_weight=w)
        sil = silhouette_score(X, km.labels_) if len(set(km.labels_)) > 1 else float("nan")
        rows.append({"k": k, "inertia": round(km.inertia_, 1), "silhouette": round(sil, 4)})
    ks = pd.DataFrame(rows)
    if k_fixed:
        return k_fixed, ks
    pool = ks[ks.k >= 3] if (ks.k >= 3).any() else ks
    return int(pool.loc[pool.silhouette.idxmax(), "k"]), ks


def short(text, n=110):
    text = str(text).replace("|", "\\|")
    return text if len(text) <= n else text[:n] + "…"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", default=str(ML_DIR / "session_features.csv"))
    ap.add_argument("--k", type=int, default=0, help="number of K-Means clusters (default: best silhouette)")
    ap.add_argument("--eps", type=float, default=0, help="DBSCAN eps (default: median 5-NN distance)")
    ap.add_argument("--min-samples", type=int, default=10, help="DBSCAN: sessions needed for a dense region")
    args = ap.parse_args()

    df = pd.read_csv(args.features, keep_default_na=False, dtype={"session_id": str, "src_ip": str})
    df = df.sort_values("start").reset_index(drop=True)
    cut = int(len(df) * TRAIN_SHARE)
    train, test = df.iloc[:cut].copy(), df.iloc[cut:].copy()
    print(f"Sessions: {len(df):,}  train {len(train):,} (until {train.start.iloc[-1][:19]})  test {len(test):,}")

    # ---------- fit on unique behavior families of the training period ----------
    fam = family_table(train)
    if len(fam) < 4:
        sys.exit(f"Only {len(fam)} behavior families in the training part - not enough to cluster.")
    enc = Encoder().fit(fam)
    X, w = enc.transform(fam), fam["sessions"].to_numpy(float)
    print(f"Behavior families in train: {len(fam):,} (from {len(train):,} sessions)")

    k, ks = choose_k(X, w, args.k)
    km = KMeans(n_clusters=k, n_init=10, random_state=SEED).fit(X, sample_weight=w)
    fam["kmeans"] = km.labels_
    fam["dist"] = np.linalg.norm(X - km.cluster_centers_[km.labels_], axis=1)
    print(f"K-Means: k = {k} (silhouette {ks.set_index('k').loc[k, 'silhouette']})")

    # DBSCAN: eps from the 90th percentile of the k-nearest-neighbour distance; weights count as sessions
    min_samples = args.min_samples
    nn_k = min(5, len(X) - 1)
    d = NearestNeighbors(n_neighbors=nn_k + 1).fit(X).kneighbors(X)[0][:, -1]
    eps = args.eps or float(np.median(d)) or 0.5
    fam["dbscan"] = DBSCAN(eps=eps, min_samples=min_samples).fit(X, sample_weight=w).labels_
    n_db = len(set(fam.dbscan) - {-1})
    noise = fam[fam.dbscan == -1]
    print(f"DBSCAN: eps = {eps:.2f}, {n_db} clusters, {len(noise)} rare families ({int(noise.sessions.sum())} sessions) as noise")

    # ---------- assign test sessions (time-based hold-out) ----------
    threshold = float(np.percentile(fam["dist"], 95))
    tfam = family_table(test)
    Xt = enc.transform(tfam)
    tfam["kmeans"] = km.predict(Xt)
    tfam["dist"] = np.linalg.norm(Xt - km.cluster_centers_[tfam["kmeans"]], axis=1)
    tfam["seen_in_train"] = tfam.index.isin(fam.index)
    # only behavior that did not exist in train can be "new"
    tfam["novel"] = ~tfam["seen_in_train"] & (tfam["dist"] > threshold)

    train["split"], test["split"] = "train", "test"
    train = train.join(fam[["kmeans", "dbscan", "dist"]], on="behavior")
    test = test.join(tfam[["kmeans", "dist", "seen_in_train", "novel"]], on="behavior")
    train["seen_in_train"], train["novel"] = True, False
    test["dbscan"] = np.nan

    unseen = test[~test.seen_in_train]
    print(f"Test: {len(test):,} sessions, {len(unseen):,} ({len(unseen) / len(test):.1%}) with a behavior family "
          f"never seen in train, {int(test.novel.sum()):,} flagged as far from all clusters")

    # ---------- compare with rule-based baseline ----------
    ari = adjusted_rand_score(train["intent_profile"], train["kmeans"])

    # ---------- outputs ----------
    ML_DIR.mkdir(parents=True, exist_ok=True)
    ks.to_csv(ML_DIR / "k_selection.csv", index=False)
    fam_out = pd.concat([fam.assign(split="train"), tfam[~tfam.seen_in_train].assign(split="test_only")])
    fam_out.to_csv(ML_DIR / "family_clusters.csv", index_label="behavior")
    cols = ["session_id", "src_ip", "src_country", "start", "split", "kmeans", "dbscan", "dist",
            "seen_in_train", "novel", "intent_profile", "client", "behavior"]
    pd.concat([train, test])[cols].to_csv(ML_DIR / "session_clusters.csv", index=False)

    fig, ax = plt.subplots(1, 2, figsize=(10, 4))
    ax[0].plot(ks.k, ks.inertia, "o-")
    ax[0].set(title="Elbow (inertia)", xlabel="k")
    ax[1].plot(ks.k, ks.silhouette, "o-", color="tab:orange")
    ax[1].axvline(k, ls="--", c="grey")
    ax[1].set(title="Silhouette score", xlabel="k")
    fig.tight_layout()
    fig.savefig(ML_DIR / "k_selection.png", dpi=150)
    plt.close(fig)

    sizes = 15 + 25 * np.log1p(fam["sessions"])
    p2 = PCA(n_components=2, random_state=SEED).fit(X)
    new_mask = ~tfam.seen_in_train.to_numpy()
    for name, pts, pts_test in (
        ("pca", p2.transform(X), p2.transform(Xt[new_mask]) if new_mask.any() else None),
        ("tsne", TSNE(n_components=2, perplexity=max(2, min(30, (len(X) - 1) // 3)), random_state=SEED,
                      init="pca").fit_transform(X), None),
    ):
        fig, axis = plt.subplots(figsize=(8, 6))
        sc = axis.scatter(pts[:, 0], pts[:, 1], c=fam["kmeans"], s=sizes, cmap="tab10", alpha=0.75, edgecolors="none")
        axis.add_artist(axis.legend(*sc.legend_elements(), title="cluster", loc="upper right"))
        if pts_test is not None and len(pts_test):
            axis.scatter(pts_test[:, 0], pts_test[:, 1], marker="x", c="black", s=30, label="new family in test period")
            axis.legend(loc="lower left")
        axis.set_title(f"Cowrie behavior families - K-Means k={k} ({name.upper()}), size = sessions")
        fig.tight_layout()
        fig.savefig(ML_DIR / f"clusters_{name}.png", dpi=150)
        plt.close(fig)

    # ---------- readable report ----------
    L = ["# Clustering Prototype - Results", "",
         f"- Sample: {len(df):,} Cowrie command sessions ({df.start.iloc[0][:10]} to {df.start.iloc[-1][:10]}), "
         f"time-based split {TRAIN_SHARE:.0%}/{1 - TRAIN_SHARE:.0%} (no shuffling)",
         f"- Train: {len(train):,} sessions -> **{len(fam):,} behavior families** (models are fitted on families, weighted by sessions)",
         f"- K-Means: **k = {k}**, silhouette {ks.set_index('k').loc[k, 'silhouette']}",
         f"- DBSCAN: eps {eps:.2f}, min_samples {min_samples} sessions -> {n_db} clusters, "
         f"{len(noise)} rare families ({int(noise.sessions.sum())} sessions) marked as noise",
         f"- Test: {len(test):,} sessions; {len(unseen):,} ({len(unseen) / len(test):.1%}) use a family never seen in train; "
         f"{int(test.novel.sum()):,} sessions are far from every cluster (distance > 95th percentile of train)",
         f"- Agreement with rule-based intent profiles (Adjusted Rand Index): **{ari:.2f}** "
         "(1 = same grouping, 0 = unrelated)", "",
         "## K-Means clusters", "",
         "| Cluster | Sessions | Share | Families | IPs | Med. cmds | Med. gap s | Top intents | Top clients | Biggest family |",
         "|---:|---:|---:|---:|---:|---:|---:|:---|:---|:---|"]
    for c in range(k):
        s, f_c = train[train.kmeans == c], fam[fam.kmeans == c]
        intents = s[INTENTS].mean().sort_values(ascending=False)
        top_int = ", ".join(f"{i[7:]} {v:.0%}" for i, v in intents.items() if v >= 0.2) or "none"
        top_cli = ", ".join(f"{n} {v:.0%}" for n, v in s.client.value_counts(normalize=True).head(2).items())
        L.append(f"| {c} | {len(s):,} | {len(s) / len(train):.1%} | {len(f_c)} | {s.src_ip.nunique():,} | "
                 f"{s.n_commands.median():g} | {s.mean_gap_s.median():g} | {top_int} | {top_cli} | "
                 f"`{short(f_c.sort_values('sessions').index[-1], 90)}` |")
    L += ["", "## Clusters vs. rule-based intent profiles (train sessions)", "",
          pd.crosstab(train.intent_profile, train.kmeans).to_markdown() if _has_tabulate() else
          "```\n" + pd.crosstab(train.intent_profile, train.kmeans).to_string() + "\n```", "",
          "## Rare behavior (DBSCAN noise, top 10 by sessions)", ""]
    for b, r in noise.sort_values("sessions", ascending=False).head(10).iterrows():
        L.append(f"- {int(r.sessions)} sessions, {int(r.ips)} IPs, K-Means cluster {int(r.kmeans)}: `{short(b)}`")
    L += ["", "## New behavior in the test period (families never seen in train, top 10)", ""]
    for b, r in tfam[~tfam.seen_in_train].sort_values("sessions", ascending=False).head(10).iterrows():
        flag = " **far from all clusters**" if r.novel else ""
        L.append(f"- {int(r.sessions)} sessions -> cluster {int(r.kmeans)}{flag}: `{short(b)}`")
    L += ["", "*Clusters are groups of similar behavior, not proof that the same actor is behind them. "
          "Intent profiles are heuristics from db_analyzer.py, not ground truth.*"]
    (ML_DIR / "cluster_report.md").write_text("\n".join(L), encoding="utf-8")
    print(f"Done. Results in {ML_DIR}")


def _has_tabulate():
    try:
        import tabulate  # noqa: F401
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    main()
