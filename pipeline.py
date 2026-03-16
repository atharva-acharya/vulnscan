#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pipeline.py — Hybrid AI Framework for Vulnerability Prioritisation & Threat Attribution

Two-stage pipeline:
  Stage 1 : LightGBM intrusion detection on CIC-IDS-2017 / CSE-CIC-IDS-2018 / UNSW-NB15
  Stage 2 : Vulnerability prioritisation & MITRE ATT&CK enrichment on Nessus-like findings

Usage:
    # Full pipeline (Stage 1 + Stage 2)
    python pipeline.py --ids-dir ./data/cic-ids-2017 --nessus-csv ./data/findings.csv

    # Stage 2 only (if alerts already exist)
    python pipeline.py --nessus-csv ./data/findings.csv --alerts ./outputs/alerts_stage1.csv --skip-stage1

    # Demo mode (generates a tiny synthetic dataset and runs end-to-end)
    python pipeline.py --demo
"""

import argparse
import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")           # headless — no display needed
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from lightgbm import LGBMClassifier

# ──────────────────────────────────────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────────────────────────────────────
DEFAULT_OUTPUT_DIR    = "./outputs"
STAGE1_SUBSAMPLE      = 150_000
STAGE1_TEST_SIZE      = 0.20
STAGE2_TRAIN_SAMPLE   = 350_000
STAGE2_TEST_SIZE      = 0.30

SERVICE_POOL = ["http","https","ssh","ftp","dns","rdp","smb","mysql","mssql","ldap"]
PROTO_POOL   = ["tcp","udp"]

TTP_MAPPING = {
    "T1110.001": ["brute force","ftp-patator","ssh-patator"],
    "T1498":     ["dos","ddos","hulk","goldeneye","slowloris","slowhttptest"],
    "T1190":     ["heartbleed"],
    "T1059.007": ["xss"],
    "T1505":     ["sql injection"],
    "T1071":     ["infiltration"],
    "T1583":     ["bot"],
    "T1046":     ["portscan"],
}
REMEDIATION_ADVICE = {
    "T1110.001": "Implement account lockout policies and MFA.",
    "T1498":     "Deploy WAF / DDoS mitigation and rate limiting.",
    "T1190":     "Patch the vulnerable public-facing application immediately.",
    "T1059.007": "Sanitize inputs; enable a WAF with XSS rules.",
    "T1505":     "Use parameterized queries and input validation.",
    "T1071":     "Monitor egress for unusual destinations; block C2.",
    "T1583":     "Harden perimeter; block known C2 IPs/domains.",
    "T1046":     "Throttle or block scanning sources; tighten ACLs.",
}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def read_csv(path: str) -> pd.DataFrame:
    """UTF-8 with latin-1 fallback."""
    try:
        return pd.read_csv(path, encoding="utf-8", low_memory=False)
    except UnicodeDecodeError:
        return pd.read_csv(path, encoding="latin-1", low_memory=False)

def list_csvs(folder: str):
    return [os.path.join(folder, f)
            for f in os.listdir(folder) if f.lower().endswith(".csv")]

def build_lightgbm(**kwargs) -> LGBMClassifier:
    """GPU with automatic CPU fallback."""
    base = dict(random_state=42, n_estimators=300, learning_rate=0.1, n_jobs=-1)
    base.update(kwargs)
    try:
        clf = LGBMClassifier(**{**base, "device": "gpu"})
        clf.get_params()
        return clf
    except Exception:
        return LGBMClassifier(**base)

def map_ttp(desc: str):
    if not isinstance(desc, str):
        return "TTP Not Found", "No specific advice available."
    s = desc.lower()
    for ttp, kws in TTP_MAPPING.items():
        if any(k in s for k in kws):
            return ttp, REMEDIATION_ADVICE.get(ttp, "No specific advice available.")
    return "TTP Not Found", "No specific advice available."

def band_sla(risk: float):
    if risk >= 0.80: return "P1", "Patch within 24–48 h"
    if risk >= 0.60: return "P2", "Patch within 7 days"
    if risk >= 0.40: return "P3", "Patch within 14 days"
    if risk >= 0.20: return "P4", "Patch within 30 days"
    return "P5", "Monitor / schedule patch"

# ──────────────────────────────────────────────────────────────────────────────
# Demo dataset (tiny, in-memory — no downloads required)
# ──────────────────────────────────────────────────────────────────────────────
def make_demo_data(out_dir: str):
    """Generate a minimal synthetic dataset for smoke-testing the pipeline."""
    rng = np.random.default_rng(42)
    n   = 5_000

    # --- IDS data (mimics CIC-IDS-2017 columns) ---
    ids_df = pd.DataFrame({
        "Destination Port": rng.integers(1, 65535, n),
        "Flow Duration":    rng.integers(0, 1_000_000, n),
        "Total Fwd Packets":rng.integers(1, 500, n),
        "Total Backward Packets": rng.integers(0, 500, n),
        "Flow Bytes/s":     rng.uniform(0, 1e6, n),
        "Flow Packets/s":   rng.uniform(0, 1e4, n),
        "Label": rng.choice(["BENIGN","DoS Hulk","PortScan"], n, p=[0.7,0.2,0.1]),
        "Source IP": [f"192.168.1.{rng.integers(1,50)}" for _ in range(n)],
    })
    ids_path = os.path.join(out_dir, "demo_ids.csv")
    ids_df.to_csv(ids_path, index=False)

    # --- Nessus-like findings ---
    ips = ids_df["Source IP"].unique()
    vuln_df = pd.DataFrame({
        "Source IP":    rng.choice(ips, n),
        "cvss":         rng.uniform(0, 10, n).round(1),
        "severity":     rng.integers(0, 5, n),
        "exploit_available": rng.integers(0, 2, n),
        "description_len": rng.integers(50, 700, n),
        "age_days":     rng.integers(0, 200, n),
        "persistence_scans": np.ones(n, int),
        "port":         rng.integers(1, 9000, n),
        "proto":        rng.choice(PROTO_POOL, n),
        "svc_name":     rng.choice(SERVICE_POOL, n),
        "remediation_priority": rng.integers(1, 6, n),
        "asset_criticality":    rng.integers(1, 6, n),
        "internet_exposed":     rng.integers(0, 2, n),
    })
    vuln_path = os.path.join(out_dir, "demo_findings.csv")
    vuln_df.to_csv(vuln_path, index=False)

    print(f"[demo] Created {ids_path} and {vuln_path}")
    return ids_path, vuln_path

# ──────────────────────────────────────────────────────────────────────────────
# Stage 1 — Intrusion Detection
# ──────────────────────────────────────────────────────────────────────────────
def stage1_run(ids_dir: str, output_dir: str) -> str:
    """
    Train a LightGBM binary classifier on IDS network flow data.
    Returns path to the exported alerts CSV.
    """
    print("\n" + "="*60)
    print("STAGE 1 — Intrusion Detection")
    print("="*60)

    csvs = list_csvs(ids_dir)
    if not csvs:
        raise FileNotFoundError(f"No CSV files found in: {ids_dir}")

    print(f"[Stage 1] Loading {len(csvs)} file(s) from {ids_dir} ...")
    df = pd.concat((read_csv(p) for p in csvs), ignore_index=True)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    if "Label" not in df.columns:
        raise ValueError("Expected a 'Label' column in IDS data.")

    df["is_attack"] = (df["Label"].astype(str).str.strip() != "BENIGN").astype(int)
    print(f"[Stage 1] Records: {len(df):,}  |  Attack rate: {df['is_attack'].mean():.1%}")

    # Stratified subsample for training speed
    if len(df) > STAGE1_SUBSAMPLE:
        _, df = train_test_split(df, test_size=STAGE1_SUBSAMPLE,
                                 random_state=42, stratify=df["is_attack"])

    drop_cols = {"Label","is_attack","Flow ID","Timestamp","Source IP","Destination IP"}
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    y = df["is_attack"]

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=STAGE1_TEST_SIZE,
                                               random_state=42, stratify=y)

    num_cols = X_tr.select_dtypes(include=np.number).columns.tolist()
    cat_cols = X_tr.select_dtypes(exclude=np.number).columns.tolist()

    pre = ColumnTransformer([
        ("num", StandardScaler(), num_cols),
        ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
    ], remainder="drop")

    pipe = ImbPipeline([
        ("pre",   pre),
        ("smote", SMOTE(random_state=42)),
        ("clf",   build_lightgbm()),
    ])

    print("[Stage 1] Training ...")
    pipe.fit(X_tr, y_tr)
    y_pred = pipe.predict(X_te)
    print("[Stage 1] Classification Report:")
    print(classification_report(y_te, y_pred, target_names=["Benign","Attack"]))

    # Export alerts
    X_all = df[X.columns].copy()
    proba = pipe.predict_proba(X_all)[:, 1]
    alerts = pd.DataFrame({"prob_attack": proba})
    for col in ["Source IP","Destination IP","Protocol","Destination Port"]:
        if col in df.columns:
            alerts[col] = df[col].values

    alerts = alerts.sort_values("prob_attack", ascending=False).head(50_000)
    ensure_dir(output_dir)
    alerts_path = os.path.join(output_dir, "alerts_stage1.csv")
    alerts.to_csv(alerts_path, index=False)
    print(f"[Stage 1] Alerts saved → {alerts_path}")
    return alerts_path

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2 — Vulnerability Prioritisation & Enrichment
# ──────────────────────────────────────────────────────────────────────────────
def stage2_run(nessus_csv: str, alerts_path: str, output_dir: str):
    """
    Filter vulnerabilities to alerted assets, train a priority model,
    and enrich high-priority findings with MITRE ATT&CK TTPs + SLA hints.
    """
    print("\n" + "="*60)
    print("STAGE 2 — Vulnerability Prioritisation")
    print("="*60)

    dfv = read_csv(nessus_csv)
    print(f"[Stage 2] Loaded {len(dfv):,} vulnerability records.")

    # Inject synthetic Source IP if missing
    if "Source IP" not in dfv.columns:
        rng = np.random.default_rng(42)
        dfv["Source IP"] = [f"10.0.{rng.integers(0,255)}.{rng.integers(1,254)}"
                            for _ in range(len(dfv))]

    # Filter to alerted assets from Stage 1
    if os.path.exists(alerts_path):
        alerts = read_csv(alerts_path)
        alerted_ips = set()
        for col in ["Source IP","Destination IP"]:
            if col in alerts.columns:
                alerted_ips |= set(alerts[col].dropna().astype(str))

        before = len(dfv)
        dfv = dfv[dfv["Source IP"].astype(str).isin(alerted_ips)]
        print(f"[Stage 2] Asset filter: {before:,} → {len(dfv):,} records on alerted assets.")

        if len(dfv) == 0:
            print("[Stage 2] WARN: No matching vulns — running on full dataset.")
            dfv = read_csv(nessus_csv)

    # Derived / enrichment columns
    if "patch_available"   not in dfv.columns:
        dfv["patch_available"]   = (dfv["cvss"] >= 4.0).astype(int)
    if "patch_age_days"    not in dfv.columns:
        dfv["patch_age_days"]    = (dfv["age_days"] * 0.6).astype(int)
    if "in_cisa_kev"       not in dfv.columns:
        dfv["in_cisa_kev"]       = ((dfv["severity"] >= 3) &
                                    (dfv["exploit_available"] == 1)).astype(int)
    if "has_known_exploit" not in dfv.columns:
        dfv["has_known_exploit"] = dfv["exploit_available"].astype(int)
    if "trending"          not in dfv.columns:
        dfv["trending"]          = ((dfv["age_days"] <= 45) &
                                    (dfv["severity"] >= 3)).astype(int)
    if "asset_criticality" not in dfv.columns:
        dfv["asset_criticality"] = 3
    if "internet_exposed"  not in dfv.columns:
        dfv["internet_exposed"]  = 0

    # TTP + remediation text
    desc_col = (dfv["svc_name"].astype(str) + " " +
                dfv["proto"].astype(str)    + " port " +
                dfv["port"].astype(str))
    dfv["ttp"], dfv["remediation_text"] = zip(*desc_col.map(map_ttp))

    # Model features
    num_feats = ["cvss","severity","exploit_available","age_days","description_len",
                 "persistence_scans","port","asset_criticality","internet_exposed",
                 "patch_available","patch_age_days","in_cisa_kev",
                 "has_known_exploit","trending"]
    cat_feats = ["proto","svc_name"]
    target    = "remediation_priority"

    if target not in dfv.columns:
        raise ValueError(f"Column '{target}' not found in {nessus_csv}.")

    dfm = dfv[[c for c in num_feats + cat_feats + [target,"Source IP",
               "ttp","remediation_text"] if c in dfv.columns]].dropna(subset=[target])

    if len(dfm) > STAGE2_TRAIN_SAMPLE:
        dfm = dfm.sample(STAGE2_TRAIN_SAMPLE, random_state=42)

    X = dfm[num_feats + cat_feats]
    y = dfm[target].astype(int)

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=STAGE2_TEST_SIZE,
                                               random_state=42, stratify=y)

    pre = ColumnTransformer([
        ("num", StandardScaler(), num_feats),
        ("cat", OneHotEncoder(handle_unknown="ignore"), cat_feats),
    ], remainder="drop")

    pipe = ImbPipeline([
        ("pre",   pre),
        ("smote", SMOTE(random_state=42)),
        ("clf",   build_lightgbm(objective="multiclass", num_class=y.nunique())),
    ])

    print("[Stage 2] Training prioritisation model ...")
    pipe.fit(X_tr, y_tr)
    y_pred = pipe.predict(X_te)
    print("[Stage 2] Classification Report:")
    print(classification_report(y_te, y_pred))

    # Risk scoring
    proba     = pipe.predict_proba(dfm[num_feats + cat_feats])
    classes   = pipe.named_steps["clf"].classes_.tolist()
    weights   = np.array([(i + 1) for i, _ in enumerate(sorted(classes))], float)
    base_risk = (proba * weights).sum(axis=1) / weights.max()

    mult = (1 + 0.12 * (dfm["asset_criticality"].fillna(3) - 3) *
            (1 + 0.10 * dfm["internet_exposed"].fillna(0)) *
            (1 + 0.15 * dfm["in_cisa_kev"].fillna(0))       *
            (1 + 0.10 * dfm["has_known_exploit"].fillna(0))  *
            (1 + 0.08 * dfm["trending"].fillna(0)))
    risk_score = np.clip(base_risk * mult, 0, 1.0)

    bands, slas = zip(*[band_sla(r) for r in risk_score])

    out = dfm.copy()
    out["predicted_priority"] = pipe.predict(dfm[num_feats + cat_feats])
    out["risk_score"]         = risk_score
    out["priority_band"]      = bands
    out["sla_hint"]           = slas
    out = out.sort_values(["priority_band","risk_score"], ascending=[True, False])

    ensure_dir(output_dir)
    enriched_path = os.path.join(output_dir, "vuln_prioritized_enriched.csv")
    out.to_csv(enriched_path, index=False)
    print(f"[Stage 2] Enriched output saved → {enriched_path}")

    # Risk band summary
    summary = (out.groupby("priority_band")
               .agg(count=("risk_score","count"),
                    mean_risk=("risk_score","mean"),
                    mean_cvss=("cvss","mean"))
               .reset_index())
    summary_path = os.path.join(output_dir, "risk_bands_summary.csv")
    summary.to_csv(summary_path, index=False)
    print(f"[Stage 2] Risk band summary saved → {summary_path}")
    print(summary.to_string(index=False))

    # Optional SHAP
    try:
        import shap
        sample    = dfm.sample(min(5000, len(dfm)), random_state=42)
        X_shap    = pipe.named_steps["pre"].transform(sample[num_feats + cat_feats])
        explainer = shap.TreeExplainer(pipe.named_steps["clf"])
        shap_vals = explainer.shap_values(X_shap)
        shap.summary_plot(shap_vals, X_shap,
                          feature_names=pipe.named_steps["pre"].get_feature_names_out(),
                          show=False)
        plt.tight_layout()
        shap_path = os.path.join(output_dir, "shap_summary.png")
        plt.savefig(shap_path, dpi=150)
        plt.close()
        print(f"[Stage 2] SHAP plot saved → {shap_path}")
    except Exception as e:
        print(f"[Stage 2] SHAP skipped (optional): {e}")

# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Hybrid AI Framework — Vulnerability Prioritisation & Threat Attribution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline
  python pipeline.py --ids-dir ./data/cic-ids-2017 --nessus-csv ./data/findings.csv

  # Stage 2 only (alerts already exist)
  python pipeline.py --nessus-csv ./data/findings.csv \\
                     --alerts ./outputs/alerts_stage1.csv --skip-stage1

  # Quick smoke-test with synthetic data
  python pipeline.py --demo
        """
    )
    p.add_argument("--ids-dir",     help="Folder containing IDS dataset CSV files (CIC-IDS-2017 etc.)")
    p.add_argument("--nessus-csv",  help="Path to Nessus-like findings CSV")
    p.add_argument("--alerts",      default="./outputs/alerts_stage1.csv",
                   help="Path to Stage 1 alerts CSV (default: ./outputs/alerts_stage1.csv)")
    p.add_argument("--output-dir",  default=DEFAULT_OUTPUT_DIR,
                   help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    p.add_argument("--skip-stage1", action="store_true",
                   help="Skip Stage 1 and use an existing alerts CSV")
    p.add_argument("--demo",        action="store_true",
                   help="Generate tiny synthetic datasets and run the full pipeline")
    return p.parse_args()


def main():
    args = parse_args()
    ensure_dir(args.output_dir)

    if args.demo:
        print("[demo] Generating synthetic data ...")
        demo_dir = os.path.join(args.output_dir, "demo_data")
        ensure_dir(demo_dir)
        ids_csv, nessus_csv = make_demo_data(demo_dir)
        args.ids_dir    = demo_dir
        args.nessus_csv = nessus_csv
        args.skip_stage1 = False

    if not args.skip_stage1:
        if not args.ids_dir:
            sys.exit("Error: --ids-dir is required unless --skip-stage1 or --demo is set.")
        alerts_path = stage1_run(args.ids_dir, args.output_dir)
    else:
        alerts_path = args.alerts
        if not os.path.exists(alerts_path):
            sys.exit(f"Error: Alerts file not found at {alerts_path}")

    if not args.nessus_csv:
        sys.exit("Error: --nessus-csv is required unless --demo is set.")

    stage2_run(args.nessus_csv, alerts_path, args.output_dir)
    print("\n✓ Pipeline complete. Outputs in:", args.output_dir)


if __name__ == "__main__":
    main()
