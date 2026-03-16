# VulnScan — Hybrid AI Framework for Vulnerability Prioritisation & Threat Attribution

> MSc Dissertation Project · Atharva Acharya · University of Warwick (WMG) · 2025

A two-stage AI pipeline that connects **live network threat detection** directly to **host-level vulnerability prioritisation**, automating the triage process that security teams typically do manually.

---

## The Problem

Security teams face two overwhelming data streams simultaneously: millions of network events from IDS/SIEM tools, and thousands of vulnerabilities from scanners like Nessus. Traditional CVSS-based scoring treats every vulnerability in isolation — it has no awareness of which assets are actively under attack *right now*. This creates a critical gap: analysts waste time patching low-risk theoretical vulnerabilities while actively exploited hosts go unremediated.

## The Solution

VulnScan bridges this gap with a sequential two-stage framework:

```
Network Traffic (PCAP/flows)
        │
        ▼
┌───────────────────┐
│  Stage 1 — IDS    │  LightGBM binary classifier
│  Threat Detection │  Identifies compromised assets from network flows
└────────┬──────────┘
         │  Alerted IP list
         ▼
┌───────────────────┐
│  Stage 2 — VPM    │  LightGBM multi-class classifier
│  Vuln Priority    │  Prioritises vulns ONLY on alerted assets
└────────┬──────────┘
         │
         ▼
  Enriched output:
  MITRE ATT&CK TTPs · Risk bands (P1–P5) · SLA hints · Remediation advice
```

---

## Results

| Stage | Task | Model | Score |
|-------|------|-------|-------|
| Stage 1 | Binary intrusion detection | LightGBM on CIC-IDS-2017 | **F1 = 1.00** |
| Stage 2 | Multi-class vulnerability prioritisation | LightGBM on 6M+ synthetic records | **Weighted F1 = 0.89** |

**Top features driving prioritisation** (SHAP analysis): CVSS score, severity, vulnerability age, exploit availability, asset criticality, internet exposure — empirically validating risk-based principles over raw CVSS scoring.

![SHAP Feature Importance](confusion_matrix_stage1.png)

---

## Quickstart

### 1. Install dependencies

```bash
git clone https://github.com/atharva-acharya/vulnscan.git
cd vulnscan
pip install -r requirements.txt
```

### 2. Demo mode (no datasets needed)

Generates a small synthetic dataset and runs the full pipeline end-to-end in under a minute:

```bash
python pipeline.py --demo
```

### 3. Full pipeline with real data

**Download datasets** (large files — stored externally):

| Dataset | Link |
|---------|------|
| CIC-IDS-2017 | [Google Drive](https://drive.google.com/drive/folders/1L0Fth5OQrjNqw11TTAoFZQsXaUbIuARX?usp=sharing) |
| CSE-CIC-IDS-2018 | [Google Drive](https://drive.google.com/drive/folders/11Xr267ncPzJ7gjHXdGLtURYOaAzTZj3Y?usp=sharing) |
| UNSW-NB15 | [Google Drive](https://drive.google.com/drive/folders/150zpa5fepFIs0FlPcFUXLH1sS-XXRtQh?usp=sharing) |
| Synthetic Nessus findings | [Google Drive](https://drive.google.com/drive/folders/1Y_CpC3W05azQjeuN3pdMxD6zkxiPIXbe?usp=sharing) |

**Run the full pipeline:**

```bash
python pipeline.py \
    --ids-dir   ./data/cic-ids-2017 \
    --nessus-csv ./data/findings.csv \
    --output-dir ./outputs
```

**Stage 2 only** (if Stage 1 alerts already exist):

```bash
python pipeline.py \
    --nessus-csv ./data/findings.csv \
    --alerts     ./outputs/alerts_stage1.csv \
    --skip-stage1
```

---

## Outputs

All outputs are written to `./outputs/` (or your `--output-dir`):

| File | Description |
|------|-------------|
| `alerts_stage1.csv` | Alerted IPs with attack probability scores from Stage 1 |
| `vuln_prioritized_enriched.csv` | Vulnerabilities ranked by risk score with TTP mapping and SLA hints |
| `risk_bands_summary.csv` | Aggregate summary: count, mean risk, mean CVSS per priority band (P1–P5) |
| `shap_summary.png` | SHAP feature importance plot (generated if `shap` is installed) |

### Reading the output

- **`priority_band`** — P1 (critical, patch in 24–48h) through P5 (low, monitor/schedule)
- **`risk_score`** — 0–1 composite score accounting for CVSS, exploit availability, asset criticality, and internet exposure
- **`ttp`** — mapped MITRE ATT&CK technique (e.g. `T1190: Exploit Public-Facing Application`)
- **`sla_hint`** — plain-English patching SLA for the analyst

---

## Generating the synthetic Nessus dataset

The synthetic dataset mimics a real Nessus scan report with correlated features (CVSS, severity, exploit availability, vulnerability age). To regenerate it:

```bash
python generate_realistic_dataset_auto_v3.py \
    --rows 6250000 \
    --output ./data/findings.csv \
    --plots
```

---

## Technical Design

- **Algorithm:** LightGBM (gradient boosting) — chosen for superior performance on tabular data and training efficiency vs XGBoost on large datasets
- **Class imbalance:** SMOTE (Synthetic Minority Over-sampling Technique) applied in both stages
- **Preprocessing:** `ColumnTransformer` with `StandardScaler` for numeric features and `OneHotEncoder` for categorical
- **Explainability:** SHAP (SHapley Additive exPlanations) for feature importance analysis
- **TTP mapping:** Keyword-based matching of service names to MITRE ATT&CK techniques
- **CyBOK alignment:** Risk Management & Governance, Network Security, Security Operations & Incident Management

---

## Project Structure

```
vulnscan/
├── pipeline.py                          # Main pipeline (Stage 1 + Stage 2)
├── generate_realistic_dataset_auto_v3.py # Synthetic Nessus dataset generator
├── requirements.txt
├── outputs/                             # Generated at runtime (gitignored)
│   ├── alerts_stage1.csv
│   ├── vuln_prioritized_enriched.csv
│   ├── risk_bands_summary.csv
│   └── shap_summary.png
└── sanity_plots/                        # Dataset validation plots
```

---

## Acknowledgements

- **CIC-IDS-2017 / CSE-CIC-IDS-2018** — Canadian Institute for Cybersecurity, University of New Brunswick
- **UNSW-NB15** — University of New South Wales / IXIA PerfectStorm
- Dissertation supervised by Sarah Aktaa, WMG, University of Warwick

---

## Licence

This project is for academic and research purposes. The synthetic Nessus dataset does not contain any real vulnerability data.
