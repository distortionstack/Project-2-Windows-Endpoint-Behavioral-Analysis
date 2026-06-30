#Vetala
## Windows Endpoint Behavioral Analysis

<img width="367" height="604" alt="image" src="https://github.com/user-attachments/assets/c8cae993-f75f-4262-947c-5945ba87f0d4" />

Behavioral-based Windows endpoint threat detection pipeline combining Isolation Forest (unsupervised) and LightGBM (supervised) ML with MITRE ATT&CK mapping, Sigma rule correlation, and interactive dashboards.

## Methodology

The pipeline processes Windows event logs (Sysmon, Security, PowerShell, etc.) through the following stages:

1. **Loading & Normalization** — Raw JSON/CSV/XML logs are loaded, flattened, and normalized to a standard schema with columns like `_process`, `_cmd`, `_parent`, `_user`, `_channel`, `EventID`, `@timestamp`.

2. **Behavioral Feature Extraction** — 19 binary behavioral signals are extracted per event:
   - PowerShell usage, base64-encoded commands, hack tools, MSHTA/Rundll32/WMIC/Certutil invocation
   - Office -> Shell spawning, suspicious ports/IPs/DNS, temp writes, DLL side-loading
   - LSASS access, process injection (CreateRemoteThread / suspicious Process Access)
   - Indicator removal, valid account abuse

3. **MITRE ATT&CK Tagging** — Each behavioral signal maps to 1+ MITRE technique IDs (e.g., `is_lsass_access -> T1003.001`). Every event gets a `mitre_techniques` list column.

4. **Time-Window Aggregation** — Events are grouped by `_host` + 5-min windows. Summed signal counts produce a feature vector per window for ML.

5. **Anomaly Detection** (Unsupervised) — Isolation Forest scores each window. Windows scoring in the tail are flagged as anomalous.

6. **Supervised Classification** (LightGBM) — Multi-class classifier trained on labeled Mordor dataset sources. Predicts the technique family per window with confidence scores.

7. **Sigma Rule Matching** — Pre-loaded Sigma rules are matched against events. Results are compared against ML flags to compute precision/recall.

8. **Attack Chain Detection** — Tactic-level sequences (e.g., Initial Access -> Execution -> Credential Access) are extracted per host. Known kill-chain patterns are identified.

## Installation

```bash
pip install -r requirements.txt
```

Dependencies: `lightgbm`, `scikit-learn`, `pandas`, `numpy`, `polars`, `plotly`, `matplotlib`, `seaborn`, `joblib`, `requests`, `pyyaml`.

## Configuration

Edit `config/config.json` to tune:
- Detection thresholds, suspicious IPs/ports/domains
- ML hyperparameters (Isolation Forest, LightGBM)  
- Time window size (default: 5min)
- Model persistence settings

## Usage

### Analysis Pipeline

```bash
python src/main/myapp/main.py
```

This runs the default pipeline with Isolation Forest on the Mordor LSASS dump dataset.

### Options

| Flag | Description |
|------|-------------|
| `-s <path_or_url>` | Input source (repeatable; local file, URL, ZIP, JSON, CSV) |
| `--force-update` | Bypass cache and re-download sources |
| `--no-browser` | Do not auto-open the dashboard |
| `--model-type {isolation_forest,lightgbm}` | ML model type (default: isolation_forest) |
| `--train` | Train LightGBM on loaded sources before inference |

### Supervised Training

```bash
python src/main/myapp/main.py --model-type lightgbm --train
```

Sources are loaded and technique labels are extracted from their URL paths (e.g., paths containing `credential_access` map to T1003). The pipeline:
1. Loads and normalizes each source
2. Runs feature extraction and aggregation
3. Trains a multi-class LightGBM classifier
4. Evaluates with Precision/Recall/F1 per technique
5. Saves model + label encoder + scaler to `models/`

### Supervised Inference

```bash
python src/main/myapp/main.py --model-type lightgbm
```

Uses the pre-trained model (must run `--train` first). Predicts a technique class per window with confidence. Windows with confidence > 0.5 are flagged as suspicious.

## Output

### Dashboard (`output/dashboard.html`)

Interactive SOC dashboard with:
- KPI row (total events, hosts, channels, anomalous windows, threat events)
- **MITRE ATT&CK Matrix** — Heatmap: tactics vs techniques, colored by detection count
- Data provenance pie chart + event type bar chart
- **Attack Chain Sankey** — Tactic transition flow diagram
- Known attack chain pattern occurrence bar chart
- Threat timeline (5-min windows), top suspicious hosts, severity distribution
- Event ID, behavioral signal, and feature deviation distributions
- Anomaly score histogram, top suspicious executables
- **Evaluation Metrics** — Precision/Recall/F1 bar chart, Sigma vs ML confusion matrix, metric table
- Top suspicious behavioral windows table
- Top events table with MITRE technique tags

### JSON Exports (`output/`)

| File | Contents |
|------|----------|
| `alerts_full.json` | Threat events in suspicious windows |
| `aggregated_windows.json` | All 5-min windows with feature vectors |
| `evaluation_metrics.json` | Sigma comparison, supervised metrics (if trained), attack chain analysis |
| `supervised_metrics.json` | Per-technique Precision/Recall/F1, confusion matrix, ROC/PR curves |

## Evaluation Metrics

### Sigma vs ML Comparison

When Sigma rules are loaded, `compare_ml_vs_sigma()` computes:
- **Window-level**: TP/FP/FN/TN, precision, recall, F1 (treating ML as predictor, Sigma as ground truth)
- **Event-level**: Total events, sigma-matched events, match rate

### Supervised Classification Metrics

When `--train` is used, `evaluate_model()` computes:
- Per-technique precision, recall, F1, support
- Macro / weighted averages
- Confusion matrix (image + Plotly JSON)
- ROC curves (one-vs-rest, image + JSON)
- PR curves (one-vs-rest, image + JSON)

### Attack Chain Analysis

`detect_sequences()` extracts per-host tactic chains from the `mitre_techniques` column and matches against 6 known kill-chain patterns. Statistics are exported to `evaluation_metrics.json`.

## MITRE ATT&CK Coverage

| Technique | Name | Detection |
|-----------|------|-----------|
| T1059.001 | PowerShell | has_powershell, has_base64, long_ps_cmd |
| T1027 | Obfuscated Files | has_base64, long_ps_cmd |
| T1003.001 | LSASS Memory | is_lsass_access, has_attack_sig |
| T1059 | Command & Scripting | office_spawned_shell |
| T1566.001 | Spearphishing Attachment | office_spawned_shell |
| T1588.002 | Obtain Tools | has_hack_tool |
| T1105 | Remote File Copy / Temp Write | has_certutil, is_temp_write |
| T1140 | Deobfuscate/Decode | has_certutil |
| T1047 | WMI | has_wmic |
| T1218.005 | Mshta | has_mshta |
| T1218.011 | Rundll32 | has_rundll32 |
| T1021 | Remote Services | susp_port |
| T1071 / T1071.004 | C2 / DNS | susp_ip, susp_dns |
| T1574.002 | DLL Side-Loading | susp_dll_path |
| T1055 / T1055.001 | Process Injection | is_process_injection |
| T1070 | Indicator Removal | has_indicator_removal |
| T1078 | Valid Accounts | has_valid_account |

## Project Structure

```
src/main/myapp/
  config/          — Constants, MITRE mappings, regex, settings
  loader/          — Data loading, caching, normalization
  features/        — Feature extraction (process, command, network, file, sequence)
  ml/              — ML pipeline (train, predict, preprocessing, evaluation, metrics, supervised)
  sigma/           — Sigma rule loading, matching, comparison
  dashboard/       — Plotly SOC dashboard, theme, attack matrix, chain timeline
  export/          — JSON export utilities
  schemas/         — Data schema definitions
  detection/       — Severity scoring, threat mapping
  main.py          — Pipeline orchestrator
```
