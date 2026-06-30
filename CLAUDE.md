# CLAUDE.md — Windows Endpoint Behavioral Analysis

## What This Project Does

SOC pipeline that ingests Windows event logs (Winlogbeat, `shire.com` lab domain),
extracts behavioral features per host per 5-min window, runs Isolation Forest anomaly
detection, evaluates against Sigma rules, and outputs an interactive HTML dashboard.

---

## Project Layout

```
src/main/myapp/
  main.py               # Entry point — orchestrates the full pipeline
  schemas/              # Pydantic schemas: feature.py, raw.py, window.py
  loader/               # loader.py → normalize.py → cache.py (Parquet)
  features/             # Feature extraction: extractor.py orchestrates all
    aggregate.py        # 5-min window aggregation per host
    process.py / network.py / file.py / command.py / sequence.py / mitre.py
  ml/                   # train.py → predict.py → evaluation.py → explain.py
  detection/severity.py # severity_score + low/medium/high/critical label
  sigma/                # loader.py + comparator.py (Sigma rule matching)
  export/json_export.py
  dashboard/
    theme.py            # Color palette, BASE_LAYOUT, BEHAVIORAL_LABELS
    builder.py          # All chart builders + HTML assembler (build_dashboard)
    attack_matrix.py    # MITRE ATT&CK heatmap
    chain_timeline.py   # Attack chain Sankey + pattern summary
output/                 # Generated artifacts (dashboard.html, JSON exports)
```

---

## Key Conventions

### Never change without asking
- Color constants in `theme.py` — intentional GitHub-dark SOC palette
- Normalized column names: `_host`, `_channel`, `_process`, `_parent`, `_action`, `_cmd`
- `BASE_LAYOUT` dict — all 14 Plotly figures depend on it
- 5-min window aggregation interval — affects all downstream logic
- Sigma evaluation logic in `ml/evaluation.py` — it's the ground truth reference

### Python style
- Type hints on all new functions; docstrings on public functions
- `logger = logging.getLogger(__name__)` — never `print()` in pipeline code
- Always guard DataFrames: `if df is None or df.empty: return`
- Always guard columns: `if "col" in df.columns` before accessing
- Use `pathlib.Path` — never `os.path`
- Prefer `df = df.copy()` over inplace ops to avoid SettingWithCopyWarning

---

## Dashboard HTML Template — Critical Rule

`build_dashboard()` in `builder.py` builds the HTML inside a Python f-string.

**CSS/HTML literal braces MUST be doubled:**

```python
# CORRECT
.card{{background:{C_CARD};border:1px solid {C_BORD}}}

# WRONG — SyntaxError or garbled output
.card{background:{C_CARD}}
```

Run `python3 -c "import ast; ast.parse(open('builder.py').read()); print('OK')"` after any edit.

---

## Color System (`theme.py`)

```python
C_BG="#0d1117"  C_CARD="#161b22"  C_BORD="#21262d"
C_RED="#f85149" C_AMBER="#e3b341" C_GREEN="#3fb950"
C_BLUE="#58a6ff" C_PURPLE="#bc8cff"
C_TEXT="#c9d1d9" C_MUTED="#8b949e"
```

Severity mapping: `high/critical → C_RED`, `medium → C_AMBER`, `low → C_GREEN`

---

## Key Columns (post-normalize.py)

| Column | Description |
|---|---|
| `@timestamp` | Event time |
| `EventID` | Windows Event ID |
| `_host` | Normalized hostname |
| `_channel` | `sysmon` / `security` / `powershell` / `defender` |
| `_process` / `_parent` | Full image paths |
| `_cmd` | CommandLine |
| `_action` | `process_create`, `network_connect`, `process_access`, `dns_query`, `registry_modify`, `file_modify` |
| `_net_dst` | `IP:port` for network events |
| `mitre_techniques` | List of ATT&CK technique IDs |
| `is_anomaly` | Bool — Isolation Forest output |
| `anomaly_score` | Float (more negative = more anomalous) |
| `severity` | `low/medium/high/critical` |
| `severity_score` | Float 0–10 |

Behavioral feature columns (aggregated, suffix `_sum`):
`has_powershell_sum`, `has_base64_sum`, `has_certutil_sum`, `has_wmic_sum`,
`has_mshta_sum`, `has_rundll32_sum`, `has_attack_sig_sum`, `office_spawned_shell_sum`,
`has_hack_tool_sum`, `long_ps_cmd_sum`, `susp_port_sum`, `susp_ip_sum`,
`is_temp_write_sum`, `susp_dll_path_sum`, `is_lsass_access_sum`, `susp_dns_sum`

---

## Common Tasks → Where to Edit

| Task | File |
|---|---|
| Dashboard UI / layout | `dashboard/builder.py` → `build_dashboard()` |
| Add/modify a chart | `dashboard/builder.py` → `build_charts()` |
| Colors / Plotly theme | `dashboard/theme.py` |
| New behavioral feature | `features/<type>.py` + `features/aggregate.py` + `theme.py` (BEHAVIORAL_LABELS) |
| Severity logic | `detection/severity.py` |
| Sigma rule matching | `sigma/comparator.py` |
| ML training / scoring | `ml/train.py` / `ml/predict.py` |
| Evaluation metrics | `ml/evaluation.py` |

---

## Behavior Expectations

- Discuss approach before writing code
- Explain what changes and why before showing a diff
- Call out side effects on other modules
- For new DataFrame columns: always add `.fillna(0)` and null guards
- For new HTML sections in builder.py: verify brace escaping before presenting
