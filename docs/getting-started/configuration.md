# Configuration

DocFirewall is highly configurable via PyYAML or direct Python object configuration. The configuration is controlled by the `ScanConfig` class.

## Loading Configuration

You can load configuration from a YAML file or instantiate it in code.

=== "Python"
    ```python
    from doc_firewall import ScanConfig, Scanner

    config = ScanConfig(
        profile="strict",
        enable_antivirus=True
    )
    scanner = Scanner(config=config)
    ```

=== "YAML"
    **doc_firewall_config.yaml**
    ```yaml
    profile: "strict"
    enable_antivirus: true
    thresholds:
      block: 0.8
    ```

    **Loading:**
    ```python
    from doc_firewall import ScanConfig
    config = ScanConfig.from_yaml("doc_firewall_config.yaml")
    ```

## Core Settings

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `profile` | `str` | `"balanced"` | One of `balanced`, `strict`, `lenient`. Adjusts default thresholds. |
| `enable_pdf` | `bool` | `True` | enable PDF parsing/scanning. |
| `enable_docx` | `bool` | `True` | enable DOCX parsing/scanning. |
| `enable_pptx` | `bool` | `True` | enable PPTX parsing/scanning. |
| `enable_xlsx` | `bool` | `True` | enable XLSX parsing/scanning. |

## Threat Modules (T1-T9)

You can granularly enable or disable specific detection modules.

```python
config = ScanConfig(
    # T1: Malware / Virus (Requires AV Setup)
    enable_antivirus=False,  
    
    # T2: Active Content (Macros, JS)
    enable_active_content_checks=True,
    
    # T3: Obfuscation (Hidden content)
    enable_obfuscation_checks=True,
    
    # T4: Prompt Injection (Jailbreaks)
    enable_prompt_injection=True,
    
    # T5: Ranking Manipulation (Keyword stuffing)
    enable_ranking_abuse=True,
    
    # T6: Resource Exhaustion (DoS)
    enable_dos_checks=True,
    
    # T7: Embedded Payloads (Binaries in streams)
    enable_embedded_content_checks=True,
    
    # T8: Metadata Injection
    enable_metadata_checks=True,
    
    # T9: ATS Manipulation (White text)
    enable_ats_manipulation_checks=True
)
```

## Antivirus Configuration

To use the T1 Malware protection, you must configure a provider.

=== "ClamAV (Default)"
    Reliable, open-source integration.
    ```yaml
    antivirus:
      provider: "clamav"
      clamav_bin_path: "/usr/bin/clamscan"
      # OR use Daemon Socket (Recommended for speed)
      # clamav_socket_path: "/var/run/clamav/clamd.ctl"
    ```

=== "VirusTotal"
    Cloud-based hash lookup.
    ```yaml
    antivirus:
      provider: "virustotal"
      virustotal_api_key: "YOUR_VT_API_KEY"
    ```

=== "Generic CLI"
    Wrap any CLI tool (e.g., Sophos, Windows Defender).
    ```yaml
    antivirus:
      provider: "generic_cli"
      # {path} is replaced by the file path
      generic_cli_command: "sophos_scan --file {path}"
      # Exit codes that indicate infection
      generic_cli_infected_codes: [1, 2] 
    ```

## Thresholds & Limits

Adjust sensitivity and resource constraints.

```yaml
thresholds:
  deep_scan_trigger: 0.20  # Risk score to trigger deep parsing (0.0-1.0)
  flag: 0.35               # Return VERDICT=FLAG
  block: 0.70              # Return VERDICT=BLOCK

# Empirically calibrated via scripts/calibrate_thresholds.py (ROC-AUC = 1.0)
# on 1 185 labeled records. Do not lower block below 0.35 without re-running
# calibration on your dataset.

limits:
  max_mb: 10               # Max file size in MB
  max_pages: 1000          # PDF page limit
  parse_timeout_ms: 15000  # Parsing timeout
  min_embedded_object_size_bytes: 20000  # Min size for embedded payload detection
```

## Advanced Threat Configuration

### Prompt Injection Tuning

The multi-layer injection detector (L0–L4) exposes several tuning knobs:

```python
config = ScanConfig(
    # Layer 3 — local BERT classifier
    enable_advanced_bert=True,
    bert_model_path="ProtectAI/deberta-v3-base-prompt-injection-v2",  # local weights
    bert_confidence_threshold=0.85,   # lower = more sensitive
    bert_max_chunks=20,               # max sliding-window chunks per document

    # Layer 4 — semantic nearest-neighbour (opt-in)
    enable_semantic_nn=False,         # disabled by default; enable for highest recall
    nn_model_name="all-MiniLM-L6-v2",
    nn_sim_threshold=0.80,

    # Layer 1 — custom phrases on top of built-in list
    custom_ahocorasick_yaml_path="path/to/custom_phrases.yaml",
)
```

### Customizing ATS & Ranking Keywords
To prevent heuristic overfitting, developers can define custom ATS target keywords depending on the job domain or specific organizational ranking manipulation vulnerabilities:

```python
from doc_firewall import ScanConfig, Limits

# Pass a custom list to detect domain-specific keyword stuffing.
# The default list contains only injection-style phrases — not skill words
# like "python", "java", or "developer" — to avoid false positives on resumes.
custom_config = ScanConfig(
    ats_keywords=["nursing", "medical", "registered", "certified", "healthcare"],
    limits=Limits(min_embedded_object_size_bytes=50000)
)
```

## False Positive Management

### Watermarks
Enterprise documents often contain "hidden" watermarks (e.g., "Confidential" in a hidden text layer). By default, DocFirewall employs a smart bypass.

```python
# Default: True. Allows standard watermarks ("Draft", "Internal Use")
config.allow_hidden_watermarks = True
```
