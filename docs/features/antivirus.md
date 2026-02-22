# Antivirus Integration

DocFirewall provides an abstraction layer for integrating traditional Antivirus engines into the document scanning pipeline. This covers **Threat T1 (Malware)**.

## Supported Providers

### 1. ClamAV
The default and recommended provider for local, offline scanning.

-   **Mechanism**: Can use the `clamscan` binary or `clamd` daemon socket.
-   **Pros**: Free, open-source, local (privacy-friendly).
-   **Cons**: Signature database updates required.

### 2. VirusTotal
For checking file hashes against a massive cloud database.

-   **Mechanism**: Hashes the file (SHA256) and queries the VirusTotal API.
-   **Privacy**: Uploading full files is disabled by default; only hashes are sent.
-   **Pros**: 70+ engines, high detection rate.
-   **Cons**: Requires API key, quota limits.

### 3. Generic CLI
The "Universal Adapter" allowing you to use any AV installed on the system (Sophos, Windows Defender, ESET, etc.).

-   **Mechanism**: Runs a shell command replacing `{path}` with the temp file path.
-   **Pros**: Compatible with enterprise endpoint protection agents.

## Workflow

1.  **Extraction**: The document is received in memory or on disk.
2.  **Pre-Flight**: Before parsing, the raw file bytes are passed to the configured AV engine.
3.  **Verdict**:
    -   If **Infected**: The scan stops immediately. Verdict is `BLOCK`. Risk Score `1.0`.
    -   If **Clean**: The file proceeds to the Deep Parser.
