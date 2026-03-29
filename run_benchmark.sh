#!/bin/bash
set -e

# Start Time tracking
EVAL_START_TIME=$(date +%s)
EVAL_START_DATE=$(date)
echo "=========================================="
echo "Benchmark Started at: $EVAL_START_DATE"
echo "=========================================="

# Change to the project directory if we are not already there
# This assumes the script is run from project root e.g. ./run_benchmark.sh
# or from parent dir e.g. doc_guard_project/run_benchmark.sh

# Ensure we are in one of the expected directories for the volume mounts to work
if [ -f "Dockerfile" ]; then
    PROJECT_ROOT=$(pwd)
elif [ -f "doc_guard_project/Dockerfile" ]; then
    cd doc_guard_project
    PROJECT_ROOT=$(pwd)
else
    echo "Error: Could not find Dockerfile. Please run from project root."
    exit 1
fi

echo "Using project root: $PROJECT_ROOT"

# Locate dataset
if [ -d "$DATASET_DIR" ]; then
    DATASET_DIR="$DATASET_DIR"
elif [ -d "$PROJECT_ROOT/../dataset" ]; then
    # Resolve absolute path for ../dataset
    DATASET_DIR=$(cd "$PROJECT_ROOT/.." && pwd)/dataset
    if [ ! -d "$DATASET_DIR" ]; then
        echo "Error: Dataset specific path not found at $DATASET_DIR"
        exit 1
    fi
else
    echo "Error: Could not find dataset directory."
    exit 1
fi
echo "Using dataset dir: $DATASET_DIR"

# 1. Cleanup
echo "--- Cleaning up previous builds ---"
# Remove dangling containers if any (ignoring errors if they don't exist)
docker rm -f doc-firewall-bench 2>/dev/null || true
# Remove the image to ensure a fresh build
docker rmi doc-firewall:latest 2>/dev/null || true

# 2. Build
echo "--- Building Docker image ---"
docker build -t doc-firewall .

# 3. Download Models (Host Side)
# Ensure models are present before running validation (though they are baked in image now)
# If they are baked in, this is optional, but good for local checks.
# echo "--- Downloading Models (if missing) ---"
# python scripts/download_ocr_model.py
# python scripts/download_embedding_model.py

# 4. Run Pipeline
echo "--- Running Validation ---"
# Generate full manifest
docker run --rm -v "$DATASET_DIR:/app/dataset" -v "$PROJECT_ROOT/..:/app" --entrypoint python doc-firewall /app/generate_full_manifest.py

# Mount dataset to persist scan_results.jsonl
docker run --rm \
    -v "$DATASET_DIR:/app/dataset" \
    --entrypoint python \
    doc-firewall scripts/validate_with_doc_firewall.py /app/dataset/manifest_full_t1_t9.csv

echo "--- Running Antivirus Verification ---"
# Mount current dir to save test file or logs if needed
docker run --rm \
     -v "$PROJECT_ROOT:/app" \
    --entrypoint python \
    doc-firewall scripts/test_antivirus_docker.py
    
echo "--- Calculating Metrics ---"
# Mount dataset to read results and write summary
docker run --rm \
    -v "$DATASET_DIR:/app/dataset" \
    --entrypoint python \
    doc-firewall scripts/metrics.py /app/dataset/manifest_full_t1_t9.csv

echo "--- Running Holdout Evaluation (PPTX/XLSX) ---"
# Run evaluation on the holdout/test split for pptx/xlsx (updates metrics_summary.json)
docker run --rm \
    -v "$DATASET_DIR:/app/dataset" \
    -e PYTHONPATH=/app/src \
    --entrypoint python \
    doc-firewall scripts/doc_firewall_evaluate.py /app/dataset/manifest_holdout_pptx_xlsx_test.csv /app/dataset/splits/holdout_test_pptx_xlsx.txt

echo "--- Running Holdout Evaluation (Legacy DOCX/PDF) ---"
# Run evaluation on the generic holdout/test split
docker run --rm \
    -v "$DATASET_DIR:/app/dataset" \
    -e PYTHONPATH=/app/src \
    --entrypoint python \
    doc-firewall scripts/doc_firewall_evaluate.py /app/dataset/manifest.csv /app/dataset/splits/test.txt

echo "--- Generating Paper Artifacts ---"
# Mount paper_artifacts to output tables/charts
docker run --rm \
    -v "$DATASET_DIR:/app/dataset" \
    -v "$PROJECT_ROOT/paper_artifacts:/app/paper_artifacts" \
    --entrypoint bash \
    doc-firewall -c "pip install --quiet matplotlib pandas && python scripts/paper_artifacts.py"

echo "--- Generating DOCX Report ---"
# Mount scripts to output the .docx report next to the script
docker run --rm \
    -v "$DATASET_DIR:/app/dataset" \
    -v "$PROJECT_ROOT/scripts:/app/scripts" \
    --entrypoint bash \
    doc-firewall -c "pip install --quiet matplotlib pandas python-docx && python scripts/generate_docx_report.py"

echo "--- Benchmark Complete ---"

EVAL_END_TIME=$(date +%s)
EVAL_END_DATE=$(date)
EVAL_DURATION=$((EVAL_END_TIME - EVAL_START_TIME))

echo "=========================================="
echo "Benchmark Finished at: $EVAL_END_DATE"
echo "Total Time Taken: $((EVAL_DURATION / 60)) minutes and $((EVAL_DURATION % 60)) seconds."
echo "=========================================="
