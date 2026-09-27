import os
import re

def on_config(config):
    # Determine the directory where this hook script resides.
    # We are in doc_guard_project/docs, so we need to go up one level to find pyproject.toml
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(base_dir)
    pyproject_path = os.path.join(project_root, "pyproject.toml")
    
    version_found = "0.0.0"
    
    try:
        with open(pyproject_path, "r") as f:
            for line in f:
                # Naive regex to extract version = "x.y.z"
                match = re.match(r'^version\s*=\s*"([^"]+)"', line.strip())
                if match:
                    version_found = match.group(1)
                    break 
    except Exception as e:
        print(f"Warning: Could not read version from pyproject.toml: {e}")

    # Inject into mkdocs config extra dictionary
    if "extra" not in config:
        config["extra"] = {}
    
    config["extra"]["version_raw"] = version_found
    config["extra"]["version"] = f"v{version_found}"
    print(f"Hook: Injected version {config['extra']['version']}")
    
    return config
