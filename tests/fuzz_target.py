import atheris
import sys
import os
import tempfile

# Add the src directory to the path so we can import the package
# We might need to install the package in editable mode for coverage, or use sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Instrument the library for coverage
with atheris.instrument_imports(include=["doc_firewall"]):
    from doc_firewall.scanner import scan

def TestOneInput(data):
    """
    Fuzz test for the scan function.
    Since scan expects a file path, we'll write the data to a temporary file.
    """
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)
        
        # Run the scanner
        try:
            # Using defaults
            scan(path)
        except Exception:
            # We catch all exceptions because fuzzing is looking for crashes (segfaults)
            # or unexpected exits. Python exceptions are generally fine unless
            # we want to filter specific ones.
            pass
            
    finally:
        if os.path.exists(path):
            os.remove(path)

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
