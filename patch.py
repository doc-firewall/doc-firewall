import re

files_to_patch = [
    "/Users/gliffton/Desktop/ACLPrep/DocScan/doc_guard_project/scripts/requirements-build.txt",
    "/Users/gliffton/Desktop/ACLPrep/DocScan/doc_guard_project/scripts/requirements-pip-audit.txt"
]

pip_pattern = re.compile(r"pip==[^\n]*\n(?:\s+--hash[^\n]*\n)*")
new_pip_entry = '''pip==26.1 \\
    --hash=sha256:4e8486d821d814b77319acb7b9e8bf5a4ee7590a643e7cb21029f209be8573c1 \\
    --hash=sha256:81e13ebcca3ffa8cc85e4deff5c27e1ee26dea0aa7fc2f294a073ac208806ff3
'''

for file in files_to_patch:
    with open(file, 'r') as f:
        content = f.read()
    
    new_content = pip_pattern.sub(new_pip_entry, content)
    
    with open(file, 'w') as f:
        f.write(new_content)
