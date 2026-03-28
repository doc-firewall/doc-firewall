def resolve_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    parts = []
    state = "normal"
    current_head = ""
    
    for line in content.splitlines(True):
        if line.startswith("<<<<<<< "):
            state = "head"
        elif line.startswith("======="):
            state = "other"
        elif line.startswith(">>>>>>> "):
            state = "normal"
            parts.append(current_head)
            current_head = ""
        else:
            if state == "normal":
                parts.append(line)
            elif state == "head":
                current_head += line
                
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("".join(parts))

resolve_file(".github/workflows/pypi-publish.yml")
resolve_file("README.md")
resolve_file("SECURITY.md")
resolve_file("docs/overrides/main.html")
print("Done")
