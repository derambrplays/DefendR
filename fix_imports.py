#!/usr/bin/env python3
"""Fix imports in all defendr/ modules."""
import os, re

pkg_dir = "defendr"

# Module dependency map
module_imports = {
    "constants": [],  # no internal imports
    "lang": ["constants"],
    "engine": ["constants"],
    "quarantine": ["constants"],
    "monitors": ["constants", "engine"],
    "security": ["constants"],
    "tools": ["constants"],
    "network_tools": ["constants"],
    "scheduler": ["constants"],
    "ui": ["constants", "engine", "monitors", "security", "tools", "network_tools", "quarantine", "scheduler", "lang"],
}

for module, deps in module_imports.items():
    filepath = os.path.join(pkg_dir, f"{module}.py")
    if not os.path.exists(filepath):
        print(f"Skipping {module} (not found)")
        continue
    
    with open(filepath) as f:
        content = f.read()
    
    # Fix all "from constants import" -> "from defendr.constants import"
    # But NOT if already fixed
    content = re.sub(r'^from (?!defendr)(\w+) import', r'from defendr.\1 import', content, flags=re.MULTILINE)
    
    # Fix "from engine import" -> "from defendr.engine import" (if not already)
    content = re.sub(r'^from (?!defendr)(\w+) import', r'from defendr.\1 import', content, flags=re.MULTILINE)
    
    with open(filepath, "w") as f:
        f.write(content)
    print(f"Fixed imports: {module}")

# Now fix the __init__.py - it already has defendr. prefix, so it should be fine
print("All imports fixed!")
