#!/usr/bin/env python3
"""F3: bundle + verify. Zip the submission bundle, hash it, count deck pages."""
import hashlib, os, zipfile

base = "/root/.hermes/hackyeah/f3"
src = os.path.join(base, "submission-bundle")
zpath = os.path.join(base, "submission-bundle.zip")
with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(src):
        for f in sorted(files):
            full = os.path.join(root, f)
            z.write(full, os.path.relpath(full, base))

h = hashlib.sha256(open(zpath, "rb").read()).hexdigest()
print("zip bytes:", os.path.getsize(zpath))
print("zip sha256:", h)
open(os.path.join(base, "submission-bundle.sha256"), "w").write(f"{h}  submission-bundle.zip\n")

import pymupdf
d = pymupdf.open(os.path.join(src, "warrnt-deck.pdf"))
print("deck pages:", d.page_count)
desc = open(os.path.join(src, "description-en.txt"), encoding="utf-8").read()
print("description words:", len(desc.split()))
print("zip entries:", len(zipfile.ZipFile(zpath).namelist()))
