import re, sys

man = open(r"C:\Users\zenyxx\AppData\Local\Temp\dirtyfrag\apk\AndroidManifest.xml", "rb").read()
lib = open(r"C:\Users\zenyxx\AppData\Local\Temp\dirtyfrag\apk\lib\arm64-v8a\libexp.so", "rb").read()

def utf16_strings(b, minlen=4):
    # UTF-16LE строки в binary XML: последовательности ascii-символов с \x00
    out = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, b):
        out.append(m.group().decode("utf-16-le"))
    return out

print("=== manifest strings (package-like) ===")
for s in utf16_strings(man):
    if "." in s and " " not in s:
        print(s)

print("=== libexp paths ===")
for pat in [rb"/data/user_de/0/[\x20-\x7e]+", rb"/data/[a-z]+/[a-z]+/[\x20-\x7e]+"]:
    seen = set()
    for m in re.finditer(pat, lib):
        seen.add(m.group().decode())
    for s in sorted(seen):
        print(s)
