# Find injected cosmetics that actually match the page they were injected into:
# every "SEL{display:none !important}" pair whose simple id/class token really
# appears in the document is a candidate for hiding real content.
import re
import sys

path = sys.argv[1]
html = open(path, "rb").read().decode("utf-8", "replace")
# Only look at the style blocks we injected (they end with !important).
rules = re.findall(r"([^{}\n]{1,200})\{display:none !important\}", html)
print("hide rules injected:", len(rules))
ids = set(re.findall(r'id="([^"]+)"', html[:600000]))
classes = set()
for attr in re.findall(r'class="([^"]+)"', html[:600000]):
    classes.update(attr.split())
print("ids on page:", len(ids), " classes on page:", len(classes))
hits = []
for sel in rules:
    sel = sel.strip()
    for token in re.split(r"[,\s>+~]+", sel):
        if token.startswith("#") and token[1:] and token[1:] in ids:
            hits.append((sel, token, "id"))
        elif token.startswith(".") and token[1:] and token[1:] in classes:
            hits.append((sel, token, "class"))
print("matching hides:", len(hits))
seen = set()
for sel, token, kind in hits:
    if token in seen:
        continue
    seen.add(token)
    print(f"   {kind} {token}   <- {sel[:120]}")
    if len(seen) > 40:
        print("   ...")
        break
