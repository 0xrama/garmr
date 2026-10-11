import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
stock = open(os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet.tlbin"), "rb").read()
patched = open(os.path.join(ROOT, "poc", "trustlet_patch", "0706000000000000000000000000004d.tlbin"), "rb").read()
new = open(os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet_20_5_14.tlbin"), "rb").read()

print(f"stock={len(stock)} patched={len(patched)} new={len(new)}")
assert len(stock) == len(patched)

diffs = []
for i in range(len(stock)):
    if stock[i] != patched[i]:
        diffs.append(i)

# merge into regions
regions = []
for i in diffs:
    if regions and i - regions[-1][1] <= 16:
        regions[-1][1] = i + 1
    else:
        regions.append([i, i + 1])

print(f"\npatched regions (stock -> v2-patched): {len(regions)}")
for s, e in regions:
    print(f"  0x{s:05x}-0x{e:05x}: {stock[s:e].hex(' ')}  ->  {patched[s:e].hex(' ')}")

print("\n20-5-14 status of those regions:")
for s, e in regions:
    same = new[s:e] == stock[s:e]
    print(f"  0x{s:05x}-0x{e:05x}: new={'STOCK-IDENTICAL (patch applies as-is)' if same else 'CHANGED: ' + new[s:e].hex(' ')}")

# also: where do new and stock differ at all (top regions)?
d2 = []
for i in range(min(len(stock), len(new))):
    if stock[i] != new[i]:
        d2.append(i)
r2 = []
for i in d2:
    if r2 and i - r2[-1][1] <= 8:
        r2[-1][1] = i + 1
    else:
        r2.append([i, i + 1])
print(f"\nnew-vs-stock differing regions: {len(r2)} (first 20):")
for s, e in r2[:20]:
    print(f"  0x{s:05x}-0x{e:05x} ({e - s}B): {stock[s:min(e, s + 12)].hex(' ')} -> {new[s:min(e, s + 12)].hex(' ')}")
