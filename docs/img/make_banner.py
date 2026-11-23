"""Builds docs/img/banner-dark.svg and docs/img/banner-light.svg for the README.

One mark per case in the lab, in order: short green where the result matched the guess written
before the code, tall red where the guess was wrong. The marks sweep in once and the wrong ones
pop; with reduced motion the banner stands still. Data: the site's case catalogue.

Run: python3 docs/img/make_banner.py                       (reads the live catalogue)
     python3 docs/img/make_banner.py path/to/catalogue.json
"""
import json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "https://roshantrivedi.co.in/data/catalogue.json"
if len(sys.argv) > 1:
    cat = json.load(open(sys.argv[1], encoding="utf-8"))
else:
    req = urllib.request.Request(URL, headers={"User-Agent": "ai-governance-lab-readme"})
    cat = json.loads(urllib.request.urlopen(req, timeout=30).read())
kinds = ["bad" if c["guess"] == "Guess was wrong" else "ok" for c in cat["cases"] if c["lab"] == "agl"]
n, wrong = len(kinds), kinds.count("bad")

THEMES = {
    "dark":  dict(bg="#05061a", line="#1f2a40", ink="#e8eefc", sub="#a9b6d3", ok="#34d399", bad="#fb7185", acc="#8b5cf6", cyan="#4de2ff"),
    "light": dict(bg="#f7f9ff", line="#d5dcec", ink="#0b1230", sub="#4a5675", ok="#047857", bad="#be123c", acc="#6d3fe0", cyan="#0a7f93"),
}
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace"
W, H = 1200, 300


def svg(c):
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d">',
         '<title id="t">AI Governance Lab</title>',
         f'<desc id="d">Do AI governance controls hold? 13 rounds and {n} cases on made-up data, each guess committed before the code. '
         f'One mark per case: {n - wrong} matched the guess, {wrong} did not.</desc>',
         ('<style>'
          '.marks{animation:sweep 2s cubic-bezier(.3,.7,.2,1) .4s both}'
          '@keyframes sweep{from{clip-path:inset(0 100% 0 0)}to{clip-path:inset(0 0 0 0)}}'
          '.bad{transform-box:fill-box;transform-origin:50% 100%;animation:pop .6s ease-out 2.4s both}'
          '@keyframes pop{0%,100%{transform:scaleY(1)}45%{transform:scaleY(1.35)}}'
          '@media (prefers-reduced-motion: reduce){.marks,.bad{animation:none}}'
          '</style>'),
         f'<rect width="{W}" height="{H}" rx="18" fill="{c["bg"]}"/>',
         f'<rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="18" fill="none" stroke="{c["line"]}"/>',
         f'<g font-family="{SANS}">',
         f'<text x="56" y="66" font-family="{MONO}" font-size="15" letter-spacing="3" fill="{c["cyan"]}">OPEN LAB · MADE-UP DATA · GUESSES COMMITTED FIRST</text>',
         f'<text x="56" y="122" font-size="48" font-weight="800" fill="{c["ink"]}">AI Governance Lab</text>',
         f'<text x="56" y="160" font-size="21" fill="{c["sub"]}">Do the controls hold when someone pushes on them? 13 rounds, {n} cases.</text>']
    x0, x1, base = 56, 1144, 248
    pitch = (x1 - x0) / n
    w = max(2, pitch * 0.62)
    o.append('<g class="marks">')
    for i, k in enumerate(kinds):
        x = x0 + i * pitch
        if k == "bad":
            o.append(f'<rect class="bad" x="{x:.1f}" y="{base - 40}" width="{w:.1f}" height="40" rx="1" fill="{c["bad"]}"/>')
        else:
            o.append(f'<rect x="{x:.1f}" y="{base - 16}" width="{w:.1f}" height="16" rx="1" fill="{c["ok"]}"/>')
    o.append('</g>')
    o += [f'<text x="56" y="276" font-size="14" fill="{c["sub"]}">One mark per case. Tall red: my guess was wrong ({wrong}). Short green: it matched ({n - wrong}).</text>',
          '</g>', '</svg>']
    return "\n".join(o) + "\n"


for name, c in THEMES.items():
    with open(os.path.join(HERE, f"banner-{name}.svg"), "w", encoding="utf-8") as f:
        f.write(svg(c))
print("banner written:", n, "cases,", wrong, "wrong")
