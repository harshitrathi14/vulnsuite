"""Generate VulnSuite_Executive_Deck.pptx mirroring the HTML executive deck.

Color/font palette approximates the HTML deck:
- Background:  dark navy   (#0A0E1A)
- Card bg:     deep slate  (#131A2E)
- Accent 1:    orange      (#F38020)
- Accent 2:    sky blue    (#7DD3FC)
- Body text:   light slate (#E8ECF4 / #CBD5E1 / #94A3B8)
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pathlib import Path

# ---------- palette (light theme) ----------
BG          = RGBColor(0xF8, 0xFA, 0xFC)   # very light slate page bg
CARD_BG     = RGBColor(0xFF, 0xFF, 0xFF)   # white cards
CARD_BORDER = RGBColor(0xE2, 0xE8, 0xF0)   # slate-200 hairline
ORANGE      = RGBColor(0xF3, 0x80, 0x20)   # accent — kept
ORANGE_SOFT = RGBColor(0xC2, 0x41, 0x0C)   # darker on light bg for legibility
BLUE        = RGBColor(0x1E, 0x40, 0xAF)   # deep blue for sub-headings on white
NAVY        = RGBColor(0x0A, 0x25, 0x40)   # BFSI navy — used for h1/h2 headings
WHITE       = NAVY                         # alias: heading text on light = navy
TRUE_WHITE  = RGBColor(0xFF, 0xFF, 0xFF)   # actual white — only for text on colored chips
TEXT        = RGBColor(0x1E, 0x29, 0x3B)   # slate-800 body
TEXT_DIM    = RGBColor(0x33, 0x41, 0x55)   # slate-700 card body
TEXT_FAINT  = RGBColor(0x64, 0x74, 0x8B)   # slate-500 subdued
PILL_BG     = RGBColor(0xFF, 0xF6, 0xEE)   # cream pill background
P0          = RGBColor(0xB9, 0x1C, 0x1C)
P1          = RGBColor(0xEA, 0x58, 0x0C)
P2          = RGBColor(0xCA, 0x8A, 0x04)
P3          = RGBColor(0x25, 0x63, 0xEB)
P4          = RGBColor(0x6B, 0x72, 0x80)

FONT = "Calibri"

# 16:9 widescreen
SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)


# ---------- helpers ----------

def _set_bg(slide, color):
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.line.fill.background()
    bg.fill.solid()
    bg.fill.fore_color.rgb = color
    bg.shadow.inherit = False
    return bg


def _add_text(slide, left, top, width, height, text, *,
              size=14, bold=False, color=TEXT, align=PP_ALIGN.LEFT,
              anchor=MSO_ANCHOR.TOP, font=FONT):
    tb = slide.shapes.add_textbox(left, top, width, height)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top = tf.margin_bottom = Inches(0.02)
    tf.vertical_anchor = anchor
    p = tf.paragraphs[0]
    p.alignment = align
    r = p.add_run()
    r.text = text
    r.font.name = font
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.color.rgb = color
    return tb


def _add_multi(slide, left, top, width, height, lines, *,
               size=12, color=TEXT_DIM, bullet="▸", bullet_color=ORANGE,
               line_spacing=1.25, align=PP_ALIGN.LEFT):
    """Add a textbox with one paragraph per `lines` entry. Each line gets a
    bullet character in `bullet_color` followed by the text in `color`."""
    tb = slide.shapes.add_textbox(left, top, width, height)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.05)
    tf.margin_top = tf.margin_bottom = Inches(0.02)
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.line_spacing = line_spacing
        if bullet:
            br = p.add_run()
            br.text = f"{bullet}  "
            br.font.name = FONT
            br.font.size = Pt(size)
            br.font.bold = True
            br.font.color.rgb = bullet_color
        tr = p.add_run()
        tr.text = line
        tr.font.name = FONT
        tr.font.size = Pt(size)
        tr.font.color.rgb = color
    return tb


def _add_card(slide, left, top, width, height, *, fill=CARD_BG, border=CARD_BORDER):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.adjustments[0] = 0.06
    card.fill.solid()
    card.fill.fore_color.rgb = fill
    card.line.color.rgb = border
    card.line.width = Pt(0.75)
    card.shadow.inherit = False
    return card


def _add_pill(slide, left, top, text, *, color=ORANGE):
    """Tag-style pill at the top of a slide."""
    width = Inches(0.04 * len(text) + 0.6)
    pill = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, Inches(0.32))
    pill.adjustments[0] = 0.5
    pill.fill.solid()
    pill.fill.fore_color.rgb = PILL_BG
    pill.line.color.rgb = color
    pill.line.width = Pt(0.75)
    pill.shadow.inherit = False
    tf = pill.text_frame
    tf.margin_left = tf.margin_right = Inches(0.12)
    tf.margin_top = tf.margin_bottom = Inches(0.02)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = text
    r.font.name = FONT
    r.font.size = Pt(10)
    r.font.bold = True
    r.font.color.rgb = color
    return pill


def _add_slide_number(slide, num_text):
    _add_text(slide, Inches(11.8), Inches(0.3), Inches(1.4), Inches(0.3),
              num_text, size=10, color=RGBColor(0xCB, 0xD5, 0xE1), align=PP_ALIGN.RIGHT)


def _add_h1(slide, left, top, width, height, text, *, size=44, color=NAVY):
    return _add_text(slide, left, top, width, height, text, size=size,
                     bold=True, color=color)


def _add_h2(slide, left, top, width, height, text, *, size=32, color=WHITE):
    return _add_text(slide, left, top, width, height, text, size=size,
                     bold=True, color=color)


def _accent_h2(slide, left, top, width, height, normal, accent):
    """h2 with two-tone wording: normal text white, accent in orange."""
    tb = slide.shapes.add_textbox(left, top, width, height)
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    r1 = p.add_run(); r1.text = normal + " "
    r1.font.name = FONT; r1.font.size = Pt(32); r1.font.bold = True; r1.font.color.rgb = WHITE
    r2 = p.add_run(); r2.text = accent
    r2.font.name = FONT; r2.font.size = Pt(32); r2.font.bold = True; r2.font.color.rgb = ORANGE
    return tb


def _module_card(slide, left, top, width, height, title, bullets):
    _add_card(slide, left, top, width, height)
    _add_text(slide, left + Inches(0.25), top + Inches(0.18),
              width - Inches(0.5), Inches(0.4),
              title, size=15, bold=True, color=ORANGE)
    _add_multi(slide, left + Inches(0.25), top + Inches(0.65),
               width - Inches(0.5), height - Inches(0.7),
               bullets, size=10.5, color=TEXT_DIM, line_spacing=1.2)


# ---------- slide builders ----------

prs = Presentation()
prs.slide_width = SLIDE_W
prs.slide_height = SLIDE_H
BLANK = prs.slide_layouts[6]


# 01 — Cover
def slide_cover():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "01 / COVER")
    _add_text(s, Inches(0.9), Inches(1.4), Inches(2), Inches(1.2),
              "🛡️", size=72)
    _add_pill(s, Inches(0.95), Inches(2.55), "INTRODUCING")
    _add_h1(s, Inches(0.85), Inches(2.95), Inches(11.5), Inches(1.4),
            "VulnSuite", size=68)
    _add_text(s, Inches(0.95), Inches(4.4), Inches(11.4), Inches(1.7),
              "A BFSI-native, multi-tool, risk-prioritized cybersecurity "
              "vulnerability analysis platform spanning code, IaC, runtime, "
              "perimeter, API, supply chain, and multi-cloud — Azure + AWS + GCP. "
              "Built for Indian banking. Aligned to RBI CSF and CERT-In from the "
              "ground up.",
              size=16, color=TEXT_FAINT)
    _add_text(s, Inches(0.95), Inches(6.6), Inches(11.4), Inches(0.4),
              "CONFIDENTIAL — INTERNAL USE ONLY · Prepared for CISO Review",
              size=10, color=RGBColor(0x64, 0x74, 0x8B))


# 02 — What it addresses (no invented numbers)
def slide_problem():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "02 / WHAT IT ADDRESSES")
    _add_pill(s, Inches(0.85), Inches(0.85), "WHAT VULNSUITE ADDRESSES")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.5),
               "Four gaps in", "conventional vulnerability scanning.")

    cards = [
        ("Tools, no risk lens",
         "Scanners produce raw findings without business-risk prioritization. Severity ≠ exploitability ≠ blast radius."),
        ("Findings, no citations",
         "Auditors expect RBI CSF / CERT-In / CIS / NIST traceability per finding. Most scanners stop at CVE IDs."),
        ("Cloud, no parity",
         "Azure, AWS, and GCP each carry their own console, severity scale, and compliance pack. No unified view."),
        ("Code, no trust chain",
         "No continuity from SBOM → signature → SLSA attestation → VEX. Supply-chain risk lives in slides, not pipelines."),
    ]
    card_w = Inches(2.85); card_h = Inches(2.4); gap = Inches(0.2)
    total_w = card_w * 4 + gap * 3
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(3.05)
    for i, (title, body) in enumerate(cards):
        x = start_x + i * (card_w + gap)
        _add_card(s, x, y, card_w, card_h)
        _add_text(s, x + Inches(0.25), y + Inches(0.2),
                  card_w - Inches(0.5), Inches(0.55),
                  title, size=14, bold=True, color=ORANGE)
        _add_text(s, x + Inches(0.25), y + Inches(0.85),
                  card_w - Inches(0.5), card_h - Inches(1.0),
                  body, size=11, color=TEXT_DIM)

    _add_text(s, Inches(0.85), Inches(5.85), Inches(11.5), Inches(1.4),
              "VulnSuite addresses all four in a single platform, with passive-only "
              "enforcement and air-gap support as defaults — engineered for BFSI "
              "from the schema up.",
              size=13, color=TEXT_FAINT)


# 03 — Solution
def slide_solution():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "03 / THE SOLUTION")
    _add_pill(s, Inches(0.85), Inches(0.85), "THE SOLUTION")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.5),
               "One platform.", "One risk lens. One compliance story.")

    cards = [
        ("🎯  Risk-Prioritized",
         "CVSS × EPSS × criticality × exposure collapses raw scanner output into a focused P0–P4 queue."),
        ("🏛️  Compliance-Native",
         "RBI CSF, CERT-In, ISO 27001, CIS, NIST citations embedded in every finding."),
        ("🔒  Passive & Air-Gap Ready",
         "No exploitation. Offline modes for every network dependency. BFSI audit-safe."),
    ]
    card_w = Inches(3.85); card_h = Inches(2.6)
    gap = Inches(0.25)
    total_w = card_w * 3 + gap * 2
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(3.4)
    for i, (title, body) in enumerate(cards):
        x = start_x + i * (card_w + gap)
        _add_card(s, x, y, card_w, card_h)
        _add_text(s, x + Inches(0.3), y + Inches(0.3),
                  card_w - Inches(0.6), Inches(0.5),
                  title, size=18, bold=True, color=ORANGE)
        _add_text(s, x + Inches(0.3), y + Inches(1.0),
                  card_w - Inches(0.6), card_h - Inches(1.2),
                  body, size=13, color=TEXT_DIM)


# 04 — Risk engine
def slide_risk_engine():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "04 / RISK ENGINE")
    _add_pill(s, Inches(0.85), Inches(0.85), "THE RISK ENGINE")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.5),
               "Math that", "matches business risk.")

    # Formula box
    formula = _add_card(s, Inches(0.85), Inches(2.95), Inches(11.6), Inches(1.05),
                        fill=CARD_BG, border=ORANGE)
    tb = formula.text_frame
    tb.margin_top = tb.margin_bottom = Inches(0.1)
    tb.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tb.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = "risk = CVSS × EPSS × (criticality / 5) × exposure"
    r.font.name = "Consolas"; r.font.size = Pt(24); r.font.bold = True
    r.font.color.rgb = ORANGE_SOFT

    inputs = [("CVSS", "0–10 · Technical severity from NVD/vendor"),
              ("EPSS", "0–1 · Exploit probability (FIRST.org, Redis-cached)"),
              ("Criticality", "1–5 · Business tier from asset tags"),
              ("Exposure", "Internet 1.0 · Internal 0.6 · Isolated 0.3")]
    card_w = Inches(2.85); card_h = Inches(1.4); gap = Inches(0.2)
    total_w = card_w * 4 + gap * 3
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(4.25)
    for i, (h, body) in enumerate(inputs):
        x = start_x + i * (card_w + gap)
        _add_card(s, x, y, card_w, card_h)
        _add_text(s, x + Inches(0.2), y + Inches(0.18),
                  card_w - Inches(0.4), Inches(0.4),
                  h, size=14, bold=True, color=BLUE)
        _add_text(s, x + Inches(0.2), y + Inches(0.6),
                  card_w - Inches(0.4), Inches(0.7),
                  body, size=10.5, color=TEXT_FAINT)

    # Bucket strip
    buckets = [("P0 ≥ 7.0", "CERT-In clock", P0),
               ("P1 ≥ 4.5", "7-day SLA", P1),
               ("P2 ≥ 2.0", "30-day SLA", P2),
               ("P3 ≥ 0.5", "Backlog", P3),
               ("P4 < 0.5", "Info", P4)]
    bw = Inches(2.30); bh = Inches(0.9); bgap = Inches(0.1)
    btotal = bw * 5 + bgap * 4
    bstart = (SLIDE_W - btotal) / 2
    by = Inches(6.05)
    for i, (label, sub, color) in enumerate(buckets):
        bx = bstart + i * (bw + bgap)
        sh = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, bx, by, bw, bh)
        sh.adjustments[0] = 0.18
        sh.fill.solid(); sh.fill.fore_color.rgb = color
        sh.line.fill.background(); sh.shadow.inherit = False
        tf = sh.text_frame
        tf.margin_top = tf.margin_bottom = Inches(0.05)
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        r = p.add_run(); r.text = label
        r.font.name = FONT; r.font.size = Pt(14); r.font.bold = True; r.font.color.rgb = TRUE_WHITE
        p2 = tf.add_paragraph(); p2.alignment = PP_ALIGN.CENTER
        r2 = p2.add_run(); r2.text = sub
        r2.font.name = FONT; r2.font.size = Pt(9); r2.font.color.rgb = TRUE_WHITE


# 05 — Scanner coverage
def slide_coverage():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "05 / SCANNER COVERAGE")
    _add_pill(s, Inches(0.85), Inches(0.85), "12 MODULES · 1 SCHEMA · 1 RISK LENS")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.5),
               "Belt-and-braces", "by design.")

    rows = [
        ("SCA",          "Trivy · pip-audit · OSV-Scanner",                   "Triple-corroborated CVEs (NVD/PyPA/OSV.dev)"),
        ("Secrets",      "gitleaks · TruffleHog",                              "Hardcoded creds with live cloud verification"),
        ("SAST",         "Semgrep · Bandit",                                   "OWASP Top 10 + Python crypto pitfalls"),
        ("Network",      "nmap (passive) · testssl.sh",                        "Services + TLS hygiene with RBI Annex-I citations"),
        ("Cloud",        "Prowler Azure · AWS · GCP",                          "CIS + ISO + NIST across all hyperscalers"),
        ("Container",    "Trivy image · Dockle",                               "Image CVEs + CIS Docker hardening"),
        ("IaC",          "Checkov · Trivy config",                             "Terraform · Bicep · Helm · K8s · OpenAPI"),
        ("Kubernetes",   "Kubescape · kubectl + Trivy",                        "NSA + CIS posture and every running image"),
        ("ASM",          "Subfinder · httpx · TestSSL",                        "Passive subdomain + service + TLS exposure"),
        ("API Security", "Nuclei · OWASP ZAP (gated)",                         "OpenAPI-driven DAST, triple-gated allowlist"),
        ("Supply Chain", "Syft · Cosign · VEX",                                "SBOM + signed + SLSA-attested + VEX-suppressed"),
        ("Discovery",    "Azure RG · AWS CLI · gcloud · Subfinder · kubectl",  "Auto-inventory across cloud, perimeter, and clusters"),
    ]
    cols = [Inches(2.0), Inches(4.4), Inches(5.5)]
    x0 = Inches(0.85)
    y0 = Inches(2.85)
    row_h = Inches(0.36)

    # header
    for i, (h, w) in enumerate(zip(("MODULE", "TOOLS", "WHAT IT CATCHES"), cols)):
        x = x0 + sum(cols[:i], Emu(0))
        _add_text(s, x, y0, w, row_h, h, size=10, bold=True, color=ORANGE)
    # underline
    line = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, x0, y0 + Inches(0.32),
                              sum(cols, Emu(0)), Inches(0.02))
    line.fill.solid(); line.fill.fore_color.rgb = ORANGE
    line.line.fill.background(); line.shadow.inherit = False

    for ri, row in enumerate(rows):
        ry = y0 + Inches(0.42) + ri * row_h
        for i, (val, w) in enumerate(zip(row, cols)):
            x = x0 + sum(cols[:i], Emu(0))
            _add_text(s, x, ry, w, row_h, val,
                      size=10.5, bold=(i == 0),
                      color=WHITE if i == 0 else TEXT_DIM)


# 06 — SCA
def slide_sca():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "06 / SCA MODULE")
    _add_pill(s, Inches(0.85), Inches(0.85), "MODULE 01 — SCA")
    _add_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(0.9),
            "Software Composition Analysis", size=32)

    cards = [
        ("Trivy", ["Broad multi-ecosystem", "NVD-first CVSS",
                   "Container + filesystem", "Offline DB support",
                   "15-min hard timeout"]),
        ("pip-audit", ["PyPA Advisory DB",
                       "requirements.txt / pyproject / venv",
                       "Unpatched CVEs → HIGH",
                       "Offline cache mode"]),
        ("OSV-Scanner", ["Google OSV.dev",
                         "npm · Maven · crates · Go",
                         "Often fresher than NVD",
                         "Walks nested fix events"]),
    ]
    card_w = Inches(3.85); card_h = Inches(3.4); gap = Inches(0.25)
    total_w = card_w * 3 + gap * 2
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(2.6)
    for i, (title, bullets) in enumerate(cards):
        x = start_x + i * (card_w + gap)
        _module_card(s, x, y, card_w, card_h, title, bullets)
    _add_text(s, Inches(0.85), Inches(6.3), Inches(11.5), Inches(1),
              "Dedup keyed on (asset, cve, pkg, version). Cross-tool corroboration "
              "trail stored in every finding for audit defensibility.",
              size=12, color=TEXT_FAINT)


# 07 — Secrets + SAST
def slide_secrets_sast():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "07 / SECRETS + SAST")
    _add_pill(s, Inches(0.85), Inches(0.85), "MODULES 02 & 03 — SECRETS & SAST")
    _add_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(0.9),
            "Credentials & code quality")

    cards = [
        ("🔑  gitleaks", ["Regex-based, redact by default",
                          "Commit + author captured for blame",
                          "Severity floor: HIGH",
                          "CWE-798 mapped",
                          "Cloud keys auto → CRITICAL"]),
        ("🔑  TruffleHog", ["LIVE credential verification",
                            "Verified hits → CRITICAL",
                            "CERT-In language in remediation",
                            "Raw values NEVER persisted",
                            "Opt-in egress control"]),
        ("🧪  Semgrep", ["Multi-language SAST",
                         "default + security-audit + OWASP + secrets packs",
                         "--metrics off (BFSI mandate)",
                         "HIGH+HIGH impact/confidence → CRITICAL",
                         "Offline rules dir for air-gap"]),
        ("🧪  Bandit", ["Python AST-driven linter",
                        "3×3 severity × confidence matrix",
                        "Curated fix for MD5, DES, ECB, pickle, yaml.load, shell=True, SQL concat",
                        "Maps to RBI CSF 6.14 SDLC"]),
    ]
    cw = Inches(5.9); ch = Inches(2.4); gap = Inches(0.25)
    cells = [(Inches(0.85), Inches(2.45)),
             (Inches(0.85) + cw + gap, Inches(2.45)),
             (Inches(0.85), Inches(2.45) + ch + gap),
             (Inches(0.85) + cw + gap, Inches(2.45) + ch + gap)]
    for (title, bullets), (x, y) in zip(cards, cells):
        _module_card(s, x, y, cw, ch, title, bullets)


# 08 — Network
def slide_network():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "08 / NETWORK")
    _add_pill(s, Inches(0.85), Inches(0.85), "MODULE 04 — NETWORK (PASSIVE)")
    _add_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(0.9),
            "Services & TLS hygiene")
    cards = [
        ("🔍  nmap (passive)",
         ["-sT -sV only, no SYN, no vuln scripts",
          "T2 polite timing ceiling enforced at __init__",
          "Refuses public CIDRs unless opted in",
          "BFSI severity table: Telnet/rsh → CRITICAL, FTP/RDP/Mongo/Redis → HIGH",
          "CPE extraction for downstream CVE enrichment"]),
        ("🔐  testssl.sh",
         ["Protocols, ciphers, certs, HSTS, TLS vulns",
          "Direct RBI Annex-I clause on every finding (6.2/6.3/6.4/6.5)",
          "Heartbleed, POODLE, ROBOT, FREAK, LOGJAM, DROWN, BEAST, LUCKY13",
          "Remediation names Azure App Gateway / nginx / HAProxy by product"]),
    ]
    cw = Inches(5.9); ch = Inches(4.0); gap = Inches(0.25)
    y = Inches(2.55)
    for i, (title, bullets) in enumerate(cards):
        x = Inches(0.85) + i * (cw + gap)
        _module_card(s, x, y, cw, ch, title, bullets)


# 09 — Cloud + Container + Discovery
def slide_cloud_container():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "09 / CLOUD · CONTAINER · DISCOVERY")
    _add_pill(s, Inches(0.85), Inches(0.85),
              "MODULES 05–07 — CLOUD · CONTAINER · DISCOVERY")
    _add_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(0.9),
            "Multi-cloud posture · Azure + AWS + GCP")
    cards = [
        ("☁️  Prowler — Azure · AWS · GCP",
         ["Read-only credentials only",
          "CIS + ISO 27001 + NIST 800-53",
          "Account / project scoping passed through",
          "OCSF JSON, single Module.CLOUD shape",
          "Failing checks only — no noise"]),
        ("📦  Dockle",
         ["CIS Docker Benchmark",
          "Non-root USER enforcement",
          "Pinned tags, HEALTHCHECK",
          "Content Trust, setuid bits",
          "Runtime secrets check"]),
        ("🗺️  Multi-cloud Inventory",
         ["Azure Resource Graph (KQL)",
          "AWS CLI: ELBv2 + Elastic IPs",
          "gcloud asset search-all-resources",
          "Tag-based criticality (prod→5, dev→1)",
          "Public-facing → exposure INTERNET",
          "Idempotent upsert, nightly via Beat"]),
    ]
    cw = Inches(3.85); ch = Inches(3.9); gap = Inches(0.25)
    total_w = cw * 3 + gap * 2
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(2.55)
    for i, (title, bullets) in enumerate(cards):
        x = start_x + i * (cw + gap)
        _module_card(s, x, y, cw, ch, title, bullets)


# 10 — IaC + Kubernetes
def slide_iac_k8s():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "10 / IAC + KUBERNETES")
    _add_pill(s, Inches(0.85), Inches(0.85), "MODULES 08 & 09 — IAC · KUBERNETES")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "Shift left.", "Land safe.")
    cards = [
        ("📐  Checkov",
         ["Terraform · Plan JSON · Bicep · Helm · K8s · Kustomize · OpenAPI",
          "Policy packs across CIS, NIST, PCI-DSS, SOC 2, ISO",
          "--download-external-modules false (air-gap safe)",
          "RBI CSF 6.4 secure config + 6.14 SDLC"]),
        ("📐  Trivy config",
         ["AVD-ID-keyed misconfiguration corroboration",
          "Pairs with Checkov: only agreed misconfigs rise above informational",
          "Triple-corroboration pattern auditors expect for SCA, now applied to IaC"]),
        ("☸️  Kubescape",
         ["NSA + CIS Kubernetes benchmarks",
          "Live cluster mode with namespace exclusions",
          "Per-control YAML evidence for auditors",
          "RBI CSF 6.3 + 6.4 + 6.13"]),
        ("☸️  K8s Inventory + Trivy",
         ["kubectl get deploy/sts/ds/pod -A → image extraction",
          "Every running image fed back through Trivy under Module.KUBERNETES",
          "Cluster posture + workload CVEs land on the same asset",
          "\"What's running\" matches \"what we scanned\""]),
    ]
    cw = Inches(5.9); ch = Inches(2.4); gap = Inches(0.25)
    cells = [(Inches(0.85), Inches(2.55)),
             (Inches(0.85) + cw + gap, Inches(2.55)),
             (Inches(0.85), Inches(2.55) + ch + gap),
             (Inches(0.85) + cw + gap, Inches(2.55) + ch + gap)]
    for (title, bullets), (x, y) in zip(cards, cells):
        _module_card(s, x, y, cw, ch, title, bullets)


# 11 — ASM
def slide_asm():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "11 / EXTERNAL ATTACK SURFACE")
    _add_pill(s, Inches(0.85), Inches(0.85), "MODULE 10 — ASM")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "What attackers", "see of us.")
    cards = [
        ("🌐  Subfinder",
         ["Passive sources only (Censys, VT, AlienVault, etc.)",
          "Zero probing traffic to our perimeter",
          "Per-root cap (default 500)",
          "Each subdomain becomes a DOMAIN asset"]),
        ("🌐  httpx",
         ["HTTP/HTTPS service fingerprint",
          "Status, title, web server, tech stack, TLS",
          "HTTP on prod ports → MEDIUM (cleartext forbidden)",
          "Feeds asset enrichment, not just a scan"]),
        ("🔐  TestSSL + nmap (opt-in)",
         ["Every discovered host → automatic TLS posture run",
          "nmap validation gated behind explicit opt-in",
          "RBI Annex-I 6.1 inventory + 6.2 crypto + 6.4 hardening"]),
    ]
    cw = Inches(3.85); ch = Inches(3.4); gap = Inches(0.25)
    total_w = cw * 3 + gap * 2
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(2.55)
    for i, (title, bullets) in enumerate(cards):
        x = start_x + i * (cw + gap)
        _module_card(s, x, y, cw, ch, title, bullets)
    _add_text(s, Inches(0.85), Inches(6.2), Inches(11.5), Inches(0.8),
              "Closes the \"shadow IT\" gap. The assets the inventory misses, "
              "the perimeter still tells us about.",
              size=12, color=TEXT_FAINT)


# 12 — API security + Gated DAST
def slide_api_dast():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "12 / API SECURITY + GATED DAST")
    _add_pill(s, Inches(0.85), Inches(0.85), "MODULE 11 — API SECURITY")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "Active testing.", "Failsafe by design.")

    cards = [
        ("⚡  Nuclei",
         ["Community + custom YAML templates",
          "Severity floor configurable (default `medium`)",
          "CVE-tagged hits inherit EPSS — proper exploitability scoring",
          "OWASP API Top 10 + product-specific rule packs"]),
        ("🕷️  OWASP ZAP Automation Framework",
         ["YAML plan: ingest OpenAPI → spider → passive wait → optional active scan",
          "Reports normalized into the same Finding schema",
          "Per-tenant timeout cap (default 20 min)",
          "Both passive (baseline) and active modes available"]),
    ]
    cw = Inches(5.9); ch = Inches(2.0); gap = Inches(0.25)
    y = Inches(2.55)
    for i, (title, bullets) in enumerate(cards):
        x = Inches(0.85) + i * (cw + gap)
        _module_card(s, x, y, cw, ch, title, bullets)

    # Triple-gating callout
    cy = Inches(4.85)
    cw_full = Inches(12.05); ch_full = Inches(2.35)
    _add_card(s, Inches(0.85), cy, cw_full, ch_full, border=ORANGE)
    _add_text(s, Inches(1.05), cy + Inches(0.15), Inches(11.6), Inches(0.45),
              "🛡️  DAST Triple-Gating — production cannot be hit by accident",
              size=14, bold=True, color=ORANGE)
    gates = [
        "Gate 1 · dast_mode flag — must be `baseline` or `active` on the request; default is `off`",
        "Gate 2 · FQDN allowlist — every target URL must match VULNSUITE_APISEC_DAST_ALLOWLIST; enforced both at the API and inside the Celery task",
        "Gate 3 · Active opt-in — dast_mode=active additionally requires VULNSUITE_APISEC_ALLOW_ACTIVE_SCAN=true",
        "Air-gap — offline mode emits a graceful skip, never silently runs without policy",
    ]
    _add_multi(s, Inches(1.05), cy + Inches(0.65),
               cw_full - Inches(0.4), ch_full - Inches(0.7),
               gates, size=11, color=TEXT_DIM, line_spacing=1.2)


# 13 — Supply chain
def slide_supply_chain():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "13 / SUPPLY CHAIN")
    _add_pill(s, Inches(0.85), Inches(0.85), "MODULE 12 — SUPPLY CHAIN")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "SBOM. Signed.", "Attested. Suppressed.")
    cards = [
        ("📋  Syft (SBOM)",
         ["CycloneDX SBOM emit and ingest",
          "Components missing PURL/version → flagged",
          "Every emitted SBOM re-scanned by Trivy in `sbom` mode"]),
        ("🔏  Cosign — Signatures",
         ["Keyless: Sigstore identity + OIDC issuer policy",
          "Air-gap fallback: PEM key",
          "Missing signature → HIGH",
          "Wired through SupplyChainSettings"]),
        ("📜  Cosign — Attestations",
         ["cosign verify-attestation with predicate type",
          "SLSA provenance · SBOM · VEX",
          "Missing required attestation → HIGH",
          "RBI CSF 6.14 SDLC trust chain"]),
        ("📝  VEX (CycloneDX + OpenVEX)",
         ["Auto-detects format per file",
          "not_affected / resolved / fixed → INFO/P4 downgrade",
          "Applied as orchestrator post-processor",
          "Original VEX state preserved on evidence for audit"]),
    ]
    cw = Inches(2.95); ch = Inches(3.4); gap = Inches(0.18)
    total_w = cw * 4 + gap * 3
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(2.55)
    for i, (title, bullets) in enumerate(cards):
        x = start_x + i * (cw + gap)
        _module_card(s, x, y, cw, ch, title, bullets)
    _add_text(s, Inches(0.85), Inches(6.25), Inches(11.5), Inches(0.9),
              "\"This dependency is in our SBOM, signed by our build pipeline, the "
              "provenance attestation matches, and where we accept residual risk it's "
              "a documented VEX statement — not a forgotten ticket.\"",
              size=12, color=TEXT_FAINT)


# 14 — Compliance
def slide_compliance():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "14 / COMPLIANCE")
    _add_pill(s, Inches(0.85), Inches(0.85), "COMPLIANCE-NATIVE")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "Every finding carries a", "citation.")
    cards = [
        ("🏛️  RBI Cyber Security Framework",
         ["6.1 Asset inventory", "6.2 Crypto & TLS",
          "6.3 Patch management", "6.4 Secure configuration",
          "6.5 Certificate & PKI", "6.13 Cloud security",
          "6.14 SDLC", "6.15 Secrets management",
          "6.16 Database security"]),
        ("🚨  CERT-In Directions 28 Apr 2022",
         ["6-hour reporting window auto-tracked",
          "JSON incident packet on every P0",
          "SHA-256 integrity hash",
          "180-day log retention compatible",
          "Upload-ready for incident portal",
          "Never auto-transmitted (human gate)"]),
        ("✅  Additional Frameworks",
         ["ISO 27001:2013 Annex A",
          "NIST 800-53 Rev 5",
          "CIS Azure 2.0 Benchmark",
          "CIS Docker Benchmark",
          "OWASP Top 10",
          "PCI-DSS (opt-in per tenant)"]),
        ("📊  Audit Defensibility",
         ["Tool corroboration trail",
          "Regulatory citation per finding",
          "SHA-256 hash on all PDFs",
          "Operator + timestamp on all actions",
          "Tenant-scoped audit log",
          "Tamper-evident reports"]),
    ]
    cw = Inches(5.9); ch = Inches(2.4); gap = Inches(0.25)
    cells = [(Inches(0.85), Inches(2.55)),
             (Inches(0.85) + cw + gap, Inches(2.55)),
             (Inches(0.85), Inches(2.55) + ch + gap),
             (Inches(0.85) + cw + gap, Inches(2.55) + ch + gap)]
    for (title, bullets), (x, y) in zip(cards, cells):
        _module_card(s, x, y, cw, ch, title, bullets)


# 15 — Architecture
def slide_architecture():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "15 / ARCHITECTURE")
    _add_pill(s, Inches(0.85), Inches(0.85), "ARCHITECTURE")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "Productizable", "from day one.")
    cards = [
        ("⚡  FastAPI",
         ["OIDC + JWT", "4-role RBAC",
          "Tenant-scoped routes", "OpenAPI spec"]),
        ("🔧  Celery Workers",
         ["Redis broker", "4 dedicated queues",
          "Beat scheduler", "Retry discipline"]),
        ("🗄️  PostgreSQL 16",
         ["Row-Level Security", "Tenant kernel isolation",
          "Composite indexes", "DuckDB cold archive"]),
        ("📊  Streamlit",
         ["CISO KPI strip", "CERT-In countdown",
          "MTTR trends", "Compliance tabs"]),
    ]
    cw = Inches(2.85); ch = Inches(3.4); gap = Inches(0.2)
    total_w = cw * 4 + gap * 3
    start_x = (SLIDE_W - total_w) / 2
    y = Inches(2.85)
    for i, (title, bullets) in enumerate(cards):
        x = start_x + i * (cw + gap)
        _module_card(s, x, y, cw, ch, title, bullets)


# 16 — Differentiators
def slide_diff():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "16 / DIFFERENTIATORS")
    _add_pill(s, Inches(0.85), Inches(0.85), "WHY VULNSUITE")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "What makes this", "different.")

    diffs = [
        ("01", "BFSI-native, not BFSI-bolted-on",
         "RBI CSF clauses (6.1, 6.2, 6.3, 6.4, 6.5, 6.13, 6.14, 6.15, 6.16) and CERT-In 6-hour timing are first-class data model concerns across all 12 modules."),
        ("02", "Multi-tool corroboration end-to-end",
         "Triple-corroborated SCA, two-tool secrets, two-tool SAST, two-tool IaC, signature + attestation supply chain — applied uniformly."),
        ("03", "Active testing without production risk",
         "DAST is triple-gated (mode flag + FQDN allowlist + active opt-in). Active scanning of production cannot happen by accident."),
        ("04", "Supply chain trust as a signal, not a slogan",
         "SBOM, keyless Sigstore signature, SLSA provenance attestation, CycloneDX-VEX + OpenVEX downgrade — VEX is the documented last word."),
        ("05", "Multi-cloud parity, single risk lens",
         "Azure + AWS + GCP posture all flow into the same Module.CLOUD shape. No accidental org walks."),
        ("06", "Air-gap is first-class",
         "Every collector has an offline path or graceful skip. Cosign falls back to PEM key when Sigstore is unreachable."),
        ("07", "Findings are actionable",
         "Curated, library-specific remediation ships with every finding from Bandit, Dockle, TestSSL, TruffleHog, Cosign."),
    ]
    y = Inches(2.5)
    for num, head, body in diffs:
        rh = Inches(0.62)
        # left orange bar
        bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                 Inches(0.85), y, Inches(0.06), rh)
        bar.fill.solid(); bar.fill.fore_color.rgb = ORANGE
        bar.line.fill.background(); bar.shadow.inherit = False
        # row card body
        row = _add_card(s, Inches(0.91), y, Inches(11.55), rh,
                        fill=CARD_BG, border=CARD_BORDER)
        row.adjustments[0] = 0.04
        _add_text(s, Inches(1.05), y + Inches(0.07), Inches(0.6), rh - Inches(0.14),
                  num, size=18, bold=True, color=ORANGE,
                  anchor=MSO_ANCHOR.MIDDLE)
        _add_text(s, Inches(1.7), y + Inches(0.06), Inches(4.0), Inches(0.3),
                  head, size=12, bold=True, color=WHITE)
        _add_text(s, Inches(1.7), y + Inches(0.32), Inches(10.7), Inches(0.3),
                  body, size=10, color=TEXT_FAINT)
        y = y + rh + Inches(0.07)


# 17 — Ask
def slide_ask():
    s = prs.slides.add_slide(BLANK)
    _set_bg(s, BG)
    _add_slide_number(s, "17 / ASK")
    _add_pill(s, Inches(0.85), Inches(0.85), "NEXT STEPS")
    _accent_h2(s, Inches(0.85), Inches(1.35), Inches(11.5), Inches(1.0),
               "What we", "need from you.")
    cards = [
        ("01 · Architectural Review",
         "Your sign-off on the design and reference implementation — particular attention to DAST gating, Cosign keyless policy, and SLSA attestation enforcement."),
        ("02 · 30-Day Pilot",
         "Internal pilot covering Azure infra, repos, container registry, Terraform/Bicep modules, two non-prod AKS clusters, public root domains (passive only), one AWS sandbox, one GCP sandbox."),
        ("03 · Platform-Engineering Owner",
         "One CI/CD owner to wire Cosign signing into our build pipelines so supply-chain checks can move from \"report\" to \"block\" in production."),
        ("04 · Strategic Direction",
         "Helm + Alembic for SaaS readiness, SIEM connectors (Splunk/Sentinel) for SOC integration, or automated remediation playbooks — which next?"),
    ]
    cw = Inches(5.9); ch = Inches(1.95); gap = Inches(0.25)
    cells = [(Inches(0.85), Inches(2.7)),
             (Inches(0.85) + cw + gap, Inches(2.7)),
             (Inches(0.85), Inches(2.7) + ch + gap),
             (Inches(0.85) + cw + gap, Inches(2.7) + ch + gap)]
    for (title, body), (x, y) in zip(cards, cells):
        _add_card(s, x, y, cw, ch)
        _add_text(s, x + Inches(0.3), y + Inches(0.2),
                  cw - Inches(0.6), Inches(0.45),
                  title, size=15, bold=True, color=ORANGE)
        _add_text(s, x + Inches(0.3), y + Inches(0.75),
                  cw - Inches(0.6), ch - Inches(0.85),
                  body, size=12, color=TEXT_DIM)
    _add_text(s, Inches(0.85), Inches(7.0), Inches(11.5), Inches(0.4),
              "Thank you. Questions welcome.   ·   "
              "CONFIDENTIAL — INTERNAL USE ONLY · Do not forward without CISO approval",
              size=9, color=RGBColor(0x64, 0x74, 0x8B), align=PP_ALIGN.CENTER)


# ---------- build ----------
slide_cover()
slide_problem()
slide_solution()
slide_risk_engine()
slide_coverage()
slide_sca()
slide_secrets_sast()
slide_network()
slide_cloud_container()
slide_iac_k8s()
slide_asm()
slide_api_dast()
slide_supply_chain()
slide_compliance()
slide_architecture()
slide_diff()
slide_ask()

out = Path("vulnsuite/VulnSuite_Executive_Deck.pptx").resolve()
prs.save(out)
print(f"wrote {out}")
print(f"  slides: {len(prs.slides)}")
print(f"  size:   {out.stat().st_size / 1024:.1f} KB")
