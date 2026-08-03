"""
BOLAHawk PDF Report Generator
------------------------------
Generates a polished, color-coded OWASP API Security assessment report.

Public entry point (unchanged signature so existing callers keep working):

    build_pdf_report(context: dict, output_path: str) -> str

Expected `context` shape (unchanged from the original module):

    {
        "status": "completed",
        "scan_id": "...",
        "started_at": "...",
        "generated_at": "...",
        "summary": {
            "total_findings": int,
            "highest_score": float,
            "by_severity": {"Critical": n, "High": n, "Medium": n, "Low": n},
        },
        "findings": [
            {
                "title": str, "severity": "Critical|High|Medium|Low",
                "cvss_score": float, "cvss_vector": str,
                "method": str, "endpoint": str, "auth_context": str,
                "check_id": str, "description": str, "evidence": str,
                "remediation": str,
            },
            ...
        ],
    }
"""

from xml.sax.saxutils import escape as _xesc

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Polygon, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
    KeepTogether,
)

# ==============================================================
# Palette
# ==============================================================

PRIMARY = colors.HexColor("#0F172A")     # near-black slate, headings
SECONDARY = colors.HexColor("#334155")   # body text
MUTED = colors.HexColor("#64748B")       # captions / meta
ACCENT = colors.HexColor("#2563EB")      # brand blue
ACCENT_LIGHT = colors.HexColor("#EFF6FF")
LINE = colors.HexColor("#CBD5E1")
PANEL = colors.HexColor("#F8FAFC")
WHITE = colors.white

_SEVERITY_HEX = {
    "Critical": "#B91C1C",
    "High": "#EA580C",
    "Medium": "#CA8A04",
    "Low": "#15803D",
    "None": "#64748B",
}

_SEVERITY_COLORS = {k: colors.HexColor(v) for k, v in _SEVERITY_HEX.items()}

_SEVERITY_TINTS = {
    "Critical": colors.HexColor("#FEF2F2"),
    "High": colors.HexColor("#FFF7ED"),
    "Medium": colors.HexColor("#FEFCE8"),
    "Low": colors.HexColor("#F0FDF4"),
    "None": colors.HexColor("#F8FAFC"),
}

_RISK_COLORS = {
    "CRITICAL": _SEVERITY_COLORS["Critical"],
    "HIGH": _SEVERITY_COLORS["High"],
    "MEDIUM": _SEVERITY_COLORS["Medium"],
    "LOW": _SEVERITY_COLORS["Low"],
    "NONE": _SEVERITY_COLORS["None"],
}

# ==============================================================
# Page geometry — every table width in the document derives from
# this so nothing can ever run off the page edge.
# ==============================================================

PAGE_SIZE = A4
MARGIN = 0.75 * inch
USABLE_WIDTH = PAGE_SIZE[0] - (2 * MARGIN)  # ~6.77in on A4


def _esc(value) -> str:
    """Safely escape dynamic scanner content before it goes into a
    Paragraph's mini-XML markup. Without this, any '<', '>' or '&'
    coming from real evidence/JSON/HTML payloads would break rendering
    or get silently mis-parsed."""
    if value is None:
        return ""
    return _xesc(str(value))


# ==============================================================
# Styles
# ==============================================================

def _styles():
    styles = getSampleStyleSheet()

    def add(name, **kwargs):
        styles.add(ParagraphStyle(name=name, **kwargs))

    add("ReportTitle", fontName="Helvetica-Bold", fontSize=30, leading=34,
        alignment=TA_CENTER, textColor=PRIMARY, spaceAfter=6)
    add("ReportSubtitle", fontName="Helvetica", fontSize=13, leading=18,
        alignment=TA_CENTER, textColor=MUTED, spaceAfter=4)
    add("SectionHeading", fontName="Helvetica-Bold", fontSize=17, leading=20,
        textColor=PRIMARY, spaceBefore=14, spaceAfter=10)
    add("SubHeading", fontName="Helvetica-Bold", fontSize=11.5, leading=15,
        textColor=SECONDARY, spaceBefore=8, spaceAfter=5)
    add("Body", fontName="Helvetica", fontSize=10, leading=15,
        textColor=SECONDARY, alignment=TA_LEFT, wordWrap="CJK")
    add("BodySmall", fontName="Helvetica", fontSize=9, leading=13,
        textColor=SECONDARY, alignment=TA_LEFT, wordWrap="CJK")
    add("CardTitle", fontName="Helvetica-Bold", fontSize=13, leading=16,
        textColor=PRIMARY, wordWrap="CJK")
    add("CardMeta", fontName="Helvetica-Bold", fontSize=11, leading=14,
        textColor=SECONDARY, alignment=TA_CENTER)
    add("TableCellHead", fontName="Helvetica-Bold", fontSize=9.5, leading=13,
        textColor=PRIMARY, wordWrap="CJK")
    add("TableCellBody", fontName="Helvetica", fontSize=9.5, leading=14,
        textColor=SECONDARY, wordWrap="CJK")
    add("InfoBox", fontName="Helvetica", fontSize=10, leading=16,
        textColor=SECONDARY, wordWrap="CJK")
    add("Mono", fontName="Courier", fontSize=8.3, leading=12,
        textColor=colors.HexColor("#111827"), wordWrap="CJK")
    add("MonoLabel", fontName="Helvetica-Bold", fontSize=8.5, leading=11,
        textColor=MUTED)
    add("Badge", fontName="Helvetica-Bold", fontSize=9, alignment=TA_CENTER,
        textColor=WHITE)
    add("PillLabel", fontName="Helvetica-Bold", fontSize=9, alignment=TA_CENTER,
        textColor=PRIMARY)
    add("TocIndex", fontName="Helvetica-Bold", fontSize=9.5, textColor=MUTED)
    add("TocTitle", fontName="Helvetica-Bold", fontSize=10.5, textColor=PRIMARY,
        wordWrap="CJK")
    add("TocMeta", fontName="Helvetica", fontSize=8.5, textColor=MUTED,
        wordWrap="CJK")
    add("FooterBrand", fontName="Helvetica-Bold", fontSize=9.5, textColor=PRIMARY)
    add("FooterMeta", fontName="Helvetica", fontSize=7.5, textColor=MUTED)

    return styles


# ==============================================================
# Small reusable building blocks
# ==============================================================

def _overall_risk(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _severity_of(f: dict) -> str:
    sev = f.get("severity", "None")
    return sev if sev in _SEVERITY_COLORS else "None"


def _pill(text, bg, fg=WHITE, width=1.1 * inch, font_size=9, pad=6):
    """A small rounded-look color chip used for severity/risk labels."""
    style = ParagraphStyle(
        name="PillTxt", fontName="Helvetica-Bold", fontSize=font_size,
        alignment=TA_CENTER, textColor=fg, leading=font_size + 2,
    )
    t = Table([[Paragraph(text, style)]], colWidths=[width])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), pad),
        ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _kv_table(rows, col_widths_fraction, styles, header_bg=ACCENT_LIGHT):
    """A two-column key/value table whose widths are always a fraction
    of USABLE_WIDTH, so it can never overflow the page regardless of
    how long the values are."""
    widths = [USABLE_WIDTH * f for f in col_widths_fraction]
    data = []
    for label, value in rows:
        data.append([
            Paragraph(_esc(label), styles["TableCellHead"]),
            Paragraph(_esc(value), styles["TableCellBody"]),
        ])
    t = Table(data, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), header_bg),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _logo_drawing(size=40):
    """A small vector shield/hawk-mark logo built from primitive shapes,
    so the report never depends on emoji glyph support (which renders
    as a blank box in reportlab's built-in fonts)."""
    d = Drawing(size, size)
    d.add(Polygon(
        points=[
            size * 0.5, size * 0.02,
            size * 0.95, size * 0.20,
            size * 0.95, size * 0.55,
            size * 0.5, size * 0.98,
            size * 0.05, size * 0.55,
            size * 0.05, size * 0.20,
        ],
        fillColor=ACCENT, strokeColor=PRIMARY, strokeWidth=1,
    ))
    d.add(String(size * 0.5, size * 0.33, "BH", fontName="Helvetica-Bold",
                  fontSize=size * 0.32, fillColor=WHITE, textAnchor="middle"))
    return d


# ==============================================================
# Page chrome
# ==============================================================

def _page_chrome(canvas, doc):
    canvas.saveState()
    width, height = PAGE_SIZE

    # Header rule
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, height - 32, width - MARGIN, height - 32)

    canvas.setFont("Helvetica-Bold", 9.5)
    canvas.setFillColor(PRIMARY)
    canvas.drawString(MARGIN, height - 24, "BOLAHawk Security Assessment Report")

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(width - MARGIN, height - 24, "Confidential")

    # Footer rule
    canvas.setStrokeColor(LINE)
    canvas.line(MARGIN, 30, width - MARGIN, 30)

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, 18, "Generated by BOLAHawk \u2014 Automated OWASP API Security Scanner")
    canvas.drawRightString(width - MARGIN, 18, f"Page {doc.page}")

    canvas.restoreState()


# ==============================================================
# Cover page
# ==============================================================

def _cover(context, styles):
    summary = context["summary"]
    highest = summary.get("highest_score", 0) or 0
    risk = _overall_risk(highest)
    risk_color = _RISK_COLORS[risk]

    flow = []
    flow.append(Spacer(1, 40))

    logo = _logo_drawing(46)
    logo.hAlign = "CENTER"
    flow.append(logo)
    flow.append(Spacer(1, 10))

    flow.append(Paragraph("BOLAHawk", styles["ReportTitle"]))
    flow.append(Paragraph("Automated OWASP API Security Assessment Platform",
                           styles["ReportSubtitle"]))
    flow.append(Spacer(1, 14))

    flow.append(HRFlowable(width="55%", thickness=2, color=ACCENT,
                            hAlign="CENTER", spaceAfter=22))

    flow.append(Paragraph("Security Assessment Report", styles["SectionHeading"]))
    flow.append(Spacer(1, 6))

    # Risk badge row, centered
    badge = _pill(risk, risk_color, width=1.6 * inch, font_size=11, pad=9)
    badge_wrap = Table([[badge]], colWidths=[USABLE_WIDTH])
    badge_wrap.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    flow.append(badge_wrap)
    flow.append(Spacer(1, 18))

    rows = [
        ("Assessment Status", context.get("status", "unknown").upper()),
        ("Overall Risk Rating", risk),
        ("Highest CVSS Score", f"{highest:.1f} / 10.0"),
        ("Total Findings", str(summary.get("total_findings", 0))),
        ("Scan Started", context.get("started_at", "\u2014")),
        ("Report Generated", context.get("generated_at", "\u2014")),
        ("Scan ID", context.get("scan_id", "\u2014")),
    ]
    flow.append(_kv_table(rows, [0.38, 0.62], styles))
    flow.append(Spacer(1, 26))

    note = Table([[Paragraph(
        "<b>Confidentiality Notice</b><br/><br/>"
        "This report contains the results of an automated API security "
        "assessment performed using the BOLAHawk platform. It is intended "
        "solely for authorized personnel responsible for the security of "
        "the assessed application. Distribution to unauthorized "
        "individuals is not recommended.",
        styles["InfoBox"])]], colWidths=[USABLE_WIDTH])
    note.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    flow.append(note)

    return flow


# ==============================================================
# Executive summary
# ==============================================================

def _executive_summary(context, styles):
    summary = context["summary"]
    intro = Paragraph(
        "This assessment was performed using the <b>BOLAHawk Automated API "
        "Security Scanner</b> against the supplied REST API. The scanner "
        "evaluates endpoints against the OWASP API Security Top 10 using "
        "active security testing, authentication analysis, authorization "
        "validation and CVSS v3.1 risk scoring."
        "<br/><br/>"
        f"The assessment completed successfully and identified "
        f"<b>{summary.get('total_findings', 0)} confirmed findings</b>. "
        "Immediate remediation is recommended for all <b>Critical</b> "
        "vulnerabilities before production deployment.",
        styles["Body"],
    )
    return [intro]


def _summary_cards(summary, styles):
    order = ["Critical", "High", "Medium", "Low"]
    labels = [("Total\nFindings", str(summary.get("total_findings", 0)), PRIMARY, PANEL)]
    for sev in order:
        count = summary.get("by_severity", {}).get(sev, 0)
        labels.append((sev, str(count), _SEVERITY_COLORS[sev], _SEVERITY_TINTS[sev]))

    n = len(labels)
    col_w = USABLE_WIDTH / n
    label_hex = ["#0F172A"] + [_SEVERITY_HEX[sev] for sev in order]
    row_num = [Paragraph(f"<font size=20 color='{label_hex[i]}'><b>{val}</b></font>",
                          ParagraphStyle("num", alignment=TA_CENTER))
               for i, (name, val, lc, bg) in enumerate(labels)]
    row_label = [Paragraph(f"<b>{name}</b>", ParagraphStyle(
        "lbl", alignment=TA_CENTER, fontSize=9, textColor=SECONDARY, fontName="Helvetica-Bold"))
        for (name, val, lc, bg) in labels]

    t = Table([row_num, row_label], colWidths=[col_w] * n)
    style_cmds = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 0), 14),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 14),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("LINEBELOW", (0, 0), (-1, 0), 0, WHITE),
    ]
    for i, (name, val, lc, bg) in enumerate(labels):
        style_cmds.append(("BACKGROUND", (i, 0), (i, 1), bg))
    t.setStyle(TableStyle(style_cmds))
    return t


def _severity_chart_with_legend(summary):
    """Pie chart plus an explicit legend table (rather than pie labels,
    which overlap badly when a slice is small or zero)."""
    order = ["Critical", "High", "Medium", "Low"]
    values = [summary.get("by_severity", {}).get(s, 0) for s in order]
    total = sum(values)

    if total == 0:
        return None

    drawing = Drawing(200, 170)
    pie = Pie()
    pie.x = 15
    pie.y = 5
    pie.width = 160
    pie.height = 160
    pie.data = values
    pie.labels = None
    pie.simpleLabels = False
    pie.sideLabels = False
    for i, sev in enumerate(order):
        pie.slices[i].fillColor = _SEVERITY_COLORS[sev]
        pie.slices[i].strokeColor = WHITE
        pie.slices[i].strokeWidth = 1.5
    drawing.add(pie)

    legend_rows = []
    for sev, val in zip(order, values):
        pct = (val / total * 100) if total else 0
        swatch = Table([[""]], colWidths=[0.16 * inch], rowHeights=[0.16 * inch])
        swatch.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), _SEVERITY_COLORS[sev])]))
        legend_rows.append([
            swatch,
            Paragraph(f"<b>{sev}</b>", ParagraphStyle("lg", fontSize=9.5, textColor=SECONDARY)),
            Paragraph(f"{val} ({pct:.0f}%)", ParagraphStyle("lg2", fontSize=9.5, textColor=MUTED, alignment=TA_LEFT)),
        ])
    legend = Table(legend_rows, colWidths=[0.28 * inch, 1.1 * inch, 1.1 * inch])
    legend.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    combo = Table([[drawing, legend]], colWidths=[2.4 * inch, USABLE_WIDTH - 2.4 * inch])
    combo.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
    ]))
    return combo


# ==============================================================
# Findings index (quick-reference table of contents for findings)
# ==============================================================

def _findings_index(findings, styles):
    if not findings:
        return None

    header = [
        Paragraph("#", styles["TocIndex"]),
        Paragraph("Finding", styles["TocIndex"]),
        Paragraph("Severity", styles["TocIndex"]),
        Paragraph("CVSS", styles["TocIndex"]),
        Paragraph("Endpoint", styles["TocIndex"]),
    ]
    rows = [header]
    for i, f in enumerate(findings, start=1):
        sev = _severity_of(f)
        rows.append([
            Paragraph(str(i), styles["TocMeta"]),
            Paragraph(_esc(f.get("title", "Untitled finding")), styles["TocTitle"]),
            _pill(sev.upper(), _SEVERITY_COLORS[sev], width=0.85 * inch, font_size=7.5, pad=4),
            Paragraph(f"{f.get('cvss_score', 0):.1f}", styles["TocMeta"]),
            Paragraph(_esc(f"{f.get('method', '')} {f.get('endpoint', '')}".strip()),
                       styles["TocMeta"]),
        ])

    widths = [w * USABLE_WIDTH for w in (0.05, 0.32, 0.15, 0.08, 0.40)]
    t = Table(rows, colWidths=widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (3, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    for r in range(1, len(rows)):
        if r % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, r), (-1, r), PANEL))
    t.setStyle(TableStyle(style_cmds))
    return t


# ==============================================================
# Finding card
# ==============================================================

def _panel(paragraph_flowables, bg, border, pad=10):
    inner = paragraph_flowables if isinstance(paragraph_flowables, list) else [paragraph_flowables]
    t = Table([[inner]], colWidths=[USABLE_WIDTH - 0.14 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.45, border),
        ("TOPPADDING", (0, 0), (-1, -1), pad),
        ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
        ("LEFTPADDING", (0, 0), (-1, -1), pad),
        ("RIGHTPADDING", (0, 0), (-1, -1), pad),
    ]))
    return t


def _finding_header(index, f, styles):
    sev = _severity_of(f)
    sev_color = _SEVERITY_COLORS[sev]
    sev_hex = _SEVERITY_HEX[sev]

    badge = _pill(sev.upper(), sev_color, width=1.1 * inch, font_size=9.5, pad=7)
    title = Paragraph(f"<b>{index}. {_esc(f.get('title', 'Untitled finding'))}</b>", styles["CardTitle"])
    cvss_val = f.get("cvss_score", 0) or 0
    cvss = Paragraph(f"<font color='{sev_hex}'><b>CVSS {cvss_val:.1f}</b></font>",
                      ParagraphStyle("cvssTxt", fontSize=10.5, alignment=TA_CENTER))

    header = Table([[badge, title, cvss]],
                    colWidths=[1.25 * inch, USABLE_WIDTH - 1.25 * inch - 1.0 * inch, 1.0 * inch])
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    info_rows = [
        ("Affected Endpoint", f"{f.get('method', '')} {f.get('endpoint', '')}".strip() or "\u2014"),
        ("Authentication Context", f.get("auth_context", "\u2014")),
        ("Scanner Module", f.get("check_id", "\u2014")),
        ("OWASP Category", f.get("owasp_category", "OWASP API Security Top 10")),
    ]
    info = _kv_table(info_rows, [0.32, 0.68], styles)

    # The left column has no content of its own — its BACKGROUND fill
    # (set below) automatically stretches to match the row height of the
    # content column, producing a colored accent strip beside the card.
    strip = Table([["", Table([[header], [Spacer(1, 6)], [info]],
                               colWidths=[USABLE_WIDTH - 0.16 * inch])]],
                   colWidths=[0.09 * inch, USABLE_WIDTH - 0.09 * inch])
    strip.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("BACKGROUND", (0, 0), (0, 0), sev_color),
    ]))
    return strip


def _finding_block(index, f: dict, styles):
    flow = []
    sev = _severity_of(f)
    sev_color = _SEVERITY_COLORS[sev]
    sev_tint = _SEVERITY_TINTS[sev]

    flow.append(KeepTogether(_finding_header(index, f, styles)))
    flow.append(Spacer(1, 10))

    flow.append(Paragraph("Description", styles["SubHeading"]))
    flow.append(Paragraph(_esc(f.get("description", "No description provided.")), styles["Body"]))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Business Impact", styles["SubHeading"]))
    flow.append(_panel(
        Paragraph(
            "Successful exploitation of this vulnerability may allow attackers "
            "to bypass application security controls, gain unauthorized access "
            "to confidential information, perform privileged actions or "
            "compromise critical business functionality. Depending on the "
            "affected endpoint, exploitation could result in unauthorized data "
            "disclosure, privilege escalation or account compromise.",
            styles["Body"]),
        bg=sev_tint, border=sev_color))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Technical Impact", styles["SubHeading"]))
    flow.append(_panel(
        Paragraph(
            "\u2022 Authentication and authorization controls may be bypassed.<br/>"
            "\u2022 Confidential application data may become accessible.<br/>"
            "\u2022 Attackers may execute unauthorized operations.<br/>"
            "\u2022 Integrity of protected resources may be compromised.<br/>"
            "\u2022 Overall security posture is significantly weakened.",
            styles["Body"]),
        bg=PANEL, border=LINE))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Evidence", styles["SubHeading"]))
    evidence_text = _esc(f.get("evidence", "No evidence captured.")).replace("\n", "<br/>")
    flow.append(_panel(
        Paragraph(f"<b>Scanner Output</b><br/><br/>{evidence_text}", styles["Mono"]),
        bg=colors.HexColor("#FAFAFA"), border=colors.HexColor("#D4D4D8")))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("Recommended Remediation", styles["SubHeading"]))
    remediation_text = _esc(f.get("remediation", "No remediation guidance provided."))
    flow.append(_panel(
        Paragraph(
            f"{remediation_text}<br/><br/>"
            "<b>Priority:</b> Immediate<br/>"
            "<b>Recommended Validation:</b> Re-run the BOLAHawk security "
            "assessment after applying the fix to verify the vulnerability "
            "has been fully remediated.",
            styles["Body"]),
        bg=colors.HexColor("#ECFDF5"), border=colors.HexColor("#86EFAC")))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("CVSS v3.1 Vector", styles["SubHeading"]))
    flow.append(_panel(
        Paragraph(_esc(f.get("cvss_vector", "\u2014")), styles["Mono"]),
        bg=PANEL, border=LINE, pad=8))
    flow.append(Spacer(1, 8))

    flow.append(Paragraph("References", styles["SubHeading"]))
    flow.append(_panel(
        Paragraph(
            "\u2022 OWASP API Security Top 10 (2023)<br/>"
            "\u2022 CVSS v3.1 Specification (FIRST)<br/>"
            "\u2022 CWE (Common Weakness Enumeration)<br/>"
            "\u2022 BOLAHawk Automated Security Scanner",
            styles["Body"]),
        bg=PANEL, border=LINE))

    flow.append(Spacer(1, 14))
    flow.append(HRFlowable(width="100%", thickness=0.75, color=LINE))
    flow.append(Spacer(1, 18))

    return flow


# ==============================================================
# Methodology / appendix section
# ==============================================================

def _methodology_section(context, styles):
    flow = []

    flow.append(Paragraph("Assessment Methodology", styles["SectionHeading"]))
    flow.append(Paragraph(
        "The security assessment was performed using the <b>BOLAHawk "
        "Automated API Security Scanner</b>. The scanner combines active "
        "security testing, authentication analysis, authorization "
        "validation, response inspection and CVSS v3.1 based risk scoring, "
        "following industry best practices derived from the "
        "<b>OWASP API Security Top 10 (2023)</b>.",
        styles["Body"]))
    flow.append(Spacer(1, 14))

    flow.append(Paragraph("Assessment Scope", styles["SectionHeading"]))
    scope_rows = [
        ("Assessment Type", "Automated API Security Assessment"),
        ("Target", "REST API"),
        ("Authentication", "JWT Authentication"),
        ("Risk Model", "CVSS v3.1"),
        ("Framework", "OWASP API Security Top 10"),
        ("Scanner", "BOLAHawk"),
    ]
    flow.append(_kv_table(scope_rows, [0.32, 0.68], styles))
    flow.append(Spacer(1, 14))

    flow.append(Paragraph("Security Tests Performed", styles["SectionHeading"]))
    tests = [
        "Broken Object Level Authorization (BOLA)",
        "Broken Function Level Authorization (BFLA)",
        "Mass Assignment Detection",
        "JWT Security Analysis",
        "Authentication Validation",
        "Authorization Verification",
        "Rate Limiting Detection",
        "Response Analysis",
        "CVSS Risk Scoring",
        "Automated Evidence Collection",
    ]
    mid = (len(tests) + 1) // 2
    col1 = "<br/>".join(f"\u2022 {t}" for t in tests[:mid])
    col2 = "<br/>".join(f"\u2022 {t}" for t in tests[mid:])
    tests_table = Table(
        [[Paragraph(col1, styles["Body"]), Paragraph(col2, styles["Body"])]],
        colWidths=[USABLE_WIDTH / 2, USABLE_WIDTH / 2],
    )
    tests_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    flow.append(tests_table)
    flow.append(Spacer(1, 14))

    flow.append(Paragraph("Recommended Remediation Roadmap", styles["SectionHeading"]))
    roadmap_rows = [
        ["Priority", "Action"],
        ["Immediate", "Remediate all Critical vulnerabilities."],
        ["High", "Fix High severity issues before production."],
        ["Medium", "Address Medium findings during hardening."],
        ["Validation", "Run BOLAHawk again after remediation."],
    ]
    widths = [USABLE_WIDTH * 0.28, USABLE_WIDTH * 0.72]
    roadmap = Table(
        [[Paragraph(f"<b>{r[0]}</b>" if i == 0 else r[0], styles["TableCellBody"]),
          Paragraph(r[1], styles["TableCellBody"])]
         for i, r in enumerate(roadmap_rows)],
        colWidths=widths,
    )
    roadmap.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    flow.append(roadmap)
    flow.append(Spacer(1, 14))

    summary = context["summary"]
    highest = summary.get("highest_score", 0) or 0
    flow.append(Paragraph("Executive Conclusion", styles["SectionHeading"]))
    flow.append(Paragraph(
        f"The assessment identified <b>{summary.get('total_findings', 0)} "
        f"confirmed security findings</b>, with an overall risk rating of "
        f"<b>{_overall_risk(highest)}</b>. Critical vulnerabilities should "
        "be remediated immediately before deployment. Following "
        "remediation, the application should undergo another automated "
        "assessment to verify that corrective actions have successfully "
        "eliminated the identified vulnerabilities.",
        styles["Body"]))
    flow.append(Spacer(1, 14))

    flow.append(Paragraph("Disclaimer", styles["SectionHeading"]))
    flow.append(Paragraph(
        f"Report generated automatically by <b>BOLAHawk</b>.<br/><br/>"
        f"Scan ID: {_esc(context.get('scan_id', '\u2014'))}<br/><br/>"
        f"Generated: {_esc(context.get('generated_at', '\u2014'))}<br/><br/>"
        "This report is intended solely for educational, research and "
        "authorized security assessment purposes. Results should be "
        "manually verified before making security decisions.",
        styles["Body"]))

    return flow


# ==============================================================
# Build
# ==============================================================

def build_pdf_report(context: dict, output_path: str) -> str:
    """Generates the BOLAHawk PDF report and returns the output path."""

    doc = SimpleDocTemplate(
        output_path,
        pagesize=PAGE_SIZE,
        topMargin=MARGIN + 6,
        bottomMargin=MARGIN,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
    )

    styles = _styles()
    story = []

    # ---------------- Cover ----------------
    story.extend(_cover(context, styles))
    story.append(PageBreak())

    # ---------------- Executive summary ----------------
    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    story.extend(_executive_summary(context, styles))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Security Overview", styles["SectionHeading"]))
    story.append(_summary_cards(context["summary"], styles))
    story.append(Spacer(1, 16))

    summary = context["summary"]
    highest = summary.get("highest_score", 0) or 0
    risk = _overall_risk(highest)
    risk_note = Table([[Paragraph(
        f"<b>Risk Assessment</b><br/><br/>"
        f"The assessment identified <b>{summary.get('total_findings', 0)} "
        f"confirmed vulnerabilities</b> affecting the target API. The "
        f"highest observed CVSS Base Score is <b>{highest:.1f}</b>, "
        f"resulting in an overall risk classification of <b>{risk}</b>. "
        "Critical vulnerabilities should be remediated immediately before "
        "deployment. High severity issues should be prioritized during "
        "the next development cycle, while Medium severity issues should "
        "be addressed as part of regular hardening activities.",
        styles["InfoBox"])]], colWidths=[USABLE_WIDTH])
    risk_note.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(risk_note)
    story.append(Spacer(1, 18))

    # ---------------- Severity chart ----------------
    story.append(Paragraph("Severity Distribution", styles["SectionHeading"]))
    chart = _severity_chart_with_legend(context["summary"])
    if chart is not None:
        story.append(chart)
    else:
        story.append(Paragraph("No findings were recorded, so no severity "
                                "distribution is available.", styles["Body"]))
    story.append(PageBreak())

    # ---------------- Findings index ----------------
    findings = context.get("findings", []) or []
    index_table = _findings_index(findings, styles)
    if index_table is not None:
        story.append(Paragraph("Findings Index", styles["SectionHeading"]))
        story.append(index_table)
        story.append(PageBreak())

    # ---------------- Detailed findings ----------------
    story.append(Paragraph("Detailed Findings", styles["SectionHeading"]))
    if not findings:
        story.append(Paragraph("No vulnerabilities were detected during "
                                "this assessment.", styles["Body"]))
    else:
        for i, finding in enumerate(findings, start=1):
            story.extend(_finding_block(i, finding, styles))

    story.append(PageBreak())

    # ---------------- Methodology / appendix ----------------
    story.extend(_methodology_section(context, styles))

    doc.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
    return output_path