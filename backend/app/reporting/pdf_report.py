from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)

# ------------------------------------------------------------
# Severity Colors
# ------------------------------------------------------------

_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#d32f2f"),
    "High": colors.HexColor("#f57c00"),
    "Medium": colors.HexColor("#fbc02d"),
    "Low": colors.HexColor("#388e3c"),
    "None": colors.HexColor("#607d8b"),
}


# ------------------------------------------------------------
# Styles
# ------------------------------------------------------------

def _styles():

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            fontName="Helvetica-Bold",
            fontSize=30,
            leading=34,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0b1320"),
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            fontName="Helvetica",
            fontSize=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#666666"),
            spaceAfter=18,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=18,
            textColor=colors.HexColor("#1f2937"),
            spaceBefore=12,
            spaceAfter=10,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Meta",
            fontName="Helvetica",
            fontSize=9,
            alignment=TA_CENTER,
            textColor=colors.grey,
            spaceAfter=18,
        )
    )

    styles.add(
        ParagraphStyle(
            name="CardTitle",
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#111827"),
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="CardMeta",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Label",
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=colors.HexColor("#374151"),
            spaceBefore=6,
            spaceAfter=3,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Body",
            fontName="Helvetica",
            fontSize=10,
            leading=16,
            alignment=TA_LEFT,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Code",
            fontName="Courier",
            fontSize=8,
            leading=10,
            backColor=colors.HexColor("#f5f5f5"),
            borderColor=colors.HexColor("#dddddd"),
            borderWidth=0.5,
            borderPadding=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="WhiteBadge",
            fontName="Helvetica-Bold",
            fontSize=10,
            alignment=TA_CENTER,
            textColor=colors.white,
        )
    )

    return styles


# ------------------------------------------------------------
# Risk Calculation
# ------------------------------------------------------------

def _overall_risk(score):

    if score >= 9:
        return "CRITICAL"

    if score >= 7:
        return "HIGH"

    if score >= 4:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "NONE"

# ------------------------------------------------------------
# Executive Summary
# ------------------------------------------------------------

def _executive_summary(context, styles):

    highest = context["summary"]["highest_score"]
    risk = _overall_risk(highest)

    rows = [
        ["Status", context["status"]],
        ["Scan ID", context["scan_id"][:8] + "..."],
        ["Started", context["started_at"]],
        ["Generated", context["generated_at"]],
        ["Overall Risk", risk],
        ["Highest CVSS", f"{highest:.1f}"],
    ]

    table = Table(rows, colWidths=[1.6 * inch, 4.9 * inch])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f4f6f8")),
        ("TEXTCOLOR", (0,0), (-1,-1), colors.black),

        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),

        ("FONTNAME", (1,0), (1,-1), "Helvetica"),

        ("BOTTOMPADDING", (0,0), (-1,-1), 8),

        ("TOPPADDING", (0,0), (-1,-1), 8),

        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#d9d9d9")),

        ("BOX", (0,0), (-1,-1), 0.6, colors.HexColor("#cfcfcf")),
    ]))

    return table


# ------------------------------------------------------------
# Dashboard Cards
# ------------------------------------------------------------

def _summary_cards(summary):

    total = summary["total_findings"]

    critical = summary["by_severity"].get("Critical",0)
    high = summary["by_severity"].get("High",0)
    medium = summary["by_severity"].get("Medium",0)
    low = summary["by_severity"].get("Low",0)

    cards = [
        [
            "Total\n{}".format(total),
            "Critical\n{}".format(critical),
            "High\n{}".format(high),
            "Medium\n{}".format(medium),
            "Low\n{}".format(low),
        ]
    ]

    table = Table(cards, colWidths=[1.2*inch]*5)

    table.setStyle(TableStyle([

        ("BOX",(0,0),(-1,-1),0.6,colors.HexColor("#d0d0d0")),

        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#dddddd")),

        ("BACKGROUND",(0,0),(0,0),colors.HexColor("#f7f7f7")),

        ("BACKGROUND",(1,0),(1,0),colors.HexColor("#fdecec")),

        ("BACKGROUND",(2,0),(2,0),colors.HexColor("#fff1e6")),

        ("BACKGROUND",(3,0),(3,0),colors.HexColor("#fff8dd")),

        ("BACKGROUND",(4,0),(4,0),colors.HexColor("#eef8ee")),

        ("TEXTCOLOR",(1,0),(1,0),colors.red),

        ("TEXTCOLOR",(2,0),(2,0),colors.orange),

        ("TEXTCOLOR",(3,0),(3,0),colors.HexColor("#b7950b")),

        ("TEXTCOLOR",(4,0),(4,0),colors.green),

        ("ALIGN",(0,0),(-1,-1),"CENTER"),

        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),

        ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),

        ("FONTSIZE",(0,0),(-1,-1),12),

        ("BOTTOMPADDING",(0,0),(-1,-1),14),

        ("TOPPADDING",(0,0),(-1,-1),14),

    ]))

    return table


# ------------------------------------------------------------
# Severity Pie Chart
# ------------------------------------------------------------

def _severity_chart(summary):

    drawing = Drawing(360,180)

    pie = Pie()

    pie.x = 70
    pie.y = 10

    pie.width = 140
    pie.height = 140

    pie.data = [
        summary["by_severity"].get("Critical",0),
        summary["by_severity"].get("High",0),
        summary["by_severity"].get("Medium",0),
        summary["by_severity"].get("Low",0),
    ]

    pie.labels = [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]

    pie.slices[0].fillColor = colors.HexColor("#d32f2f")
    pie.slices[1].fillColor = colors.HexColor("#f57c00")
    pie.slices[2].fillColor = colors.HexColor("#fbc02d")
    pie.slices[3].fillColor = colors.HexColor("#43a047")

    drawing.add(pie)

    return drawing


# ------------------------------------------------------------
# Page Footer
# ------------------------------------------------------------

def add_page_number(canvas, doc):

    canvas.saveState()

    canvas.setFont("Helvetica",8)

    canvas.setFillColor(colors.grey)

    canvas.drawString(
        35,
        18,
        "Generated by BOLAHawk"
    )

    canvas.drawRightString(
        A4[0]-35,
        18,
        f"Page {doc.page}"
    )

    canvas.restoreState()

# ------------------------------------------------------------
# Finding Card
# ------------------------------------------------------------

def _finding_block(f: dict, styles):

    flow = []

    severity = f.get("severity", "None")
    sev_color = _SEVERITY_COLORS.get(severity, _SEVERITY_COLORS["None"])

    # ------------------------------
    # Severity Badge
    # ------------------------------

    badge = Table(
        [[Paragraph(
            f'<font color="white"><b>{severity.upper()}</b></font>',
            styles["WhiteBadge"]
        )]],
        colWidths=[1.25 * inch],
    )

    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), sev_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.4, sev_color),
    ]))

    # ------------------------------
    # Header
    # ------------------------------

    title = Paragraph(
        f"<b>{f['title']}</b>",
        styles["CardTitle"],
    )

    cvss = Paragraph(
        f"<b>CVSS {f['cvss_score']:.1f}</b>",
        styles["CardMeta"],
    )

    header = Table(
        [
            [badge, title, cvss]
        ],
        colWidths=[1.4 * inch, 4.0 * inch, 1.0 * inch],
    )

    header.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))

    flow.append(header)

    # ------------------------------
    # Endpoint
    # ------------------------------

    endpoint = Table([
        [
            Paragraph("<b>Endpoint</b>", styles["Label"]),
            Paragraph(
                f"{f['method']} {f['endpoint']}",
                styles["Body"]
            )
        ],
        [
            Paragraph("<b>Context</b>", styles["Label"]),
            Paragraph(
                f"{f['auth_context']}",
                styles["Body"]
            )
        ],
        [
            Paragraph("<b>Check ID</b>", styles["Label"]),
            Paragraph(
                f"{f['check_id']}",
                styles["Body"]
            )
        ]
    ], colWidths=[1.3*inch,5.3*inch])

    endpoint.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#f8f9fa")),
        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#dddddd")),
        ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("TOPPADDING",(0,0),(-1,-1),6),
    ]))

    flow.append(endpoint)

    flow.append(Spacer(1,10))

    # ------------------------------
    # Description
    # ------------------------------

    flow.append(
        Paragraph(
            "Description",
            styles["Label"]
        )
    )

    flow.append(
        Paragraph(
            f["description"],
            styles["Body"]
        )
    )

    flow.append(Spacer(1,6))

    # ------------------------------
    # Evidence
    # ------------------------------

    flow.append(
        Paragraph(
            "Evidence",
            styles["Label"]
        )
    )

    evidence = Table([
        [
            Paragraph(
                f["evidence"],
                styles["Code"]
            )
        ]
    ])

    evidence.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#f7f7f7")),
        ("BOX",(0,0),(-1,-1),0.4,colors.HexColor("#d0d0d0")),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),8),
    ]))

    flow.append(evidence)

    flow.append(Spacer(1,6))

    # ------------------------------
    # Recommendation
    # ------------------------------

    flow.append(
        Paragraph(
            "Recommendation",
            styles["Label"]
        )
    )

    recommendation = Table([
        [
            Paragraph(
                f["remediation"],
                styles["Body"]
            )
        ]
    ])

    recommendation.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#eef7ff")),
        ("BOX",(0,0),(-1,-1),0.4,colors.HexColor("#bcd7ff")),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),8),
    ]))

    flow.append(recommendation)

    flow.append(Spacer(1,6))

    # ------------------------------
    # CVSS Vector
    # ------------------------------

    flow.append(
        Paragraph(
            "CVSS Vector",
            styles["Label"]
        )
    )

    flow.append(
        Paragraph(
            f["cvss_vector"],
            styles["Code"]
        )
    )

    flow.append(Spacer(1,18))

    flow.append(
        HRFlowable(
            width="100%",
            color=colors.HexColor("#dddddd"),
            thickness=0.6,
        )
    )

    flow.append(Spacer(1,18))

    return flow

def build_pdf_report(context: dict, output_path: str) -> str:
    """
    Generates the professional BOLAHawk PDF report.
    """

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=0.55 * inch,
        bottomMargin=0.60 * inch,
        leftMargin=0.60 * inch,
        rightMargin=0.60 * inch,
    )

    styles = _styles()
    story = []

    # ==========================================================
    # COVER
    # ==========================================================

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "BOLAHawk",
            styles["ReportTitle"]
        )
    )

    story.append(
        Paragraph(
            "Automated OWASP API Security Scanner",
            styles["ReportSubtitle"]
        )
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            styles["SectionHeading"]
        )
    )

    story.append(
        HRFlowable(
            width="100%",
            thickness=1.5,
            color=colors.HexColor("#1565c0"),
        )
    )

    story.append(Spacer(1, 20))

    # ==========================================================
    # EXECUTIVE SUMMARY
    # ==========================================================

    story.append(
        Paragraph(
            "Executive Summary",
            styles["SectionHeading"]
        )
    )

    story.append(_executive_summary(context, styles))

    story.append(Spacer(1, 15))

    # ==========================================================
    # DASHBOARD
    # ==========================================================

    story.append(
        Paragraph(
            "Security Overview",
            styles["SectionHeading"]
        )
    )

    story.append(_summary_cards(context["summary"]))

    story.append(Spacer(1, 18))

    # ==========================================================
    # PIE CHART
    # ==========================================================

    story.append(
        Paragraph(
            "Severity Distribution",
            styles["SectionHeading"]
        )
    )

    story.append(_severity_chart(context["summary"]))

    story.append(PageBreak())

    # ==========================================================
    # FINDINGS
    # ==========================================================

    story.append(
        Paragraph(
            "Detailed Findings",
            styles["SectionHeading"]
        )
    )

    if not context["findings"]:

        story.append(
            Paragraph(
                "No vulnerabilities were detected during this assessment.",
                styles["Body"]
            )
        )

    else:

        for index, finding in enumerate(context["findings"]):

            story.extend(_finding_block(finding, styles))

            if index != len(context["findings"]) - 1:
                story.append(Spacer(1, 12))

    # ==========================================================
    # FINAL PAGE
    # ==========================================================

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Methodology",
            styles["SectionHeading"]
        )
    )

    story.append(
        Paragraph(
            """
            BOLAHawk evaluates REST APIs against common
            OWASP API Security Top 10 weaknesses using a
            combination of active and passive security testing.

            Checks include:

            • Broken Object Level Authorization (BOLA)

            • Broken Function Level Authorization (BFLA)

            • Mass Assignment

            • JWT Security Misconfigurations

            • Authentication Weaknesses

            • Rate Limiting

            • Authorization Validation

            • Response Analysis

            • Automated Risk Scoring
            """,
            styles["Body"]
        )
    )

    story.append(Spacer(1, 18))

    story.append(
        Paragraph(
            "About this Report",
            styles["SectionHeading"]
        )
    )

    story.append(
        Paragraph(
            f"""
            Report generated by <b>BOLAHawk</b><br/><br/>

            Scan ID:
            {context["scan_id"]}<br/><br/>

            Generated:
            {context["generated_at"]}<br/><br/>

            This report is intended for educational,
            research and authorized security assessment
            purposes only.
            """,
            styles["Body"]
        )
    )

    # ==========================================================
    # BUILD
    # ==========================================================

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )

    return output_path