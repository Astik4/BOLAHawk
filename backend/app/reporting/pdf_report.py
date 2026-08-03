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
    "Critical": colors.HexColor("#B91C1C"),
    "High": colors.HexColor("#EA580C"),
    "Medium": colors.HexColor("#CA8A04"),
    "Low": colors.HexColor("#15803D"),
    "None": colors.HexColor("#64748B"),
}


# ------------------------------------------------------------
# Styles
# ------------------------------------------------------------

def _styles():

    styles = getSampleStyleSheet()

    PRIMARY = colors.HexColor("#0F172A")
    SECONDARY = colors.HexColor("#334155")
    MUTED = colors.HexColor("#64748B")
    BLUE = colors.HexColor("#2563EB")

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            fontName="Helvetica-Bold",
            fontSize=34,
            leading=40,
            alignment=TA_CENTER,
            textColor=PRIMARY,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            fontName="Helvetica",
            fontSize=15,
            leading=22,
            alignment=TA_CENTER,
            textColor=MUTED,
            spaceAfter=30,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            fontName="Helvetica-Bold",
            fontSize=19,
            leading=22,
            textColor=PRIMARY,
            borderPadding=4,
            borderWidth=0,
            spaceBefore=18,
            spaceAfter=12,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SubHeading",
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=18,
            textColor=SECONDARY,
            spaceBefore=10,
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Body",
            fontName="Helvetica",
            fontSize=10.5,
            leading=18,
            textColor=SECONDARY,
            alignment=TA_LEFT,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Meta",
            fontName="Helvetica",
            fontSize=9,
            alignment=TA_CENTER,
            textColor=MUTED,
            spaceAfter=20,
        )
    )

    styles.add(
        ParagraphStyle(
            name="CardTitle",
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=PRIMARY,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="CardMeta",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=MUTED,
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Label",
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=PRIMARY,
            spaceBefore=8,
            spaceAfter=4,
        )
    )

    styles.add(
        ParagraphStyle(
            name="InfoBox",
            fontName="Helvetica",
            fontSize=10,
            leading=16,
            textColor=SECONDARY,
            leftIndent=8,
            rightIndent=8,
            borderPadding=10,
            backColor=colors.HexColor("#F8FAFC"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="BolaCode",
            fontName="Courier",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#111827"),
            backColor=colors.HexColor("#F4F4F5"),
            borderColor=colors.HexColor("#D4D4D8"),
            borderWidth=0.5,
            borderPadding=8,
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

    summary = context["summary"]

    highest = summary["highest_score"]
    risk = _overall_risk(highest)

    intro = Paragraph(
        f"""
        This assessment was performed using the <b>BOLAHawk Automated API
        Security Scanner</b> against the supplied REST API. The scanner
        evaluates endpoints against the OWASP API Security Top 10 using
        active security testing, authentication analysis, authorization
        validation and CVSS v3.1 risk scoring.

        <br/><br/>

        The assessment completed successfully and identified
        <b>{summary['total_findings']} confirmed findings</b>.
        Immediate remediation is recommended for all
        <b>Critical</b> vulnerabilities before production deployment.
        """,
        styles["Body"],
    )

    rows = [
        ["Assessment Status", context["status"].upper()],
        ["Overall Risk", risk],
        ["Highest CVSS", f"{highest:.1f}"],
        ["Total Findings", str(summary["total_findings"])],
        ["Scan Started", context["started_at"]],
        ["Report Generated", context["generated_at"]],
        ["Scan ID", context["scan_id"]],
    ]

    table = Table(rows, colWidths=[2.0 * inch, 4.3 * inch])

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EFF6FF")),
        ("BACKGROUND",(1,0),(1,-1),colors.white),

        ("TEXTCOLOR",(0,0),(-1,-1),colors.HexColor("#111827")),

        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("FONTNAME",(1,0),(1,-1),"Helvetica"),

        ("BOTTOMPADDING",(0,0),(-1,-1),10),
        ("TOPPADDING",(0,0),(-1,-1),10),

        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#CBD5E1")),

        ("BOX",(0,0),(-1,-1),0.6,colors.HexColor("#CBD5E1")),

    ]))

    return [
        intro,
        Spacer(1,16),
        table,
    ]

# ------------------------------------------------------------
# Dashboard Cards
# ------------------------------------------------------------

def _summary_cards(summary):

    cards = [

        [
            f"<b><font size=18>{summary['total_findings']}</font></b><br/>Total Findings",

            f"<font color='#DC2626'><b><font size=18>{summary['by_severity'].get('Critical',0)}</font></b></font><br/>Critical",

            f"<font color='#EA580C'><b><font size=18>{summary['by_severity'].get('High',0)}</font></b></font><br/>High",

            f"<font color='#D97706'><b><font size=18>{summary['by_severity'].get('Medium',0)}</font></b></font><br/>Medium",

            f"<font color='#16A34A'><b><font size=18>{summary['by_severity'].get('Low',0)}</font></b></font><br/>Low",

        ]

    ]

    table = Table(cards, colWidths=[1.35 * inch] * 5)

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8FAFC")),

        ("BOX",(0,0),(-1,-1),0.5,colors.HexColor("#CBD5E1")),

        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#E2E8F0")),

        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),

        ("ALIGN",(0,0),(-1,-1),"CENTER"),

        ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),

        ("BOTTOMPADDING",(0,0),(-1,-1),18),

        ("TOPPADDING",(0,0),(-1,-1),18),

    ]))

    return table


# ------------------------------------------------------------
# Severity Pie Chart
# ------------------------------------------------------------

def _severity_chart(summary):

    drawing = Drawing(430,210)

    pie = Pie()

    pie.x = 95
    pie.y = 25

    pie.width = 160
    pie.height = 160

    pie.data = [

        summary["by_severity"].get("Critical",0),

        summary["by_severity"].get("High",0),

        summary["by_severity"].get("Medium",0),

        summary["by_severity"].get("Low",0),

    ]

    pie.labels = [

        f"Critical ({summary['by_severity'].get('Critical',0)})",

        f"High ({summary['by_severity'].get('High',0)})",

        f"Medium ({summary['by_severity'].get('Medium',0)})",

        f"Low ({summary['by_severity'].get('Low',0)})",

    ]

    pie.slices[0].fillColor = colors.HexColor("#DC2626")
    pie.slices[1].fillColor = colors.HexColor("#EA580C")
    pie.slices[2].fillColor = colors.HexColor("#D97706")
    pie.slices[3].fillColor = colors.HexColor("#16A34A")

    pie.slices.strokeWidth = 0.5
    pie.slices.popout = 4

    drawing.add(pie)

    return drawing


# ------------------------------------------------------------
# Page Footer
# ------------------------------------------------------------

def add_page_number(canvas, doc):

    canvas.saveState()

    width, height = A4

    canvas.setStrokeColor(colors.HexColor("#D1D5DB"))
    canvas.setLineWidth(0.4)
    canvas.line(35, height - 32, width - 35, height - 32)

    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(colors.HexColor("#0F172A"))
    canvas.drawString(
        35,
        height - 24,
        "BOLAHawk Security Assessment Report"
    )

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))

    canvas.drawString(
        35,
        18,
        "Confidential • Generated by BOLAHawk"
    )

    canvas.drawRightString(
        width - 35,
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

    # ==========================================================
    # HEADER
    # ==========================================================

    badge = Table(
        [[Paragraph(f"<b>{severity.upper()}</b>", styles["WhiteBadge"])]],
        colWidths=[1.35 * inch],
    )

    badge.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),sev_color),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),8),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
        ("BOX",(0,0),(-1,-1),0.5,sev_color),
    ]))

    title = Paragraph(
        f"<font size=15><b>{f['title']}</b></font>",
        styles["CardTitle"]
    )

    cvss = Paragraph(
        f"<font color='#DC2626'><b>CVSS {f['cvss_score']:.1f}</b></font>",
        styles["CardMeta"]
    )

    header = Table(
        [[badge, title, cvss]],
        colWidths=[1.45*inch,4.3*inch,0.9*inch]
    )

    header.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("BOTTOMPADDING",(0,0),(-1,-1),12),
    ]))

    flow.append(header)

    # ==========================================================
    # INFORMATION TABLE
    # ==========================================================

    info = Table(

        [

            ["Affected Endpoint",f"{f['method']} {f['endpoint']}"],

            ["Authentication Context",f["auth_context"]],

            ["Scanner Module",f["check_id"]],

            ["OWASP Category","OWASP API Security Top 10"],

        ],

        colWidths=[2.15*inch,4.15*inch]

    )

    info.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EFF6FF")),

        ("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#CBD5E1")),

        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8),

    ]))

    flow.append(info)

    flow.append(Spacer(1,12))

    # ==========================================================
    # DESCRIPTION
    # ==========================================================

    flow.append(
        Paragraph(
            "Description",
            styles["SubHeading"]
        )
    )

    flow.append(
        Paragraph(
            f["description"],
            styles["Body"]
        )
    )

    flow.append(Spacer(1,10))

    # ==========================================================
    # BUSINESS IMPACT
    # ==========================================================

    flow.append(
        Paragraph(
            "Business Impact",
            styles["SubHeading"]
        )
    )

    business = Table([[
        Paragraph(

            """
            Successful exploitation of this vulnerability may allow attackers
            to bypass application security controls, gain unauthorized access
            to confidential information, perform privileged actions or
            compromise critical business functionality.

            Depending on the affected endpoint, exploitation could result in
            unauthorized data disclosure, privilege escalation or complete
            compromise of user accounts.
            """,

            styles["Body"]

        )
    ]])

    business.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#FFF7ED")),

        ("BOX",(0,0),(-1,-1),0.45,colors.HexColor("#FDBA74")),

        ("BOTTOMPADDING",(0,0),(-1,-1),10),

        ("TOPPADDING",(0,0),(-1,-1),10),

        ("LEFTPADDING",(0,0),(-1,-1),10),

        ("RIGHTPADDING",(0,0),(-1,-1),10),

    ]))

    flow.append(business)

    flow.append(Spacer(1,10))

       # ==========================================================
    # TECHNICAL IMPACT
    # ==========================================================

    flow.append(
        Paragraph(
            "Technical Impact",
            styles["SubHeading"]
        )
    )

    technical = Table([[
        Paragraph(

            """
            • Authentication and authorization controls may be bypassed.<br/>
            • Confidential application data may become accessible.<br/>
            • Attackers may execute unauthorized operations.<br/>
            • Integrity of protected resources may be compromised.<br/>
            • Security posture of the application is significantly weakened.
            """,

            styles["Body"]

        )
    ]])

    technical.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8FAFC")),

        ("BOX",(0,0),(-1,-1),0.45,colors.HexColor("#CBD5E1")),

        ("BOTTOMPADDING",(0,0),(-1,-1),10),

        ("TOPPADDING",(0,0),(-1,-1),10),

        ("LEFTPADDING",(0,0),(-1,-1),10),

        ("RIGHTPADDING",(0,0),(-1,-1),10),

    ]))

    flow.append(technical)

    flow.append(Spacer(1,10))

    # ==========================================================
    # EVIDENCE
    # ==========================================================

    flow.append(
        Paragraph(
            "Evidence",
            styles["SubHeading"]
        )
    )

    evidence = Table([[
        Paragraph(
            f"<b>Scanner Output</b><br/><br/>{f['evidence']}",
            styles["BolaCode"]
        )
    ]])

    evidence.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#FAFAFA")),

        ("BOX",(0,0),(-1,-1),0.45,colors.HexColor("#D4D4D8")),

        ("BOTTOMPADDING",(0,0),(-1,-1),10),

        ("TOPPADDING",(0,0),(-1,-1),10),

        ("LEFTPADDING",(0,0),(-1,-1),10),

        ("RIGHTPADDING",(0,0),(-1,-1),10),

    ]))

    flow.append(evidence)

    flow.append(Spacer(1,10))

    # ==========================================================
    # REMEDIATION
    # ==========================================================

    flow.append(
        Paragraph(
            "Recommended Remediation",
            styles["SubHeading"]
        )
    )

    remediation = Table([[
        Paragraph(

            f"""
            {f['remediation']}

            <br/><br/>

            <b>Priority:</b> Immediate

            <br/>

            <b>Recommended Validation:</b>
            Re-run the BOLAHawk security assessment after applying the fix
            to verify that the vulnerability has been fully remediated.
            """,

            styles["Body"]

        )
    ]])

    remediation.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#ECFDF5")),

        ("BOX",(0,0),(-1,-1),0.45,colors.HexColor("#86EFAC")),

        ("BOTTOMPADDING",(0,0),(-1,-1),10),

        ("TOPPADDING",(0,0),(-1,-1),10),

        ("LEFTPADDING",(0,0),(-1,-1),10),

        ("RIGHTPADDING",(0,0),(-1,-1),10),

    ]))

    flow.append(remediation)

    flow.append(Spacer(1,10))

    # ==========================================================
    # CVSS
    # ==========================================================

    flow.append(
        Paragraph(
            "CVSS v3.1 Vector",
            styles["SubHeading"]
        )
    )

    cvss = Table([[
        Paragraph(
            f["cvss_vector"],
            styles["BolaCode"]
        )
    ]])

    cvss.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8FAFC")),

        ("BOX",(0,0),(-1,-1),0.45,colors.HexColor("#CBD5E1")),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8),

        ("LEFTPADDING",(0,0),(-1,-1),8),

        ("RIGHTPADDING",(0,0),(-1,-1),8),

    ]))

    flow.append(cvss)

    flow.append(Spacer(1,10))

    # ==========================================================
    # REFERENCES
    # ==========================================================

    flow.append(
        Paragraph(
            "References",
            styles["SubHeading"]
        )
    )

    refs = Table([[
        Paragraph(

            """
            • OWASP API Security Top 10 (2023)<br/>
            • CVSS v3.1 Specification (FIRST)<br/>
            • CWE (Common Weakness Enumeration)<br/>
            • BOLAHawk Automated Security Scanner
            """,

            styles["Body"]

        )
    ]])

    refs.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8FAFC")),

        ("BOX",(0,0),(-1,-1),0.4,colors.HexColor("#CBD5E1")),

        ("BOTTOMPADDING",(0,0),(-1,-1),8),

        ("TOPPADDING",(0,0),(-1,-1),8),

        ("LEFTPADDING",(0,0),(-1,-1),8),

        ("RIGHTPADDING",(0,0),(-1,-1),8),

    ]))

    flow.append(refs)

    flow.append(Spacer(1,15))

    flow.append(

        HRFlowable(

            width="100%",

            thickness=1,

            color=colors.HexColor("#CBD5E1")

        )

    )

    flow.append(Spacer(1,20))

    return flow

def build_pdf_report(context: dict, output_path: str) -> str:
    """
    Generates the professional BOLAHawk PDF report.
    """

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )

    styles = _styles()
    story = []

    # ==========================================================
    # COVER
    # ==========================================================

    story.append(Spacer(1, 30))

    story.append(
        Paragraph(
            "🦅 BOLAHawk",
            styles["ReportTitle"],
        )
    )

    story.append(
        Paragraph(
            "Automated OWASP API Security Assessment Platform",
            styles["ReportSubtitle"],
        )
    )

    story.append(
        HRFlowable(
            width="60%",
            thickness=2,
            color=colors.HexColor("#2563EB"),
            spaceBefore=8,
            spaceAfter=20,
        )
    )

    story.append(
        Paragraph(
            "<b>Security Assessment Report</b>",
            styles["SectionHeading"],
        )
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            f"""
            <b>Assessment Status:</b> {context["status"].upper()}<br/><br/>
            <b>Overall Risk:</b> {_overall_risk(context["summary"]["highest_score"])}<br/><br/>
            <b>Total Findings:</b> {context["summary"]["total_findings"]}<br/><br/>
            <b>Highest CVSS:</b> {context["summary"]["highest_score"]:.1f}<br/><br/>
            <b>Assessment Date:</b> {context["generated_at"]}<br/><br/>
            <b>Generated By:</b> BOLAHawk Automated Scanner
            """,
            styles["InfoBox"],
        )
    )

    story.append(Spacer(1, 25))

    story.append(
        Paragraph(
            """
            <b>Confidentiality Notice</b><br/><br/>

            This report contains the results of an automated API security
            assessment performed using the BOLAHawk platform. It is intended
            solely for authorized personnel responsible for the security of
            the assessed application. Distribution or disclosure to
            unauthorized individuals is not recommended.
            """,
            styles["Body"],
        )
    )

    story.append(PageBreak())

    # ==========================================================
    # EXECUTIVE SUMMARY
    # ==========================================================

    story.append(
        Paragraph(
            "Executive Summary",
            styles["SectionHeading"]
        )
    )

    for item in _executive_summary(context, styles):
        story.append(item)

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
    risk_text = Paragraph(

    f"""
    <b>Risk Assessment</b><br/><br/>

    The assessment identified
    <b>{context['summary']['total_findings']} confirmed vulnerabilities</b>
    affecting the target API.

    The highest observed CVSS Base Score is
    <b>{context['summary']['highest_score']:.1f}</b>,
    resulting in an overall risk classification of
    <b>{_overall_risk(context['summary']['highest_score'])}</b>.

    Critical vulnerabilities should be remediated immediately
    before deployment. High severity issues should be prioritized
    during the next development cycle, while Medium severity issues
    should be addressed as part of regular hardening activities.

    """,

    styles["InfoBox"]

)

    story.append(risk_text)
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

    # ==========================================================
    # METHODOLOGY
    # ==========================================================

    story.append(
        Paragraph(
            "Assessment Methodology",
            styles["SectionHeading"]
        )
    )

    story.append(
        Paragraph(
            """
            The security assessment was performed using the
            <b>BOLAHawk Automated API Security Scanner</b>.
            The scanner combines active security testing,
            authentication analysis, authorization validation,
            response inspection and CVSS v3.1 based risk scoring.

            <br/><br/>

            The assessment methodology follows industry best
            practices derived from the
            <b>OWASP API Security Top 10 (2023)</b>.

            """,
            styles["Body"]
        )
    )

    story.append(Spacer(1,15))

    # ==========================================================
    # SCOPE
    # ==========================================================

    story.append(
        Paragraph(
            "Assessment Scope",
            styles["SectionHeading"]
        )
    )

    scope = Table([

    ["Assessment Type","Automated API Security Assessment"],

    ["Target","REST API"],

    ["Authentication","JWT Authentication"],

    ["Risk Model","CVSS v3.1"],

    ["Framework","OWASP API Security Top 10"],

    ["Scanner","BOLAHawk"],

    ])

    scope.setStyle(TableStyle([

    ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#EFF6FF")),

    ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#CBD5E1")),

    ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),

    ("BOTTOMPADDING",(0,0),(-1,-1),8),

    ("TOPPADDING",(0,0),(-1,-1),8),

    ]))

    story.append(scope)

    story.append(Spacer(1,18))

    # ==========================================================
    # TESTS PERFORMED
    # ==========================================================

    story.append(
        Paragraph(
            "Security Tests Performed",
            styles["SectionHeading"]
        )
    )

    story.append(
        Paragraph(
            """
            • Broken Object Level Authorization (BOLA)<br/>

            • Broken Function Level Authorization (BFLA)<br/>

            • Mass Assignment Detection<br/>

            • JWT Security Analysis<br/>

            • Authentication Validation<br/>

            • Authorization Verification<br/>

            • Rate Limiting Detection<br/>

            • Response Analysis<br/>

            • CVSS Risk Scoring<br/>

            • Automated Evidence Collection
            """,
            styles["Body"]
        )
    )

    story.append(Spacer(1,18))

    # ==========================================================
    # REMEDIATION ROADMAP
    # ==========================================================

    story.append(
        Paragraph(
            "Recommended Remediation Roadmap",
            styles["SectionHeading"]
        )
    )

    roadmap = Table([

    ["Priority","Action"],

    ["Immediate","Remediate all Critical vulnerabilities."],

    ["High","Fix High severity issues before production."],

    ["Medium","Address Medium findings during hardening."],

    ["Validation","Run BOLAHawk again after remediation."],

    ])

    roadmap.setStyle(TableStyle([

    ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#2563EB")),

    ("TEXTCOLOR",(0,0),(-1,0),colors.white),

    ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#CBD5E1")),

    ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),

    ("BOTTOMPADDING",(0,0),(-1,-1),8),

    ("TOPPADDING",(0,0),(-1,-1),8),

    ]))

    story.append(roadmap)

    story.append(Spacer(1,18))

    # ==========================================================
    # EXECUTIVE CONCLUSION
    # ==========================================================

    story.append(
        Paragraph(
            "Executive Conclusion",
            styles["SectionHeading"]
        )
    )

    story.append(
        Paragraph(

            f"""
            The assessment identified
            <b>{context['summary']['total_findings']} confirmed
            security findings</b>, with an overall
            risk rating of
            <b>{_overall_risk(context['summary']['highest_score'])}</b>.

            <br/><br/>

            Critical vulnerabilities should be
            remediated immediately before deployment.

            Following remediation,
            the application should undergo another
            automated assessment to verify that
            corrective actions have successfully
            eliminated the identified vulnerabilities.

            """,

            styles["Body"]

        )
    )

    story.append(Spacer(1,18))

    # ==========================================================
    # DISCLAIMER
    # ==========================================================

    story.append(
        Paragraph(
            "Disclaimer",
            styles["SectionHeading"]
        )
    )

    story.append(
        Paragraph(
            f"""
            Report generated automatically by
            <b>BOLAHawk</b>.

            <br/><br/>

            Scan ID:
            {context["scan_id"]}

            <br/><br/>

            Generated:
            {context["generated_at"]}

            <br/><br/>

            This report is intended solely for
            educational, research and authorized
            security assessment purposes.

            Results should be manually verified
            before making security decisions.
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