from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable,
)

_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#c0392b"),
    "High": colors.HexColor("#d35400"),
    "Medium": colors.HexColor("#b7950b"),
    "Low": colors.HexColor("#2471a3"),
    "None": colors.HexColor("#616a76"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=20, leading=24, spaceAfter=6, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Meta", fontSize=9, textColor=colors.HexColor("#666666"), spaceAfter=16))
    styles.add(ParagraphStyle(name="FindingTitle", fontSize=12, leading=15, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="FindingMeta", fontSize=8, textColor=colors.HexColor("#666666"), spaceAfter=6))
    styles.add(ParagraphStyle(name="FieldLabel", fontSize=8, textColor=colors.HexColor("#666666"),
                               fontName="Helvetica-Bold", spaceBefore=6))
    styles.add(ParagraphStyle(name="FieldValue", fontSize=9.5, leading=13))
    styles.add(ParagraphStyle(name="EvidenceCode", fontSize=8.5, fontName="Courier", backColor=colors.HexColor("#f2f2f2")))
    return styles


def _summary_table(summary: dict, styles) -> Table:
    order = ["Critical", "High", "Medium", "Low"]
    header = ["Total"] + order + ["Highest CVSS"]
    row = [str(summary.get("total_findings", 0))]
    row += [str(summary.get("by_severity", {}).get(s, 0)) for s in order]
    row += [f"{summary.get('highest_score', 0.0):.1f}"]

    table = Table([header, row], colWidths=[0.85 * inch] * len(header))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1c1f26")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("TEXTCOLOR", (1, 1), (1, 1), _SEVERITY_COLORS["Critical"]),
        ("TEXTCOLOR", (2, 1), (2, 1), _SEVERITY_COLORS["High"]),
        ("TEXTCOLOR", (3, 1), (3, 1), _SEVERITY_COLORS["Medium"]),
        ("TEXTCOLOR", (4, 1), (4, 1), _SEVERITY_COLORS["Low"]),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
    ]))
    return table


def _finding_block(f: dict, styles) -> list:
    sev_color = _SEVERITY_COLORS.get(f["severity"], _SEVERITY_COLORS["None"])
    flow = []

    header_table = Table(
        [[Paragraph(f["title"], styles["FindingTitle"]),
          Paragraph(f'<font color="#{sev_color.hexval()[2:]}">{f["severity"]} · CVSS {f["cvss_score"]:.1f}</font>',
                     styles["FindingTitle"])]],
        colWidths=[4.6 * inch, 2.0 * inch],
    )
    header_table.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, 0), 2, sev_color),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("VALIGN", (0, 0), (-1, 0), "BOTTOM"),
    ]))
    flow.append(header_table)
    flow.append(Paragraph(
        f'{f["check_id"]} &middot; {f["method"]} {f["endpoint"]} &middot; context: {f["auth_context"]}',
        styles["FindingMeta"],
    ))
    flow.append(Paragraph("DESCRIPTION", styles["FieldLabel"]))
    flow.append(Paragraph(f["description"], styles["FieldValue"]))
    flow.append(Paragraph("EVIDENCE", styles["FieldLabel"]))
    flow.append(Paragraph(f["evidence"], styles["EvidenceCode"]))
    flow.append(Paragraph("REMEDIATION", styles["FieldLabel"]))
    flow.append(Paragraph(f["remediation"], styles["FieldValue"]))
    flow.append(Paragraph("CVSS VECTOR", styles["FieldLabel"]))
    flow.append(Paragraph(f["cvss_vector"], styles["EvidenceCode"]))
    flow.append(Spacer(1, 16))
    return flow


def build_pdf_report(context: dict, output_path: str) -> str:
    """context comes from reporting.data.build_report_context(). Writes the
    PDF to output_path and returns it."""
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )
    styles = _styles()
    story = []

    story.append(Paragraph("API Security Testing Platform", styles["ReportTitle"]))
    story.append(Paragraph("Findings Report", styles["Heading2"]))
    story.append(Paragraph(
        f'Scan ID: {context["scan_id"]} &middot; Status: {context["status"]} &middot; '
        f'Started: {context["started_at"]} &middot; Generated: {context["generated_at"]}',
        styles["Meta"],
    ))
    story.append(_summary_table(context["summary"], styles))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 16))

    if not context["findings"]:
        story.append(Paragraph("No findings recorded for this scan.", styles["FieldValue"]))
    else:
        for i, f in enumerate(context["findings"]):
            story.extend(_finding_block(f, styles))
            if i < len(context["findings"]) - 1 and i % 4 == 3:
                story.append(PageBreak())

    doc.build(story)
    return output_path
