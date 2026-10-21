#!/usr/bin/env python3
"""generate_pdf.py — Build bug_bounty_portfolio.pdf from findings.json"""
import json
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
)

with open("findings.json") as f:
    DATA = json.load(f)

PROJECTS = DATA["projects"]
OWNER = DATA.get("portfolio_owner", "Saad")
NOW = datetime.utcnow().strftime("%Y-%m-%d")
TOTAL = sum(p["finding_count"] for p in PROJECTS)

styles = getSampleStyleSheet()
title_style = ParagraphStyle("title", parent=styles["Title"],
                              fontSize=28, textColor=colors.HexColor("#cc0000"),
                              spaceAfter=30)
h1_style = ParagraphStyle("h1", parent=styles["Heading1"],
                           fontSize=20, textColor=colors.HexColor("#cc0000"),
                           spaceAfter=15)
h2_style = ParagraphStyle("h2", parent=styles["Heading2"],
                           fontSize=14, spaceAfter=10)
body_style = styles["BodyText"]

def build_pdf():
    doc = SimpleDocTemplate(
        "bug_bounty_portfolio.pdf", pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )
    story = []

    # COVER
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("BUG BOUNTY PORTFOLIO", title_style))
    story.append(Paragraph("Ethical Hacking & Offensive Security",
                            ParagraphStyle("sub", parent=body_style,
                                           fontSize=16, alignment=1)))
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(f"<b>{OWNER}</b>",
                            ParagraphStyle("n", parent=body_style,
                                           fontSize=20, alignment=1)))
    story.append(Paragraph(f"{len(PROJECTS)} Projects Completed",
                            ParagraphStyle("c", parent=body_style,
                                           fontSize=14, alignment=1)))
    story.append(Paragraph(f"{TOTAL} Confirmed Findings",
                            ParagraphStyle("c2", parent=body_style,
                                           fontSize=14, alignment=1)))
    story.append(PageBreak())

    # EXECUTIVE SUMMARY
    story.append(Paragraph("Executive Summary", h1_style))
    story.append(Paragraph(
        f"This portfolio documents {len(PROJECTS)} offensive security projects "
        f"covering the full attack lifecycle. A total of <b>{TOTAL} confirmed "
        f"findings</b> were validated across injection, server-side, "
        f"deserialization, and cloud misconfiguration categories. All testing "
        f"was performed on self-hosted labs and LocalStack.",
        body_style))
    story.append(Spacer(1, 0.2 * inch))

    # Severity table
    sev_count = {}
    for p in PROJECTS:
        sev_count[p["severity"]] = sev_count.get(p["severity"], 0) + p["finding_count"]
    story.append(Paragraph("Findings by Severity", h2_style))
    data = [["Severity", "Findings"]]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev_count.get(sev):
            data.append([sev, str(sev_count[sev])])
    t = Table(data, colWidths=[2 * inch, 2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cc0000")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(t)
    story.append(PageBreak())

    # METHODOLOGY
    story.append(Paragraph("Methodology", h1_style))
    phases = [
        ("Phase 1 - Reconnaissance", "Map the attack surface via subdomain enumeration, port scanning, technology fingerprinting."),
        ("Phase 2 - Vulnerability Discovery", "Identify injection, server-side, client-side, and cloud vulnerabilities."),
        ("Phase 3 - Exploitation", "Build minimal PoCs, demonstrate impact, document with screenshots, score CVSS."),
        ("Phase 4 - Reporting", "Executive summary, technical details, prioritized remediation."),
        ("Phase 5 - Verification", "Re-run exploits after patch, verify closure, test bypass variants."),
    ]
    for name, desc in phases:
        story.append(Paragraph(name, h2_style))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 0.1 * inch))
    story.append(PageBreak())

    # FINDINGS
    story.append(Paragraph("Findings", h1_style))
    story.append(Paragraph(
        f"Each of the {len(PROJECTS)} projects below includes vulnerability "
        f"class, severity, tool built, and remediation.", body_style))
    story.append(Spacer(1, 0.2 * inch))

    for p in PROJECTS:
        story.append(Paragraph(
            f"#{p['id']} - {p['name']}",
            ParagraphStyle("proj", parent=h2_style,
                           textColor=colors.HexColor("#cc0000"))))
        story.append(Paragraph(f"<b>Category:</b> {p['category']}", body_style))
        story.append(Paragraph(f"<b>Vuln Class:</b> {p['vuln_class']}", body_style))
        story.append(Paragraph(f"<b>Severity:</b> {p['severity']} (CVSS {p['cvss']})", body_style))
        story.append(Paragraph(f"<b>Tool:</b> {p.get('tool', '-')}", body_style))
        story.append(Paragraph(f"<b>Findings:</b> {p['finding_count']}", body_style))
        story.append(Paragraph(f"<b>Remediation:</b> {p['remediation']}", body_style))
        story.append(Spacer(1, 0.3 * inch))

    story.append(PageBreak())

    # CONCLUSION
    story.append(Paragraph("Conclusion", h1_style))
    story.append(Paragraph(
        f"This portfolio demonstrates hands-on proficiency in offensive "
        f"security across {len(PROJECTS)} projects and {TOTAL} confirmed "
        f"findings. All testing was performed on self-hosted vulnerable labs, "
        f"LocalStack, and intentionally vulnerable targets — no production "
        f"systems were harmed.", body_style))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Next Steps", h2_style))
    for step in [
        "Pursue OSWE (Offensive Security Web Expert) certification",
        "Pursue OSCP (Offensive Security Certified Professional) certification",
        "Engage with HackerOne, Bugcrowd, and Intigriti platforms",
        "Expand coverage to API security, mobile, and Active Directory",
    ]:
        story.append(Paragraph(f"* {step}", body_style))

    doc.build(story)
    print("[OK] bug_bounty_portfolio.pdf created")

if __name__ == "__main__":
    build_pdf()
