"""
Professional PDF Remediation & Technical Report Generator
Generates clean, developer-ready, executive and technical penetration testing reports
using ReportLab with two-pass NumberedCanvas for dynamic 'Page X of Y' pagination,
CVSS v3.1 severity scores, risk distribution breakdown, and defensive code remediation snippets.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Preformatted
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render exact 'Page X of Y' footers
    and professional header bars without clipping or layout shifts.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "GuardScan | Automated Security Audit & Remediation Report")
            self.drawRightString(612 - 54, 750, datetime.now().strftime("%Y-%m-%d"))
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 612 - 54, 744)

        # Running Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawString(54, 36, "CONFIDENTIAL - Authorized Penetration Testing Document")
        self.drawRightString(612 - 54, 36, page_str)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 48, 612 - 54, 48)

        self.restoreState()


class PDFReportGenerator:
    """Generates executive and technical PDF reports for scan findings"""

    COLOR_CRITICAL = colors.HexColor("#dc2626")  # Red
    COLOR_HIGH = colors.HexColor("#ea580c")      # Orange
    COLOR_MEDIUM = colors.HexColor("#d97706")    # Amber
    COLOR_LOW = colors.HexColor("#2563eb")       # Blue
    COLOR_INFO = colors.HexColor("#64748b")      # Slate
    COLOR_PRIMARY = colors.HexColor("#0f172a")   # Dark Navy
    COLOR_ACCENT = colors.HexColor("#0284c7")    # Cyan/Blue

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_styles(self):
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            'CoverTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=26,
            leading=32,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=8
        ))

        styles.add(ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=13,
            leading=18,
            textColor=colors.HexColor("#475569"),
            spaceAfter=20
        ))

        styles.add(ParagraphStyle(
            'SectionHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=self.COLOR_PRIMARY,
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        ))

        styles.add(ParagraphStyle(
            'SubsectionHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=self.COLOR_ACCENT,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True
        ))

        styles.add(ParagraphStyle(
            'BodyRegular',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#1e293b")
        ))

        styles.add(ParagraphStyle(
            'CodeText',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a")
        ))

        styles.add(ParagraphStyle(
            'TableHead',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            leading=11,
            textColor=colors.white
        ))

        styles.add(ParagraphStyle(
            'TableBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#1e293b")
        ))

        styles.add(ParagraphStyle(
            'BadgeText',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            alignment=1,
            textColor=colors.white
        ))

        return styles

    def generate(self, scan_type: str, results: Dict[str, Any], filepath: Path) -> Path:
        """Generate a complete PDF remediation report"""
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = self._build_styles()
        story = []

        total_scanned = results.get('total_scanned', 0)
        total_found = results.get('total_found', 0)
        duration = results.get('duration', 0)
        raw_items = results.get('results', [])

        # Categorize findings by severity
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        info_count = 0
        vuln_findings = []

        for item in raw_items:
            is_vuln = item.get('vulnerable', False)
            sev = item.get('severity', 'Info').capitalize()
            if is_vuln:
                vuln_findings.append(item)
                if sev == 'Critical':
                    crit_count += 1
                elif sev == 'High':
                    high_count += 1
                elif sev == 'Medium':
                    med_count += 1
                elif sev == 'Low':
                    low_count += 1
                else:
                    med_count += 1
            else:
                info_count += 1

        # Calculate Overall Security Posture Score (0 - 100)
        score_penalty = (crit_count * 30) + (high_count * 15) + (med_count * 8) + (low_count * 3)
        security_score = max(0, 100 - score_penalty)
        grade = "A"
        grade_color = colors.HexColor("#16a34a")
        if security_score < 50:
            grade = "F"
            grade_color = self.COLOR_CRITICAL
        elif security_score < 70:
            grade = "D"
            grade_color = self.COLOR_HIGH
        elif security_score < 80:
            grade = "C"
            grade_color = self.COLOR_MEDIUM
        elif security_score < 90:
            grade = "B"
            grade_color = self.COLOR_LOW

        # ====================================================================
        # 1. COVER / EXECUTIVE SUMMARY HEADER
        # ====================================================================
        story.append(Spacer(1, 15))
        story.append(Paragraph("GUARDSCAN", ParagraphStyle(
            'Brand', fontName='Helvetica-Bold', fontSize=12, textColor=self.COLOR_ACCENT, spaceAfter=4
        )))
        story.append(Paragraph(f"Security Audit & Technical Remediation Report", styles['CoverTitle']))
        story.append(Paragraph(
            f"Automated Vulnerability Assessment for <b>{scan_type.upper()}</b> | Generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S UTC')}",
            styles['CoverSubtitle']
        ))
        story.append(Spacer(1, 10))

        # Executive Metrics Cards Table
        metric_data = [
            [
                Paragraph("<b>Overall Score</b>", styles['TableBody']),
                Paragraph("<b>Total Scanned</b>", styles['TableBody']),
                Paragraph("<b>Vulnerabilities</b>", styles['TableBody']),
                Paragraph("<b>Scan Duration</b>", styles['TableBody']),
            ],
            [
                Paragraph(f"<font size=16 color='{grade_color.hexval()}'><b>{security_score}/100 ({grade})</b></font>", styles['TableBody']),
                Paragraph(f"<font size=16><b>{total_scanned}</b></font>", styles['TableBody']),
                Paragraph(f"<font size=16 color='{self.COLOR_CRITICAL.hexval()}'><b>{total_found}</b></font>", styles['TableBody']),
                Paragraph(f"<font size=16><b>{duration}s</b></font>", styles['TableBody']),
            ]
        ]
        t_metrics = Table(metric_data, colWidths=[125, 125, 125, 129])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(t_metrics)
        story.append(Spacer(1, 15))

        # Risk Breakdown Table
        story.append(Paragraph("Risk Breakdown by Severity", styles['SectionHeader']))
        risk_data = [
            [
                Paragraph("<b>Severity Level</b>", styles['TableHead']),
                Paragraph("<b>CVSS v3.1 Range</b>", styles['TableHead']),
                Paragraph("<b>Findings Count</b>", styles['TableHead']),
                Paragraph("<b>Recommended SLA</b>", styles['TableHead']),
            ],
            [
                Paragraph("<font color='#dc2626'><b>CRITICAL</b></font>", styles['TableBody']),
                Paragraph("9.0 - 10.0", styles['TableBody']),
                Paragraph(f"<b>{crit_count}</b>", styles['TableBody']),
                Paragraph("Remediate within 24 hours", styles['TableBody']),
            ],
            [
                Paragraph("<font color='#ea580c'><b>HIGH</b></font>", styles['TableBody']),
                Paragraph("7.0 - 8.9", styles['TableBody']),
                Paragraph(f"<b>{high_count}</b>", styles['TableBody']),
                Paragraph("Remediate within 7 days", styles['TableBody']),
            ],
            [
                Paragraph("<font color='#d97706'><b>MEDIUM</b></font>", styles['TableBody']),
                Paragraph("4.0 - 6.9", styles['TableBody']),
                Paragraph(f"<b>{med_count}</b>", styles['TableBody']),
                Paragraph("Remediate within 30 days", styles['TableBody']),
            ],
            [
                Paragraph("<font color='#2563eb'><b>LOW</b></font>", styles['TableBody']),
                Paragraph("0.1 - 3.9", styles['TableBody']),
                Paragraph(f"<b>{low_count}</b>", styles['TableBody']),
                Paragraph("Remediate next release", styles['TableBody']),
            ],
        ]
        t_risk = Table(risk_data, colWidths=[110, 110, 110, 174])
        t_risk.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t_risk)
        story.append(Spacer(1, 20))

        # ====================================================================
        # 2. VULNERABILITY SUMMARY MATRIX
        # ====================================================================
        story.append(Paragraph("Vulnerability Summary Matrix", styles['SectionHeader']))

        if not vuln_findings:
            story.append(Paragraph(
                "<i>No vulnerabilities were detected during this scan session. All tested parameters satisfied baseline security checks.</i>",
                styles['BodyRegular']
            ))
            story.append(Spacer(1, 15))
        else:
            matrix_data = [
                [
                    Paragraph("<b>#</b>", styles['TableHead']),
                    Paragraph("<b>Vulnerability Title</b>", styles['TableHead']),
                    Paragraph("<b>Severity</b>", styles['TableHead']),
                    Paragraph("<b>CVSS</b>", styles['TableHead']),
                    Paragraph("<b>Target Endpoint</b>", styles['TableHead']),
                ]
            ]

            for idx, finding in enumerate(vuln_findings, 1):
                sev = finding.get('severity', 'High').upper()
                cvss = finding.get('cvss_score', 7.5)
                title = finding.get('title', 'Security Vulnerability')
                url = finding.get('url', '')
                if len(url) > 45:
                    url = url[:42] + '...'

                sev_color = self.COLOR_HIGH.hexval()
                if sev == 'CRITICAL':
                    sev_color = self.COLOR_CRITICAL.hexval()
                elif sev == 'MEDIUM':
                    sev_color = self.COLOR_MEDIUM.hexval()
                elif sev == 'LOW':
                    sev_color = self.COLOR_LOW.hexval()

                matrix_data.append([
                    Paragraph(f"{idx}", styles['TableBody']),
                    Paragraph(f"<b>{title}</b>", styles['TableBody']),
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", styles['TableBody']),
                    Paragraph(f"{cvss}", styles['TableBody']),
                    Paragraph(f"<font face='Courier' size=7>{url}</font>", styles['TableBody']),
                ])

            t_matrix = Table(matrix_data, colWidths=[24, 150, 65, 45, 220])
            t_matrix.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_matrix)

        story.append(PageBreak())

        # ====================================================================
        # 3. DETAILED TECHNICAL FINDINGS & REMEDIATION CODE
        # ====================================================================
        story.append(Paragraph("Detailed Technical Findings & Remediation Guidance", styles['SectionHeader']))
        story.append(Paragraph(
            "This section provides root-cause analysis, proof-of-concept vectors, and copy-pasteable defensive code snippets to assist engineering teams in remediation.",
            styles['BodyRegular']
        ))
        story.append(Spacer(1, 10))

        if not vuln_findings:
            story.append(Paragraph("<i>No actionable vulnerabilities require remediation.</i>", styles['BodyRegular']))
        else:
            for idx, finding in enumerate(vuln_findings, 1):
                sev = finding.get('severity', 'High').upper()
                title = finding.get('title', 'Vulnerability Finding')
                cvss = finding.get('cvss_score', 7.5)
                cwe = finding.get('cwe_id', 'CWE-200')
                owasp = finding.get('owasp_category', 'A01:2021-Broken Access Control')
                url = finding.get('url', '')
                payload = finding.get('payload', 'N/A')
                evidence = finding.get('evidence', '')
                remediation = finding.get('remediation', 'Implement proper authorization and sanitization controls.')
                code_snippet = finding.get('remediation_code', '')

                finding_elements = []

                # Finding Title Banner
                sev_color = self.COLOR_HIGH
                if sev == 'CRITICAL':
                    sev_color = self.COLOR_CRITICAL
                elif sev == 'MEDIUM':
                    sev_color = self.COLOR_MEDIUM
                elif sev == 'LOW':
                    sev_color = self.COLOR_LOW

                banner_data = [[
                    Paragraph(f"<b>FINDING #{idx}: {title}</b>", ParagraphStyle('BannerL', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white)),
                    Paragraph(f"<b>{sev} | CVSS {cvss}</b>", ParagraphStyle('BannerR', fontName='Helvetica-Bold', fontSize=10, alignment=2, textColor=colors.white))
                ]]
                t_banner = Table(banner_data, colWidths=[360, 144])
                t_banner.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ]))
                finding_elements.append(t_banner)

                # Metadata table
                meta_data = [
                    [Paragraph("<b>Target URL:</b>", styles['TableBody']), Paragraph(f"<font face='Courier' size=7.5>{url}</font>", styles['TableBody'])],
                    [Paragraph("<b>Classification:</b>", styles['TableBody']), Paragraph(f"{cwe} | {owasp}", styles['TableBody'])],
                    [Paragraph("<b>Test Vector:</b>", styles['TableBody']), Paragraph(f"<font face='Courier' size=7.5>{payload}</font>", styles['TableBody'])],
                ]
                t_meta = Table(meta_data, colWidths=[90, 414])
                t_meta.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))
                finding_elements.append(t_meta)
                finding_elements.append(Spacer(1, 6))

                # Technical Evidence
                if evidence:
                    finding_elements.append(Paragraph("<b>Observed Evidence:</b>", styles['SubsectionHeader']))
                    evidence_box = [
                        [Paragraph(f"<font face='Courier' size=7 color='#334155'>{evidence.replace(chr(10), '<br/>')}</font>", styles['TableBody'])]
                    ]
                    t_ev = Table(evidence_box, colWidths=[504])
                    t_ev.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ('TOPPADDING', (0, 0), (-1, -1), 5),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ]))
                    finding_elements.append(t_ev)
                    finding_elements.append(Spacer(1, 6))

                # Remediation Guidance
                finding_elements.append(Paragraph("<b>Remediation Guidance:</b>", styles['SubsectionHeader']))
                finding_elements.append(Paragraph(remediation, styles['BodyRegular']))
                finding_elements.append(Spacer(1, 6))

                # Remediation Code Snippet
                if code_snippet:
                    finding_elements.append(Paragraph("<b>Recommended Defensive Implementation:</b>", styles['SubsectionHeader']))
                    code_box = [[Preformatted(code_snippet, styles['CodeText'])]]
                    t_code = Table(code_box, colWidths=[504])
                    t_code.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#1e293b")),
                        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#0f172a")),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ]))
                    # Adjust text color for code inside dark container
                    styles['CodeText'].textColor = colors.HexColor("#38bdf8")
                    finding_elements.append(t_code)

                finding_elements.append(Spacer(1, 18))
                story.append(KeepTogether(finding_elements))

        # Build document with NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        return filepath
