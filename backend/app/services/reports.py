from datetime import UTC, datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def security_report(summary: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="CyberShield Security Assessment")
    styles = getSampleStyleSheet()
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    story = [
        Paragraph("CYBERSHIELD SECURITY ASSESSMENT", styles["Title"]),
        Paragraph(f"Generated: {stamp}", styles["BodyText"]),
        Spacer(1, 12),
    ]
    for title, value in summary.items():
        story += [
            Paragraph(escape(str(title)), styles["Heading2"]),
            Paragraph(escape(str(value)), styles["BodyText"]),
            Spacer(1, 8),
        ]
    story += [
        Paragraph(
            "Safety note: This report is an educational assessment and is not a security certification.",
            styles["BodyText"],
        )
    ]
    doc.build(story)
    return buf.getvalue()
