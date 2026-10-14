from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def security_report(summary: dict) -> bytes:
    buf=BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4)
    styles=getSampleStyleSheet()
    story=[Paragraph("CYBERSHIELD SECURITY ASSESSMENT", styles["Title"]), Spacer(1,12)]
    for title,value in summary.items():
        story += [Paragraph(str(title), styles["Heading2"]), Paragraph(str(value), styles["BodyText"]), Spacer(1,8)]
    story += [Paragraph("Safety note: This report is an educational assessment and is not a security certification.", styles["BodyText"])]
    doc.build(story)
    return buf.getvalue()
