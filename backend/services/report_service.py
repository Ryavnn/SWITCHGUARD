import os
import csv
import json
from datetime import datetime
from sqlalchemy.orm import Session
from database import models
from pydantic import BaseModel

# Reportlab imports
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch

# ── Path configuration ────────────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

def ensure_user_dir(user_id: str):
    """Ensure the reports/user_id directory exists completely to prevent path traversal issues."""
    safe_user_id = str(user_id).replace("..", "").replace("/", "") # Sanitize
    path = os.path.join(REPORTS_DIR, safe_user_id)
    os.makedirs(path, exist_ok=True)
    return path


def fetch_report_data(job_id: str, db: Session):
    """Fetch scan, assets, and vulnerabilities aggregated for the report."""
    job = db.query(models.ScanJob).filter_by(job_id=job_id).first()
    if not job:
        raise ValueError(f"ScanJob {job_id} not found.")

    assets = db.query(models.Asset).filter_by(job_id=job_id).all()
    vulns = db.query(models.VulnerabilityInstance).filter_by(job_id=job_id).all()

    # Calculate metrics
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulns:
        if v.severity in sev_counts:
            sev_counts[v.severity] += 1
        else:
            sev_counts["Info"] += 1

    total_assets = len(assets)
    total_vulns = len(vulns)
    critical_high = sev_counts["Critical"] + sev_counts["High"]
    
    # Simple risk score algorithm identical to dashboard logic
    risk_score = 0
    if total_assets > 0:
        risk_score = min(100, int((critical_high * 10 + total_vulns * 2) / total_assets))

    return {
        "job": job,
        "assets": assets,
        "vulns": vulns,
        "metrics": {
            "total_assets": total_assets,
            "total_vulns": total_vulns,
            "severity_summary": sev_counts,
            "risk_score": risk_score
        }
    }


def generate_csv_report(job: models.ScanJob, vulns: list, user_dir: str):
    file_path = os.path.join(user_dir, f"{job.job_id}.csv")
    
    headers = [
        "Vulnerability Name",
        "Severity",
        "CVSS Score",
        "Risk Score",
        "Asset URL/IP",
        "Recommendation",
        "Date Discovered"
    ]
    
    with open(file_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for v in vulns:
            writer.writerow([
                v.title,
                v.severity,
                "N/A",  # CVSS placeholder if not present
                v.risk_score,
                v.url or "N/A",
                v.solution or "N/A",
                job.created_at.strftime("%Y-%m-%d %H:%M:%S")
            ])
            
    return file_path


def generate_pdf_report(job: models.ScanJob, data: dict, user_dir: str):
    file_path = os.path.join(user_dir, f"{job.job_id}.pdf")
    doc = SimpleDocTemplate(
        file_path, 
        pagesize=letter,
        rightMargin=inch, leftMargin=inch,
        topMargin=inch, bottomMargin=inch
    )
    
    Story = []
    styles = getSampleStyleSheet()
    
    # Brand Palettes
    BRAND_NAVY = colors.HexColor("#0f1f3d")
    BRAND_BLUE = colors.HexColor("#1e6fff")
    BRAND_WHITE = colors.HexColor("#ffffff")
    
    # Custom Styles
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=BRAND_NAVY,
        spaceAfter=30
    )
    
    h2_style = ParagraphStyle(
        'Header2',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=BRAND_BLUE,
        spaceAfter=12,
        spaceBefore=20
    )

    # 1. Cover Page
    Story.append(Paragraph("SwitchGuard Security Platform", title_style))
    Story.append(Paragraph("Executive Vulnerability Report", ParagraphStyle('SubTitle', fontSize=18, textColor=colors.gray, spaceAfter=40)))
    
    Story.append(Paragraph(f"<b>Scan ID:</b> {job.job_id}", styles["Normal"]))
    Story.append(Paragraph(f"<b>Target:</b> {job.target}", styles["Normal"]))
    Story.append(Paragraph(f"<b>Scan Type:</b> {job.scan_type.upper()}", styles["Normal"]))
    Story.append(Paragraph(f"<b>Generated At:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
    Story.append(Spacer(1, 40))

    # 2. Executive Summary
    metrics = data["metrics"]
    Story.append(Paragraph("Executive Summary", h2_style))
    Story.append(Paragraph(
        f"This report outlines the security posture of the target <b>{job.target}</b>. "
        f"A total of <b>{metrics['total_assets']}</b> assets were evaluated, revealing <b>{metrics['total_vulns']}</b> security findings.",
        styles["Normal"]
    ))
    Story.append(Spacer(1, 10))
    Story.append(Paragraph(f"<b>Overall Risk Score: {metrics['risk_score']}/100</b>", styles["Normal"]))
    Story.append(Spacer(1, 20))
    
    # 3. Severity Distribution
    Story.append(Paragraph("Severity Distribution", h2_style))
    sev = metrics["severity_summary"]
    dist_data = [
        ["Severity", "Count"],
        ["Critical", str(sev.get('Critical', 0))],
        ["High", str(sev.get('High', 0))],
        ["Medium", str(sev.get('Medium', 0))],
        ["Low", str(sev.get('Low', 0))],
        ["Info", str(sev.get('Info', 0))]
    ]
    t = Table(dist_data, colWidths=[2.5*inch, 2.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), BRAND_NAVY),
        ('TEXTCOLOR', (0,0), (-1,0), BRAND_WHITE),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f0f4ff")),
        ('GRID', (0,0), (-1,-1), 1, colors.white)
    ]))
    Story.append(t)
    
    Story.append(PageBreak())
    
    # 4. Detailed Findings
    Story.append(Paragraph("Detailed Findings", h2_style))
    
    if len(data["vulns"]) == 0:
        Story.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))
    else:
        vuln_data = [["Severity", "Finding", "Asset"]]
        for v in data["vulns"]:
            # Truncate strings to prevent PDF table explosion
            title = v.title[:60] + "..." if len(v.title) > 60 else v.title
            asset = v.url[:40] + "..." if v.url and len(v.url) > 40 else (v.url or "N/A")
            vuln_data.append([v.severity, title, asset])
            
        vt = Table(vuln_data, colWidths=[1*inch, 3.5*inch, 2*inch])
        vt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BRAND_NAVY),
            ('TEXTCOLOR', (0,0), (-1,0), BRAND_WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('INNERGRID', (0,0), (-1,-1), 0.25, colors.lightgrey),
            ('BOX', (0,0), (-1,-1), 0.25, colors.lightgrey),
        ]))
        Story.append(vt)
        
    # Build PDF
    doc.build(Story)
    return file_path


def auto_generate_reports(job_id: str, user_id: str, db: Session):
    """
    Orchestrates the creation of CSV and PDF reports for a newly completed scan.
    Must be called at the end of the scan background tasks.
    """
    data = fetch_report_data(job_id, db)
    job = data["job"]
    vulns = data["vulns"]
    metrics = data["metrics"]
    
    user_dir = ensure_user_dir(user_id)
    
    csv_path = generate_csv_report(job, vulns, user_dir)
    pdf_path = generate_pdf_report(job, data, user_dir)
    
    # Save the physical paths inside the DB Report models
    sev_json = json.dumps(metrics["severity_summary"])
    
    report_csv = models.Report(
        user_id=user_id,
        scan_id=job.job_id,
        file_type="csv",
        file_path=csv_path,
        severity_summary=sev_json,
        risk_score=metrics["risk_score"]
    )
    
    report_pdf = models.Report(
        user_id=user_id,
        scan_id=job.job_id,
        file_type="pdf",
        file_path=pdf_path,
        severity_summary=sev_json,
        risk_score=metrics["risk_score"]
    )
    
    db.add(report_csv)
    db.add(report_pdf)
    db.commit()
    
    return True
