import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import json
from typing import Dict, List, Any

class ReportGenerator:
    def __init__(self):
        self.report_path = os.getenv('REPORT_PATH', 'reports/')
        os.makedirs(self.report_path, exist_ok=True)
    
    def generate_report(self, analysis: Dict, filename: str) -> str:
        """Generate a PDF report for a security analysis"""
        
        # Create filename for report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"security_report_{timestamp}.pdf"
        report_full_path = os.path.join(self.report_path, report_filename)
        
        # Create PDF document
        doc = SimpleDocTemplate(report_full_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            alignment=TA_CENTER,
            spaceAfter=30
        )
        story.append(Paragraph("Sentinel AI Security Report", title_style))
        story.append(Spacer(1, 12))
        
        # Check for error
        if 'error' in analysis:
            story.append(Paragraph(f"Error: {analysis['error']}", styles['Normal']))
            doc.build(story)
            return report_full_path
        
        # Metadata
        meta_style = ParagraphStyle(
            'MetaStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.grey
        )
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
        story.append(Paragraph(f"Filename: {filename}", meta_style))
        story.append(Paragraph(f"File Hash: {analysis.get('file_hash', 'N/A')}", meta_style))
        story.append(Spacer(1, 20))
        
        # Risk Summary
        story.append(Paragraph("Risk Summary", styles['Heading2']))
        risk_data = [
            ['Metric', 'Value'],
            ['Risk Score', f"{analysis.get('risk_score', 0)}%"],
            ['Threat Level', analysis.get('threat_level', 'Unknown')],
            ['Status', analysis.get('status', 'Unknown')],
            ['Malware Family', analysis.get('malware_family', 'Unknown')]
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 3*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 20))
        
        # Detection Statistics
        story.append(Paragraph("Detection Statistics", styles['Heading2']))
        stats = analysis.get('statistics', {})
        stats_data = [
            ['Category', 'Count'],
            ['Malicious', stats.get('malicious', 0)],
            ['Suspicious', stats.get('suspicious', 0)],
            ['Undetected', stats.get('undetected', 0)],
            ['Harmless', stats.get('harmless', 0)]
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Security Recommendations", styles['Heading2']))
        recommendations = analysis.get('recommendations', ['No specific recommendations available'])
        for i, rec in enumerate(recommendations, 1):
            rec_style = ParagraphStyle(
                f'Rec{i}',
                parent=styles['Normal'],
                leftIndent=20,
                bulletText='•'
            )
            story.append(Paragraph(rec, rec_style))
            story.append(Spacer(1, 6))
        
        # Detection Details (if any)
        detections = analysis.get('detections', {})
        if detections and len(detections) > 0:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Detection Results", styles['Heading2']))
            
            detection_data = [['Engine', 'Detection', 'Category']]
            for engine, result in list(detections.items())[:20]:  # Limit to 20 for space
                detection_data.append([
                    engine,
                    result.get('result', 'N/A'),
                    result.get('category', 'N/A')
                ])
            
            detection_table = Table(detection_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch])
            detection_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            story.append(detection_table)
        
        # File Information
        file_info = analysis.get('file_info', {})
        if file_info:
            story.append(PageBreak())
            story.append(Paragraph("File Information", styles['Heading2']))
            info_data = [
                ['Property', 'Value'],
                ['File Size', f"{file_info.get('size', 0):,} bytes"],
                ['File Type', file_info.get('type', 'Unknown')],
                ['Magic', file_info.get('magic', 'Unknown')],
                ['Tags', ', '.join(file_info.get('tags', [])) if file_info.get('tags') else 'None']
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 3*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(info_table)
        
        # Footer
        story.append(Spacer(1, 40))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        story.append(Paragraph("This report was generated automatically by Sentinel AI Security Platform", footer_style))
        story.append(Paragraph("© 2024 Sentinel AI - All Rights Reserved", footer_style))
        
        # Build PDF
        doc.build(story)
        return report_full_path