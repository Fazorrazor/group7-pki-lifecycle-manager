import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('w:top', top), ('w:bottom', bottom), ('w:left', left), ('w:right', right)]:
        node = OxmlElement(m)
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def create_document():
    doc = docx.Document()

    # Page setup - 0.75 in margins for clean fit
    sections = doc.sections
    for s in sections:
        s.top_margin = Inches(0.75)
        s.bottom_margin = Inches(0.75)
        s.left_margin = Inches(0.75)
        s.right_margin = Inches(0.75)

    # Styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(10)
    normal_style.font.color.rgb = RGBColor(0x22, 0x22, 0x22)

    # Header / Title
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_after = Pt(2)
    p_title.paragraph_format.space_before = Pt(0)
    run_course = p_title.add_run("CSSS 441 Software Security I — Week 1 Practical Deliverable\n")
    run_course.font.size = Pt(10)
    run_course.font.bold = True
    run_course.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    run_title = p_title.add_run("Threat Model Summary: Private PKI & Certificate Lifecycle Manager")
    run_title.font.size = Pt(15)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(0x11, 0x11, 0x11)

    # Metadata table
    p_meta = doc.add_paragraph()
    p_meta.paragraph_format.space_after = Pt(8)
    p_meta.paragraph_format.space_before = Pt(2)
    r_meta = p_meta.add_run(
        "Group 7 | Lead: Arnold Niikoi Djanie (1692642491) | Members: Peter Myles Etroo (1703154270), "
        "Aaron Tettey-Fio (1704456123), Osei Elvis (1703105081), Daniel Odame Lartey (1692180365), "
        "Edinam Afi Ezuh (1700135424)\n"
        "Associated Model File: docs/threat-model/threat-model.json (OWASP Threat Dragon v2)"
    )
    r_meta.font.size = Pt(8.5)
    r_meta.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

    # Divider line
    p_div = doc.add_paragraph()
    p_div.paragraph_format.space_after = Pt(6)
    r_div = p_div.add_run("―" * 65)
    r_div.font.color.rgb = RGBColor(0xCC, 0xCC, 0xCC)

    # 1. System Overview & Boundaries
    h1 = doc.add_paragraph()
    h1.paragraph_format.space_before = Pt(4)
    h1.paragraph_format.space_after = Pt(2)
    r_h1 = h1.add_run("1. System Architecture & Trust Boundaries")
    r_h1.font.size = Pt(11.5)
    r_h1.font.bold = True

    p_desc = doc.add_paragraph()
    p_desc.paragraph_format.space_after = Pt(4)
    p_desc.paragraph_format.line_spacing = 1.15
    p_desc.add_run(
        "This project implements an automated, two-tier private Public Key Infrastructure (PKI) designed to manage "
        "the complete lifecycle of internal TLS certificates across lab services. It enforces a maximum 30-day "
        "certificate lifespan with zero-downtime ACME renewals, continuous compliance scanning, and real-time revocation checks. "
        "The system architecture is partitioned across four distinct trust boundaries:"
    )

    boundaries = [
        ("Air-Gapped Root CA Boundary: ", "Isolates the offline Root CA private key, used exclusively to sign the intermediate CA during documented key ceremonies."),
        ("Internal Management Zone: ", "Hosts the online intermediate CA (step-ca), the FastAPI inventory service, and the PostgreSQL metadata store."),
        ("Lab Services DMZ: ", "Hosts internal NGINX HTTPS endpoints that consume short-lived certificates issued via ACME."),
        ("External Internet Boundary: ", "Outbound connection to public Certificate Transparency logs (crt.sh) and alert notification channels.")
    ]
    for b_title, b_desc in boundaries:
        p_b = doc.add_paragraph(style='List Bullet')
        p_b.paragraph_format.space_after = Pt(1.5)
        p_b.paragraph_format.space_before = Pt(0)
        r_bt = p_b.add_run(b_title)
        r_bt.font.bold = True
        r_bt.font.size = Pt(9)
        r_bd = p_b.add_run(b_desc)
        r_bd.font.size = Pt(9)

    # 2. STRIDE Threats Catalog
    h2 = doc.add_paragraph()
    h2.paragraph_format.space_before = Pt(8)
    h2.paragraph_format.space_after = Pt(3)
    r_h2 = h2.add_run("2. STRIDE Threat Catalog & Risk Ratings")
    r_h2.font.size = Pt(11.5)
    r_h2.font.bold = True

    # Table of threats
    threats = [
        ("T1", "Intermediate CA Key Exfiltration", "Info Disclosure", "step-ca Server", "Low", "Critical", "High", "Compromise enables arbitrary valid certificate forgery."),
        ("T2", "ACME Domain Impersonation", "Spoofing", "ACME Endpoint", "Medium", "High", "High", "Unauthorized internal service requests certificates for foreign hosts."),
        ("T3", "SQL Injection via Endpoint Query", "Tampering", "FastAPI / DB", "Medium", "High", "High", "Malformed query parameters extract or modify certificate records."),
        ("T4", "Stored XSS via Certificate SANs", "Tampering", "Dashboard UI", "Medium", "High", "High", "Malicious CN or SAN scripts execute in administrator browser."),
        ("T5", "Stale OCSP Response Replay", "Tampering", "OCSP Responder", "Medium", "High", "High", "Replaying cached 'Good' tokens allows revoked certificates to pass."),
        ("T6", "OCSP Responder Denial of Service", "Denial of Service", "OCSP Responder", "High", "Medium", "High", "Outage triggers client soft-fail, bypassing revocation checks."),
        ("T7", "CA Path Length & Constraint Bypass", "Elevation of Priv.", "Leaf Certs", "Low", "Critical", "High", "Absence of pathlen:0 permits leaf certificates to sign sub-CAs."),
        ("T8", "Weak Cipher Suite Downgrade", "Info Disclosure", "NGINX Services", "Medium", "Medium", "Med", "Legacy CBC or TLS < 1.2 exposes communication to plaintext recovery."),
        ("T9", "Missing Intermediate Chain DoS", "Denial of Service", "TLS Handshake", "High", "Low", "Med", "Server serving only leaf cert causes strict clients to abort."),
        ("T10", "Direct Database Modification", "Repudiation", "PostgreSQL", "Low", "High", "Med", "Direct DB edits bypass application-level audit logging."),
        ("T11", "Inventory Scan Request Flooding", "Denial of Service", "Inventory API", "High", "Low", "Med", "Burst of on-demand scan triggers exhausts worker threads."),
        ("T12", "Rogue Certificate Issuance Evasion", "Spoofing", "External CT Log", "Medium", "High", "High", "Unauthorized public certificate issued without operator discovery.")
    ]

    table = doc.add_table(rows=1, cols=8)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    headers = ["#", "Threat Name", "STRIDE", "Target Element", "Likelihood", "Impact", "Risk", "Rationale"]
    col_widths = [Inches(0.35), Inches(1.5), Inches(0.95), Inches(0.95), Inches(0.65), Inches(0.65), Inches(0.55), Inches(1.65)]

    hdr_cells = table.rows[0].cells
    for i, title in enumerate(headers):
        hdr_cells[i].text = title
        hdr_cells[i].width = col_widths[i]
        set_cell_background(hdr_cells[i], "F0F0F0")
        set_cell_margins(hdr_cells[i], top=60, bottom=60, left=80, right=80)
        p = hdr_cells[i].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        for run in p.runs:
            run.font.bold = True
            run.font.size = Pt(8)

    for row_idx, data in enumerate(threats):
        row = table.add_row()
        cells = row.cells
        for col_idx, text in enumerate(data):
            cells[col_idx].text = text
            cells[col_idx].width = col_widths[col_idx]
            set_cell_margins(cells[col_idx], top=40, bottom=40, left=80, right=80)
            if row_idx % 2 == 1:
                set_cell_background(cells[col_idx], "FAFAFA")
            p = cells[col_idx].paragraphs[0]
            if col_idx in [0, 4, 5, 6]:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            else:
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            for run in p.runs:
                run.font.size = Pt(7.5)
                if col_idx == 6 and text == "High":
                    run.font.bold = True

    # 3. Top 5 Chosen Controls
    h3 = doc.add_paragraph()
    h3.paragraph_format.space_before = Pt(8)
    h3.paragraph_format.space_after = Pt(3)
    r_h3 = h3.add_run("3. Top 5 Threats & Chosen Security Controls")
    r_h3.font.size = Pt(11.5)
    r_h3.font.bold = True

    top_controls = [
        ("Intermediate Key Compromise & Constraint Bypass (T1, T7): ", "Offline Root CA powered down in storage; Intermediate CA signed with pathlen:0 and Name Constraints restricting issuance strictly to .internal.lab; private keys set to chmod 0400 under non-root ownership."),
        ("ACME Domain Impersonation (T2): ", "ACME provisioner validates HTTP-01/DNS-01 challenges restricted to internal network ranges, coupled with strict 30-day validity lifetimes to minimize window of vulnerability."),
        ("SQL Injection Vulnerabilities (T3): ", "Strict input validation using Pydantic schemas combined with 100% parameterized queries via SQLAlchemy/asyncpg, eliminating raw SQL string concatenation."),
        ("Stored XSS via Certificate Metadata (T4): ", "Context-aware HTML auto-escaping enabled on all dashboard templates and API responses, with strict Content-Security-Policy headers prohibiting inline script execution."),
        ("Revocation Bypass & Replay (T5, T6): ", "RFC 6960 OCSP nonces enforced to prevent replay attacks; short response caching (<= 1 hour); clients configured to hard-fail if revocation checks cannot be verified.")
    ]

    for c_title, c_desc in top_controls:
        p_c = doc.add_paragraph(style='List Bullet')
        p_c.paragraph_format.space_after = Pt(2)
        p_c.paragraph_format.space_before = Pt(0)
        p_c.paragraph_format.line_spacing = 1.15
        r_ct = p_c.add_run(c_title)
        r_ct.font.bold = True
        r_ct.font.size = Pt(8.5)
        r_cd = p_c.add_run(c_desc)
        r_cd.font.size = Pt(8.5)

    # 4. Boundary Verification Table
    h4 = doc.add_paragraph()
    h4.paragraph_format.space_before = Pt(8)
    h4.paragraph_format.space_after = Pt(3)
    r_h4 = h4.add_run("4. Boundary-Crossing Data Flows Verification (Pass Condition)")
    r_h4.font.size = Pt(11.5)
    r_h4.font.bold = True

    p_pass = doc.add_paragraph()
    p_pass.paragraph_format.space_after = Pt(3)
    r_pass = p_pass.add_run("Verification against rubric rule: 'Done when every data flow that crosses a boundary has at least one threat recorded against it.'")
    r_pass.font.italic = True
    r_pass.font.size = Pt(8.5)

    flow_table = doc.add_table(rows=1, cols=5)
    flow_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    flow_table.autofit = False

    f_headers = ["Data Flow Name", "Boundary Crossed", "STRIDE", "Recorded Threat", "Selected Control"]
    f_widths = [Inches(1.5), Inches(1.5), Inches(0.85), Inches(1.5), Inches(1.9)]

    f_hdr_cells = flow_table.rows[0].cells
    for i, title in enumerate(f_headers):
        f_hdr_cells[i].text = title
        f_hdr_cells[i].width = f_widths[i]
        set_cell_background(f_hdr_cells[i], "F0F0F0")
        set_cell_margins(f_hdr_cells[i], top=50, bottom=50, left=70, right=70)
        p = f_hdr_cells[i].paragraphs[0]
        for run in p.runs:
            run.font.bold = True
            run.font.size = Pt(8)

    flows_data = [
        ("Flow 1: Offline Signing", "Air-Gapped Root -> Management Zone", "Tampering", "Malicious USB Drop / CSR Tampering", "Dual-custody ceremony protocol, SHA-256 fingerprint verification."),
        ("Flow 2: ACME Issuance & Renew", "Lab Services DMZ -> Management Zone", "Spoofing", "ACME Challenge Hijacking / SAN Spoof", "Internal challenge IP binding and CA Name Constraints (.internal.lab)."),
        ("Flow 3: OCSP Revocation Check", "Lab Services DMZ -> Management Zone", "Tampering", "OCSP Replay / Response Dropping", "RFC 6960 nonces, short cache validity (<= 1h), and hard-fail client policy."),
        ("Flow 4: TLS Inventory Probing", "Management Zone -> Lab Services DMZ", "Info Disclosure", "TLS Probe Interception / Cert Forgery", "Root-anchored X.509 chain validation and mutual TLS authentication."),
        ("Flow 7: CT Log Query", "Management Zone -> External Internet", "Tampering", "CT Query Suppression / Log Poisoning", "TLS certificate pinning for crt.sh and multi-log correlation alerts.")
    ]

    for row_idx, f_data in enumerate(flows_data):
        row = flow_table.add_row()
        cells = row.cells
        for col_idx, text in enumerate(f_data):
            cells[col_idx].text = text
            cells[col_idx].width = f_widths[col_idx]
            set_cell_margins(cells[col_idx], top=35, bottom=35, left=70, right=70)
            if row_idx % 2 == 1:
                set_cell_background(cells[col_idx], "FAFAFA")
            p = cells[col_idx].paragraphs[0]
            if col_idx == 2:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for run in p.runs:
                run.font.size = Pt(7.5)

    doc.save("docs/threat-model/Threat_Model_Summary_Group7.docx")
    print("Successfully generated docs/threat-model/Threat_Model_Summary_Group7.docx")

if __name__ == "__main__":
    create_document()

