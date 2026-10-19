"""Build introductory sharing materials from reviewed, structured content.

Run from this repository root: python3 build_updated_collateral.py
Uses native PowerPoint bullet paragraphs and preserves prior copies in archive.
"""
from pathlib import Path
from html import escape
import shutil

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.oxml.xmlchemy import OxmlElement
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_AUTO_SIZE
from PIL import ImageFont
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT = Path(__file__).resolve().parent
NAVY, ORANGE, INK, MUTED, PANEL = '0A2540', 'F38020', '334155', '64748B', 'F3F6FA'
FONT = 'DejaVu Sans'
FONT_FILE = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
BOLD_FILE = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
DATE = '19 October 2026'
# Each slide has two clear bullet groups; these are editable PowerPoint text boxes.
SLIDES = [
('VulnSuite', 'VULNERABILITY ASSESSMENT + SERVER PROTECTION',
 ('Assessment and detection', ['Code, dependencies and infrastructure assessment', 'Linux and Windows security telemetry', 'Malware signals and cross-host correlation']),
 ('Security operations', ['Verified identity, roles and a shared SOC view', 'Incident ownership and central agent enrollment', 'Reviewed quarantine, isolation and cloud-WAF response']),
 'Introducing VulnSuite | Vulnerability assessment, server monitoring and approved security response.'),
('What the suite addresses', 'SECURITY OUTCOMES',
 ('Reduce exposure', ['Find vulnerable software and unsafe configurations', 'Assess exposed services, APIs and TLS settings', 'Prioritise findings using severity and asset context']),
 ('Investigate and respond', ['Connect host alerts with vulnerability findings', 'Assign incidents, review evidence and track action', 'Approve bounded containment and inspect receipts']),
 'Selected detection signals support investigation; coverage is not equivalent to a complete EDR platform.'),
('Platform coverage', 'ASSESSMENT + OPERATIONS',
 ('Assessment modules', ['SCA, secrets and static code analysis', 'Network, cloud, containers and asset discovery', 'IaC, Kubernetes and external attack surface', 'API testing and software supply-chain checks']),
 ('Protection and operations', ['Linux audit and Windows event adapters', 'Access, process, malware and integrity signals', 'SOC console, investigations and agent lifecycle', 'Signed notifications and approved response plans']),
 'Assessment and protection services retain separate persistence and deployment boundaries.'),
('Software and supply-chain risk', 'APPLICATION SECURITY',
 ('Code and dependencies', ['Trivy, pip-audit and OSV-Scanner collectors', 'Semgrep and Bandit static analysis', 'Gitleaks and TruffleHog secret detection']),
 ('Build and artifact evidence', ['Syft software bill of materials', 'Cosign signature and attestation checks', 'VEX statements captured in finding evidence', 'Risk scoring and remediation lifecycle tracking']),
 'Coverage depends on configured targets, installed tools and available advisory data.'),
('Infrastructure and API assessment', 'EXPOSURE MANAGEMENT',
 ('Infrastructure', ['Nmap service discovery and testssl.sh TLS checks', 'Prowler cloud configuration collectors', 'Checkov / Trivy IaC and Kubernetes posture checks']),
 ('Applications and APIs', ['Nuclei and OWASP ZAP assessment collectors', 'Target allowlists and active-scan configuration gates', 'External discovery with Subfinder and httpx']),
 'Assessment scans complement host monitoring and inline WAF enforcement.'),
('Verified identity and access', 'SSO TOKEN VERIFICATION + RBAC',
 ('Authentication and roles', ['Verify token signature, issuer, audience and expiry', 'Require signed tenant and explicit role claims', 'Separate viewer, auditor, analyst and admin rights', 'Sign-in and MFA follow identity-provider policy']),
 ('Tenant and approval boundaries', ['Bind assessment transactions to signed tenant ID', 'Enforce PostgreSQL row-level security policies', 'Bind protection access to one organisation', 'Require a different admin to approve playbooks']),
 'JWT verification and RLS controls are implemented; live IdP integration and database-role enforcement need staging.'),
('Unified operations console', 'ALERTS + FINDINGS + AGENTS',
 ('Shared investigation view', ['View intrusion alerts and vulnerability findings', 'Inspect agent health, sensor status and version drift', 'Create and assign incidents from selected alerts', 'Review response plans before approval']),
 ('Operational safeguards', ['Apply the same API role checks to console actions', 'Keep access tokens in browser-tab memory', 'Report unavailable upstream sources explicitly', 'Retrieve findings through a fixed HTTPS connector']),
 'The console shows bounded recent lists; it is not an exhaustive cross-platform evidence search.'),
('Windows and Linux monitoring', 'WINDOWS EVENTS + LINUX AUDIT',
 ('Windows monitoring', ['Security log authentication and network logons', 'RDP and SMB evidence where source events support it', 'Sysmon process-creation records', 'Selected fields without raw command-line capture']),
 ('Linux monitoring', ['Event-driven audit execution records', 'Linux /proc process polling', 'SSH access, API denials and file-integrity signals', 'Sensor health and missing-telemetry indicators']),
 'Windows and Linux support monitoring and approved containment. Native enforcement and recovery require staging validation.'),
('Process and malware detection', 'SELECTED HOST SIGNALS',
 ('Suspicious activity', ['Recognised web-server parent spawning a shell', 'Execution from writable temporary locations', 'Deleted executable signals on Linux', 'Event records for short-lived processes']),
 ('Malware evidence', ['Known-bad SHA256 matches on selected targets', 'Optional Linux selected-file ClamAV scans', 'Path, signature and hash retained for review', 'Unavailable scanners surface degraded coverage']),
 'Coverage excludes complete memory scanning and full-disk protection. File quarantine does not terminate a running process.'),
('Lateral-movement signals', 'CROSS-HOST CORRELATION',
 ('Correlated patterns', ['Password spraying across multiple hosts', 'Same-user successful-login fan-out', 'Suspected pivots from already flagged hosts', 'Remote-access evidence from supported event sources']),
 ('Investigation context', ['Administrator-defined host-to-IP ownership', 'Time-bounded correlation with retained evidence', 'Retry, out-of-order and restart handling', 'Expiring exceptions for reviewed false positives']),
 'NAT, shared accounts and legitimate automation need review; protocol labels require supporting source evidence.'),
('WAF integration', 'MODSECURITY + CLOUDFLARE',
 ('On-premises or proxy WAF', ['Nginx / ModSecurity and OWASP CRS templates', 'Sanitised serial-JSON rule-match collection', 'DetectionOnly starting configuration', 'No request-body or credential export']),
 ('Cloudflare response connector', ['Use a configured zone and custom-ruleset scope', 'Apply an approved source-IP block', 'Embed fixed expiry in the provider rule', 'Retry cleanup without extending the deadline']),
 'Rule ordering, provider permissions, propagation and real traffic enforcement remain staging checks.'),
('Reviewed local containment', 'APPROVAL + BOUNDED ENFORCEMENT',
 ('Quarantine and restoration', ['Use approved malware path and SHA256 evidence', 'Linux: private same-filesystem quarantine vault', 'Windows: file-handle checks and protected ACLs', 'Restore without overwriting existing files']),
 ('Isolation and release', ['Require separate approval and local policy', 'Linux: kernel-expiring nftables isolation', 'Windows: firewall rules with local recovery tasks', 'Keep configured management exceptions']),
 'Containment is disabled by default. Windows expiry uses local recovery tasks; Linux uses kernel timeouts.'),
('How the components fit', 'PLATFORM ARCHITECTURE',
 ('Assessment service', ['Scanner collectors and orchestration workers', 'Canonical findings and deterministic risk scoring', 'Verified API access and PostgreSQL tenant policies', 'Read-only findings feed into the operations console']),
 ('Protection service', ['Authenticated Linux and Windows agents', 'One organisation per SQLite operational store', 'Detection, incidents, policies and response history', 'Independent delivery and cloud-response worker']),
 'SQLite protection persistence is not a horizontally scalable or highly available PostgreSQL backend.'),
('Central agent lifecycle', 'ENROLLMENT + POLICY + HEALTH',
 ('Credential management', ['Issue expiring, one-time enrollment credentials', 'Store hashes of enrolled host credentials', 'Rotate keys and revoke agent access centrally', 'Cancel unexecuted responses after revocation']),
 ('Inventory and policy', ['Track platform, agent version and queue health', 'Record administrator policy-version history', 'Flag drift from the desired software version', 'Keep privileged response enablement local to hosts']),
 'Agent software installation and upgrades use an administrator-controlled rollout.'),
('Incident and notification workflows', 'OWNERSHIP + EVIDENCE + DELIVERY',
 ('Investigation workflow', ['Link alerts to owned incident cases', 'Track status, notes and evidence timelines', 'Protect concurrent edits with case versions', 'Review alerts and add scoped, expiring exceptions']),
 ('SIEM and ticketing bridges', ['Send signed JSON to fixed HTTPS endpoints', 'Persist delivery state, leases and retry attempts', 'Attach stable keys for receiver deduplication', 'Audit outcomes without storing upstream secrets']),
 'Webhooks support organisation-operated adapters; native Jira, ServiceNow or Splunk connectors are not implied.'),
('Reliable delivery and retention', 'RECOVERY + MAINTENANCE',
 ('Telemetry continuity', ['Keep events until exact acknowledgement', 'Replay retained events after service outages', 'Pause collection visibly when the queue is full', 'Archive older events without fresh containment']),
 ('Evidence maintenance', ['Create consistent SQLite backups and verify restore', 'Preview retention cleanup before applying it', 'Preserve incident and response-linked evidence', 'Create offline-agent and stale-sensor alerts']),
 'Schedule maintenance explicitly and measure capacity, recovery objectives and backup security in the target environment.'),
('Validation evidence', 'AUTOMATED CHECKS + NATIVE FILE CHECKS',
 ('348 automated tests passed', ['Access, roles and tenant boundaries', 'Detection, enrollment and incident workflows', 'Delivery, retention and outage recovery', 'Response workflows with mocked enforcement']),
 ('7 native Windows file checks passed', ['Disposable file-operation contract fixtures', 'Pinned-handle relative rename behavior', 'File-sharing and junction-race checks', 'Full ACL and firewall workflows require staging']),
 'Automated tests and narrow native file checks do not establish live containment efficacy or production readiness.'),
('Required staging validation', 'DEPLOYMENT GATES',
 ('Identity and host environment', ['IdP issuance, token lifetime and revocation behavior', 'PostgreSQL RLS with the deployed runtime role', 'Windows Security/Sysmon and Linux audit collection', 'Linux ClamAV installation, signatures and results']),
 ('Enforcement and workload', ['Cloudflare permissions, expiry and rule ordering', 'ModSecurity / CRS tuning and real intervention', 'Linux/Windows isolation, expiry and rollback', 'False positives, overhead, backlog and recovery']),
 'Validate native Windows ACLs, firewall enforcement, scheduled-task expiry and reboot recovery before enabling containment.'),
('Evaluating fit for your organisation', 'DEPLOYMENT PLANNING',
 ('Scope and ownership', ['Select applications, APIs and server assets', 'Identify incident owners and response approvers', 'Define management-access exceptions', 'Agree retention and recovery requirements']),
 ('Acceptance criteria', ['Measure detection coverage and false positives', 'Verify roles and separate-actor approval', 'Exercise containment, expiry and restoration', 'Measure host overhead and service recovery']),
 'Production deployment requires environment-specific validation and an approved operating procedure.'),
]

# Two- to three-line feature explanations accompany the structured bullet groups.
DESCRIPTIONS = [
 'VulnSuite helps security teams understand where systems are exposed, investigate suspicious server activity and coordinate approved responses. It connects assessment findings with operational evidence while keeping responsibility, review and deployment requirements visible.',
 'Security teams need a clear path from identifying exposure to deciding what action is justified. VulnSuite supports that process by linking findings, suspicious activity and investigation records, helping analysts prioritise work and document their decisions.',
 'Different assets expose different kinds of risk, from vulnerable libraries to unsafe infrastructure settings and suspicious host activity. VulnSuite brings assessment and monitoring into a common operational context, with coverage determined by configured tools and telemetry sources.',
 'Applications inherit risk from their own code, third-party dependencies and build artifacts. These checks help teams understand what software contains, identify known weaknesses and retain supporting evidence so remediation and software release decisions can be reviewed.',
 'Exposed services, weak configurations and application interfaces can create paths into an organisation. Assessment collectors help identify these conditions across selected targets, giving teams evidence to prioritise fixes and confirm which systems need closer investigation.',
 'Security operations involve sensitive evidence and actions that can interrupt services. Verified identity and explicit permissions establish who may view information or approve changes, while tenant boundaries limit assessment access to the organisation identified by trusted tokens.',
 'An analyst investigating an alert needs to understand the affected host, its known weaknesses and any response already underway. The console brings that context together, helping teams coordinate investigation while making unavailable information visible.',
 'Server monitoring depends on collecting useful activity from the operating system and making gaps visible. Windows event sources and Linux audit records provide investigation evidence, while sensor health indicators help teams distinguish quiet systems from missing telemetry.',
 'Selected process patterns and reviewed malware indicators provide clues that warrant investigation. A known-bad hash match supplies specific file evidence; analysts can review its context before approving action, while missing scanners or telemetry remain visible as coverage limitations.',
 'Activity that appears ordinary on one server can become suspicious when repeated across several hosts. Correlating authentication events helps analysts recognise possible account misuse or movement between systems, while retaining context needed to assess legitimate administrative activity.',
 'Web application firewalls provide an enforcement point for traffic reaching protected applications. Connecting their signals with investigations helps teams understand attempted abuse and review scoped blocking decisions, with tuning and deployment checks needed to avoid disrupting legitimate requests.',
 'Containment can interrupt business services, so response decisions need clear evidence and accountability. VulnSuite places supported file quarantine and host isolation behind separate approval and local policy checks, with recorded outcomes and reviewed recovery paths.',
 'The assessment service evaluates exposure; the protection service handles telemetry, investigations and response. Their separate responsibilities help teams plan access, storage, maintenance and integration around the requirements of each service.',
 'Host monitoring depends on knowing which agents are enrolled, authorised and reporting correctly. Central lifecycle controls help maintain that inventory, replace credentials, withdraw access and identify policy or version differences that require administrator attention.',
 'Investigations often involve several people and external operational systems. Incident records preserve ownership and decisions, while signed notifications carry relevant information to organisation-operated integrations, helping teams coordinate work and recover delivery after temporary service failures.',
 'Network interruptions and growing evidence volumes can affect security operations. Persistent queues and acknowledgement checks support recovery after outages, while backup and retention controls help teams manage stored evidence according to investigation needs and operational requirements.',
 'The validation results demonstrate exercised code paths and selected native file behaviours. They provide evidence for technical review, while full containment effectiveness, host compatibility and operational performance require testing in the intended environment.',
 'Deployment conditions determine whether security controls work as intended. Staging should verify identity, telemetry, permissions, enforcement and recovery together, including how containment behaves during service interruptions and host restarts.',
 'A suitable deployment starts with clear asset scope, accountable owners and measurable acceptance criteria. These decisions help teams assess coverage, operational impact, recovery expectations and the conditions under which approved response should be enabled.',
]

SUBJECT = 'Introducing VulnSuite — vulnerability assessment and server protection'
SECTIONS = [
('Vulnerability assessment', [
 'Application and software risk: static code analysis, dependency checks, secret detection, software bills of materials and supply-chain evidence.',
 'Infrastructure and API assessment: network services, TLS, cloud configurations, containers, infrastructure as code, Kubernetes and exposed applications/APIs.',
 'Prioritisation: severity and asset context, consolidated findings and remediation tracking; coverage depends on configured targets and installed assessment tools.'
]),
('Server monitoring and approved protection', [
 'Windows and Linux monitoring: Windows Security/Sysmon and Linux audit adapters, with SSH/API abuse, file-integrity and selected process signals.',
 'Malware and lateral-movement signals: known-bad SHA256 matches, optional Linux selected-file ClamAV scanning and cross-host login/pivot correlation.',
 'Windows and Linux containment: approved file quarantine/restoration and temporary host isolation/release, subject to separate-actor approval and local host policy. Containment is disabled by default.',
 'WAF integration: ModSecurity/OWASP CRS templates and sanitised telemetry, plus approved source-IP blocks through a configured Cloudflare connector.'
]),
('Security operations and access controls', [
 'SOC console: intrusion alerts, vulnerability findings, agent health and response review in a shared investigation view.',
 'Identity and accountability: verified signed tokens, role permissions, tenant controls, incident ownership, evidence timelines and audited response receipts.',
 'Agent management: one-time enrollment, credential rotation/revocation, policy history and version tracking; software rollout is administrator controlled.'
]),
('Reliability and integrations', [
 'Telemetry continuity: persistent queues, exact acknowledgements, visible queue limits and replay after outages; historical evidence cannot initiate fresh containment.',
 'Evidence maintenance: consistent SQLite backup, restoration verification, previewable retention cleanup and preservation of incident/response-linked evidence.',
 'SIEM and ticketing bridges: signed HTTPS JSON webhooks with durable retries and delivery IDs for organisation-operated receiving adapters.'
]),
('Validation and deployment requirements', [
 'Evidence: 348 automated tests passed across security/protection and regression suites, plus seven narrowly scoped native Windows file-operation checks. Mocked response tests do not establish live enforcement.',
 'Staging: validate identity-provider integration, deployed PostgreSQL tenant policies, telemetry, ClamAV signatures, WAF enforcement and native Windows/Linux containment and recovery.',
 'Windows containment uses protected file ACLs and local firewall recovery tasks; Linux isolation uses kernel nftables timeouts. Validate Windows task expiry, management access and reboot recovery before enabling response.',
 'Operating scope: selected monitoring and response with one organisation per SQLite protection store. Full EDR, memory protection, high availability and production capacity are outside the validated scope; quarantine does not terminate an already-running process.'
]),
('Briefing materials', [
 'VulnSuite_Executive_Deck_FINAL.pptx — introductory executive presentation with structured capability and deployment bullets.',
 'VulnSuite_Executive_Deck_Review.pdf — companion review copy of the presentation content.',
 'Technical guides: vulnsuite/protection/OPERATIONS.md and deploy/protection/OPERATIONS.md in the project repository.'
])]

LINKEDIN = '''Introducing VulnSuite: vulnerability assessment, server monitoring and approved security response in one suite.

For teams protecting applications, APIs and internal infrastructure, the aim is straightforward: bring security findings and host activity into a shared view, with clear ownership and review before containment.

VulnSuite brings together:

• Vulnerability assessment: identify vulnerabilities and configuration issues across applications, APIs, cloud resources, containers and code.
• Windows and Linux monitoring: collect configured telemetry for process activity, known-bad file hashes and selected lateral-movement patterns.
• WAF integration: connect web attack signals with investigations and support approved blocks through configured integrations.
• Approved containment: use role permissions, separate-actor approval and local host policy for supported file quarantine, host isolation and recovery workflows.
• SOC operations: manage enrolled hosts, incidents, assignments, response approvals and audit history through a central console.

Verification includes 348 automated tests and seven narrowly scoped native Windows file-operation checks. Deployment requires environment-specific staging, including validation of telemetry coverage, permissions, containment and recovery.

The focus is practical: help analysts understand what happened, identify affected systems and take accountable action.

I’d welcome feedback from security teams evaluating vulnerability management and internal server protection workflows.

#CyberSecurity #VulnerabilityManagement #ServerSecurity #SecurityOperations #VulnSuite
'''


def color(value): return RGBColor.from_string(value)

def box(slide, x, y, w, h, fill):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shape.fill.solid(); shape.fill.fore_color.rgb = color(fill)
    shape.line.fill.background()
    return shape


def text(slide, value, x, y, w, h, size=18, fill=INK, bold=False):
    shape = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = shape.text_frame; tf.clear(); tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]; p.text = value
    p.font.name = FONT; p.font.size = Pt(size); p.font.bold = bold; p.font.color.rgb = color(fill)
    p.space_after = Pt(0)
    return shape


def wrapped(value, size, width):
    font = ImageFont.truetype(FONT_FILE, int(size * 4))
    words = value.split(); lines=[]; line=''
    for word in words:
        candidate=(line+' '+word).strip()
        if line and font.getlength(candidate)/4 > width*72:
            lines.append(line); line=word
        else: line=candidate
    if line: lines.append(line)
    return lines


def bullets(slide, items, x, y, w, h):
    shape = text(slide, '', x, y, w, h)
    tf=shape.text_frame
    for i,item in enumerate(items):
        p=tf.paragraphs[0] if i==0 else tf.add_paragraph()
        p.text=item; p.level=0
        p.font.name=FONT; p.font.size=Pt(17); p.font.color.rgb=color(INK)
        p.line_spacing=Pt(22); p.space_after=Pt(8)
        props=p._p.get_or_add_pPr(); props.set('marL',str(int(Inches(.20)))); props.set('indent',str(-int(Inches(.18))))
        bullet=OxmlElement('a:buChar'); bullet.set('char','•')
        props.insert_element_before(bullet,'a:tabLst','a:defRPr','a:extLst')
    needed=sum(len(wrapped(item,17,w-.23))*22+8 for item in items)-8
    if needed > h*72: raise ValueError(f'Bullet overflow: {needed}pt > {h*72}pt')


def generate():
    assert len(DESCRIPTIONS) == len(SLIDES), 'Each slide needs a feature explanation'
    archive=ROOT/'collateral/archive'; archive.mkdir(parents=True, exist_ok=True)
    for name in ['VulnSuite_Executive_Deck_FINAL.pptx','VulnSuite_Executive_Deck.pptx','VulnSuite_Executive_Deck_Review.pdf','VulnSuite_Intro_Email.txt','VulnSuite_Intro_Email.html','VulnSuite_LinkedIn_Post.txt']:
        backup=archive/(Path(name).stem+'_before_first_introduction'+Path(name).suffix)
        if (ROOT/name).exists() and not backup.exists(): shutil.copy2(ROOT/name,backup)
    prs=Presentation(); prs.slide_width=Inches(13.333); prs.slide_height=Inches(7.5)
    prs.core_properties.title='Introducing VulnSuite — vulnerability assessment and server protection'
    prs.core_properties.subject='Platform capabilities, security controls and deployment requirements'
    prs.core_properties.author='VulnSuite'
    pdfmetrics.registerFont(TTFont('VS',FONT_FILE)); pdfmetrics.registerFont(TTFont('VS-Bold',BOLD_FILE))
    pdf=canvas.Canvas(str(ROOT/'VulnSuite_Executive_Deck_Review.pdf'),pagesize=(13.333*72,7.5*72))
    pdf.setTitle('Introducing VulnSuite — vulnerability assessment and server protection')
    pdf.setAuthor('VulnSuite')
    def pdftext(value,x,y,size=18,bold=False,fill=INK,width=None,leading=None):
        pdf.setFillColor('#'+fill); pdf.setFont('VS-Bold' if bold else 'VS',size)
        lines=wrapped(value,size,width) if width else [value]
        for j,line in enumerate(lines): pdf.drawString(x*72,(7.5-y)*72-size-j*(leading or size+6),line)
    for n,(title,kicker,left,right,note) in enumerate(SLIDES,1):
        s=prs.slides.add_slide(prs.slide_layouts[6])
        box(s,0,0,13.333,.10,ORANGE)
        text(s,kicker,.55,.35,12,.3,11,ORANGE,True)
        text(s,title,.55,.87,12.2,.65,34,NAVY,True)
        description=DESCRIPTIONS[n-1]
        if len(wrapped(description,15.5,12.2)) > 3:
            raise ValueError(f'Slide {n} description exceeds three lines')
        explanation=text(s,description,.55,1.55,12.2,.84,15.5,INK)
        explanation.text_frame.paragraphs[0].line_spacing=Pt(20)
        pdf.setFillColor('#'+ORANGE);pdf.rect(0,7.4*72,13.333*72,.1*72,fill=1,stroke=0)
        pdftext(kicker,.55,.35,11,True,ORANGE);pdftext(title,.55,.87,34,True,NAVY)
        pdftext(description,.55,1.55,15.5,width=12.2,leading=20)
        for x,(heading,items) in zip([.55,6.87],[left,right]):
            box(s,x,2.55,5.91,4.0,PANEL)
            box(s,x,2.55,.05,4.0,ORANGE)
            text(s,heading,x+.27,2.78,5.36,.65,20,NAVY,True)
            bullets(s,items,x+.27,3.54,5.3,2.86)
            pdf.setFillColor('#'+PANEL);pdf.rect(x*72,(7.5-6.55)*72,5.91*72,4.0*72,fill=1,stroke=0)
            pdf.setFillColor('#'+ORANGE);pdf.rect(x*72,(7.5-6.55)*72,.05*72,4.0*72,fill=1,stroke=0)
            pdftext(heading,x+.27,2.78,20,True,NAVY,width=5.36)
            cursor=3.54
            for item in items:
                pdftext('•',x+.27,cursor,17,False,ORANGE)
                pdftext(item,x+.5,cursor,17,width=5.07,leading=22)
                cursor+=(len(wrapped(item,17,5.07))*22+8)/72
        text(s,note,.55,6.65,12.2,.42,11,MUTED)
        text(s,f'CONFIDENTIAL • INTERNAL REVIEW  |  {DATE}',.55,7.13,11,.2,9,MUTED)
        text(s,f'{n:02d} / {len(SLIDES):02d}',12.08,7.13,.75,.2,9,MUTED)
        pdftext(note,.55,6.65,11,fill=MUTED,width=12.2)
        pdftext(f'CONFIDENTIAL • INTERNAL REVIEW  |  {DATE}',.55,7.13,9,fill=MUTED)
        pdftext(f'{n:02d} / {len(SLIDES):02d}',12.08,7.13,9,fill=MUTED)
        s.notes_slide.notes_text_frame.text=description+'\nScope: '+note+'\nImplementation and limitations: vulnsuite/protection/OPERATIONS.md\nStaging and maintenance: deploy/protection/OPERATIONS.md\nAutomated validation does not establish live enforcement or full EDR coverage.'
        pdf.showPage()
    pdf.save()
    prs.save(ROOT/'VulnSuite_Executive_Deck_FINAL.pptx')
    shutil.copy2(ROOT/'VulnSuite_Executive_Deck_FINAL.pptx',ROOT/'VulnSuite_Executive_Deck.pptx')
    intro='Introducing VulnSuite, a security suite that brings together vulnerability assessment, server monitoring and approved response. The attached briefing outlines its capabilities, operating controls and validation requirements for evaluating deployment in your organisation.'
    lines=['Subject: '+SUBJECT,'','Classification: CONFIDENTIAL — INTERNAL USE ONLY','','Dear [CISO Name],','',intro,'']
    for i,(heading,items) in enumerate(SECTIONS,1):
        lines += [f'{i}. {heading.upper()}']+['   • '+item for item in items]+['']
    lines += ['Regards,','[Your Name]','[Your Role]','[Phone] | [Email]','','CONFIDENTIAL — INTERNAL USE ONLY']
    (ROOT/'VulnSuite_Intro_Email.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    sections=''.join('<h2>'+str(i)+'. '+escape(h)+'</h2><ul>'+''.join('<li>'+escape(v)+'</li>' for v in items)+'</ul>' for i,(h,items) in enumerate(SECTIONS,1))
    page='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VulnSuite briefing</title><style>body{margin:0;background:#f3f6fa;color:#334155;font:16px/1.6 Arial,sans-serif}main{max-width:820px;margin:24px auto;background:white;padding:36px;border-top:6px solid #f38020}h1{color:#0a2540;font-size:26px;line-height:1.3}h2{color:#0a2540;font-size:19px;margin-top:28px}li{margin:9px 0}small{color:#64748b}ul{padding-left:25px}</style></head><body><main>'''
    page+='<small>CONFIDENTIAL — INTERNAL USE ONLY</small><h1>'+escape(SUBJECT)+'</h1><p>Dear [CISO Name],</p><p>'+escape(intro)+'</p>'+sections+'<p>Regards,<br>[Your Name]<br>[Your Role]<br>[Phone] | [Email]</p></main></body></html>'
    (ROOT/'VulnSuite_Intro_Email.html').write_text(page,encoding='utf-8')
    (ROOT/'VulnSuite_LinkedIn_Post.txt').write_text(LINKEDIN,encoding='utf-8')
    print(f'Generated {len(SLIDES)} slides, native bullet lists, TXT/HTML email, LinkedIn draft and companion review PDF.')

if __name__=='__main__': generate()
