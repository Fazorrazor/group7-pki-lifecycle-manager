"""
Unit tests verifying auto-escaping and XSS neutralization in the rendering layer.
Proves defense against Cross-Site Scripting (CWE-79).
"""

from pki_lifecycle.rendering.templates import SafeRenderer


def test_escape_script_tag():
    """Verifies that classic script tags are neutralized into harmless HTML entities."""
    malicious = "<script>alert('XSS')</script>"
    rendered = SafeRenderer.render_alert_banner(malicious)
    assert "<script>" not in rendered
    assert "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;" in rendered


def test_escape_img_onerror_in_endpoint():
    """Verifies that img tag with onerror handler is escaped in table row rendering."""
    payload = '<img src=x onerror=alert(1)>'
    endpoint = {
        "id": 1,
        "hostname": payload,
        "port": 443,
        "service_name": 'service" onfocus="alert(2)',
        "environment": "lab",
    }
    html_out = SafeRenderer.render_endpoint_row(endpoint)
    assert "<img" not in html_out
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_out
    assert '&quot; onfocus=&quot;' in html_out


def test_escape_certificate_card_xss():
    """Verifies that unescaped attributes in certificate cards cannot execute script."""
    cert = {
        "serial_number": "12345678",
        "common_name": "<svg onload=alert(document.cookie)>",
        "issuer": "Evil CA <iframe src='javascript:alert(1)'>",
        "sans": "a.lab,b.lab",
        "valid_to": "2026-12-31",
        "is_revoked": False,
    }
    card_html = SafeRenderer.render_certificate_card(cert)
    assert "<svg" not in card_html
    assert "<iframe" not in card_html
    assert "&lt;svg onload=alert(document.cookie)&gt;" in card_html
    assert "&lt;iframe src=&#x27;javascript:alert(1)&#x27;&gt;" in card_html
