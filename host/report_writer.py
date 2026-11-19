#!/usr/bin/env python3
"""Shared writer for the course report template.

The template is ONE 58-row x 3-column table, not a list of paragraphs, and most
labels are merged across all three columns. Two row shapes exist:

  * a row with 2 distinct cells (Date, File Size, File Hash ...) takes its value
    in the SECOND cell
  * a row with 1 distinct cell is a LABEL, and its content goes in the FOLLOWING
    row -- so a filler addresses row 14, never row 13

`cell_of` encodes that rule. Nothing here writes into a label row, which is why
a filled report must still have all 26 label rows byte-identical to the template.

Per-sample prose lives in the fill_report_<sample>.py scripts; this module only
knows how to put lines into cells without disturbing the template's styles.
"""
import copy
import os

import docx
import docx.text.paragraph as dp
from docx.shared import Pt


def template_path(root):
    """The course template, which is never modified -- only read."""
    return os.path.join(root, "References", "Malware_Analysis_Report_Template.docx")


def cell_of(table, ri):
    """The distinct value cell for a 2-column row, else the row's single cell.

    python-docx returns one entry per grid column, so a cell merged across three
    columns comes back three times. Compare the underlying <w:tc> elements rather
    than the objects, which are recreated per access.
    """
    row = table.rows[ri]
    seen = []
    for c in row.cells:
        if all(c._tc is not s._tc for s in seen):
            seen.append(c)
    return seen[-1] if len(seen) > 1 else seen[0]


def write_cell(cell, lines, mono=True):
    """Replace the cell's content with `lines`, one paragraph each."""
    # reuse the first paragraph so the template's own paragraph style survives
    first = cell.paragraphs[0]
    for r in list(first.runs):
        r._element.getparent().remove(r._element)
    tmpl = copy.deepcopy(first._p)
    for extra in cell.paragraphs[1:]:
        extra._p.getparent().remove(extra._p)

    def fill(par, text):
        run = par.add_run(text)
        run.font.name = "Consolas" if mono else "Calibri"
        run.font.size = Pt(8.5 if mono else 10)
        run.bold = False

    fill(first, lines[0])
    prev = first._p
    for line in lines[1:]:
        newp = copy.deepcopy(tmpl)
        prev.addnext(newp)
        prev = newp
        fill(dp.Paragraph(newp, first._parent), line)


def render(template, data, title, out_path):
    """Write `data` ({row index: [lines]}) into a copy of the template."""
    doc = docx.Document(template)
    t = doc.tables[0]
    for ri in sorted(data):
        write_cell(cell_of(t, ri), data[ri])
    doc.paragraphs[0].runs[0].text = title
    doc.save(out_path)
    print("wrote %s (%d bytes)" % (out_path, os.path.getsize(out_path)))
    print("filled %d rows" % len(data))
    return out_path


def render_freeform(doc_spec, title, out_path):
    """Write a free-form report (headings + body), not the 58-row template table.

    This is the structure used by the course's example student reports -- numbered
    sections rather than the template's table. `doc_spec` is a flat list of
    (kind, payload) pairs so the content reads in document order:

        ("h1",   "1. Basic Static Analysis")
        ("h2",   "1.1. File information")
        ("body", ["- File name: ...", "- File size: ..."])     monospace block
        ("text", ["Prose paragraph.", "Another one."])          proportional
        ("shot", "What to capture here")                        screenshot marker

    A "shot" entry becomes a visible placeholder paragraph: the analyst replaces it
    with the real screenshot. Leaving them in a draft is deliberate -- a silently
    missing screenshot is worse than a labelled gap.
    """
    d = docx.Document()
    d.add_heading(title, 0)
    for kind, payload in doc_spec:
        if kind == "h1":
            d.add_heading(payload, 1)
        elif kind == "h2":
            d.add_heading(payload, 2)
        elif kind == "h3":
            d.add_heading(payload, 3)
        elif kind in ("body", "text"):
            mono = kind == "body"
            for line in payload:
                p = d.add_paragraph()
                run = p.add_run(line)
                run.font.name = "Consolas" if mono else "Calibri"
                run.font.size = Pt(9 if mono else 11)
                p.paragraph_format.space_after = Pt(0 if mono else 6)
        elif kind == "shot":
            p = d.add_paragraph()
            run = p.add_run("[SCREENSHOT: %s]" % payload)
            run.font.name = "Calibri"
            run.font.size = Pt(10)
            run.bold = True
            run.italic = True
        else:
            raise ValueError("unknown doc_spec kind: %r" % kind)
    d.save(out_path)
    shots = sum(1 for k, _ in doc_spec if k == "shot")
    print("wrote %s (%d bytes)" % (out_path, os.path.getsize(out_path)))
    print("%d blocks, %d screenshot placeholders" % (len(doc_spec), shots))
    return out_path


def _wrap(text, width=78, indent=""):
    """Wrap prose to a fixed width. Monospace blocks are never wrapped."""
    out, line = [], indent
    for word in text.split():
        if line.strip() and len(line) + 1 + len(word) > width:
            out.append(line.rstrip())
            line = indent + word
        else:
            line = (line + " " + word) if line.strip() else indent + word
    if line.strip():
        out.append(line.rstrip())
    return out or [""]


def render_freeform_txt(doc_spec, title, out_path):
    """Plain-text twin of render_freeform, from the same doc_spec.

    Rendered from the spec rather than extracted back out of the .docx, so the two
    outputs cannot drift and the text keeps its intended line breaks: monospace
    blocks (addresses, hex, tables) stay exactly as written, prose is wrapped.
    """
    L = [title, "=" * len(title), ""]
    for kind, payload in doc_spec:
        if kind == "h1":
            L += ["", payload, "=" * len(payload), ""]
        elif kind == "h2":
            L += ["", payload, "-" * len(payload), ""]
        elif kind == "h3":
            L += ["", payload, ""]
        elif kind == "body":
            L += list(payload) + [""]
        elif kind == "text":
            for para in payload:
                L += _wrap(para) + [""]
        elif kind == "shot":
            L += ["[SCREENSHOT: %s]" % payload, ""]
        else:
            raise ValueError("unknown doc_spec kind: %r" % kind)
    txt = "\n".join(L).rstrip() + "\n"
    with open(out_path, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write(txt)
    print("wrote %s (%d bytes)" % (out_path, os.path.getsize(out_path)))
    return out_path


def render_table_txt(template, data, title, out_path):
    """Plain-text rendering of a filled 58-row template report.

    Walks the template's own rows so the section labels and their order come from
    the template rather than being retyped, and drops each DATA block under the
    label it belongs to. A row the filler left empty prints as an explicit
    '(not filled)' rather than vanishing.
    """
    doc = docx.Document(template)
    t = doc.tables[0]
    L = [title, "=" * len(title), ""]
    for ri, row in enumerate(t.rows):
        seen = []
        for c in row.cells:
            if all(c._tc is not s._tc for s in seen):
                seen.append(c)
        label = seen[0].text.strip()
        if len(seen) > 1:                      # label + value on the same row
            val = data.get(ri)
            if val is None:
                continue
            L.append("%-24s %s" % (label, val[0]))
            for extra in val[1:]:
                L.append(" " * 25 + extra)
            L.append("")
        else:                                  # a label row; content is the NEXT row
            if ri in data:                     # this row IS content for the label above
                for line in data[ri]:
                    L.append("    " + line)
                L.append("")
            elif label:
                if label.isupper():
                    L += ["", "=" * 78, label, "=" * 78, ""]
                else:
                    L += [label, "-" * min(len(label), 78)]
    txt = "\n".join(L).rstrip() + "\n"
    with open(out_path, "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write(txt)
    print("wrote %s (%d bytes)" % (out_path, os.path.getsize(out_path)))
    return out_path


def section_lines(pm):
    """The PE Section Hashes block, read from pe_meta.json rather than retyped."""
    lines = ["%-8s %10s  H=%-6s %-4s  md5 %s" %
             ("name", "raw size", "entr", "perm", "sha256")]
    for s in pm["sections"]:
        lines.append("%-8s %10d  H=%-6s %-4s  %s" %
                     (s["name"], s["rawsize"], s["entropy"], s["perm"], s["md5"]))
        lines.append("%-8s %10s  %s" % ("", "", s["sha256"]))
    return lines


def entropy_lines(pm, size_note):
    """The Entropy block. Measured over RAW FILE BYTES -- see pe_meta.py.

    Ghidra reports entropy over the loaded memory block, zero-padded out to the
    section's virtual size, which collapses the figure for a packed section that
    is mostly padding and makes a packed sample read as clean.
    """
    lines = ["Whole file: H = %s  (%s)" % (pm["file_entropy"], size_note), ""]
    for s in pm["sections"]:
        lines.append("  %-8s H = %-6s  raw %d bytes  %s"
                     % (s["name"], s["entropy"], s["rawsize"], s["perm"]))
    return lines
