from pathlib import Path
import re, sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT

src = Path(sys.argv[1])
out = Path(sys.argv[2])
text = src.read_text(encoding='utf-8-sig')
lines = text.splitlines()
doc = Document()
sec = doc.sections[0]
sec.top_margin = Inches(.68); sec.bottom_margin = Inches(.68)
sec.left_margin = Inches(.72); sec.right_margin = Inches(.72)

def set_font(style, name, size, color=None, bold=None):
    style.font.name = name
    style.font.size = Pt(size)
    if color: style.font.color.rgb = RGBColor(*color)
    if bold is not None: style.font.bold = bold
    style._element.rPr.rFonts.set(qn('w:ascii'), name)
    style._element.rPr.rFonts.set(qn('w:hAnsi'), name)
    style._element.rPr.rFonts.set(qn('w:eastAsia'), name)

set_font(doc.styles['Normal'], 'Aptos', 10.25, (40,48,58))
doc.styles['Normal'].paragraph_format.space_after = Pt(5)
doc.styles['Normal'].paragraph_format.line_spacing = 1.08
set_font(doc.styles['Title'], 'Aptos Display', 25, (22,48,78), True)
set_font(doc.styles['Heading 1'], 'Aptos Display', 17, (22,70,112), True)
set_font(doc.styles['Heading 2'], 'Aptos Display', 13, (31,92,138), True)
set_font(doc.styles['Heading 3'], 'Aptos', 11, (46,102,138), True)
for h in ['Heading 1','Heading 2','Heading 3']:
    doc.styles[h].paragraph_format.keep_with_next = True
    doc.styles[h].paragraph_format.space_before = Pt(12)
    doc.styles[h].paragraph_format.space_after = Pt(5)

# Cover-like opening: use the first heading as the document title.
first = next((i for i,x in enumerate(lines) if x.startswith('# ')), None)
if first is not None:
    p = doc.add_paragraph(style='Title')
    p.add_run(lines[first][2:].strip())
    p.paragraph_format.space_after = Pt(8)
    lines[first] = ''
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.LEFT
    r = sub.add_run('Информационная безопасность • практическое руководство для соревнований')
    r.bold = True; r.font.color.rgb = RGBColor(75,91,108); r.font.size = Pt(11)
    sub.paragraph_format.space_after = Pt(15)

inline_re = re.compile(r'(`[^`]+`|\*\*.+?\*\*)')
def add_inline(p, s):
    pos=0
    for m in inline_re.finditer(s):
        if m.start()>pos: p.add_run(s[pos:m.start()])
        token=m.group(0)
        if token.startswith('`'):
            r=p.add_run(token[1:-1]); r.font.name='Consolas'; r.font.size=Pt(9)
            r._element.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'Consolas')
            r.font.color.rgb=RGBColor(120,55,35)
        else:
            r=p.add_run(token[2:-2]); r.bold=True
        pos=m.end()
    if pos<len(s): p.add_run(s[pos:])

def shade(cell, fill):
    tcPr=cell._tc.get_or_add_tcPr(); shd=OxmlElement('w:shd'); shd.set(qn('w:fill'),fill); tcPr.append(shd)

i=0; in_code=False; code_lang=''; code_lines=[]
while i<len(lines):
    line=lines[i]
    if line.startswith('```'):
        if not in_code:
            in_code=True; code_lang=line[3:].strip(); code_lines=[]
        else:
            for cl in code_lines or ['']:
                p=doc.add_paragraph()
                p.paragraph_format.left_indent=Inches(.12); p.paragraph_format.right_indent=Inches(.08)
                p.paragraph_format.space_after=Pt(0); p.paragraph_format.space_before=Pt(0)
                p.paragraph_format.keep_together=True
                pPr=p._p.get_or_add_pPr(); shd=OxmlElement('w:shd'); shd.set(qn('w:fill'),'F1F4F7'); pPr.append(shd)
                r=p.add_run(cl if cl else ' '); r.font.name='Consolas'; r.font.size=Pt(8.2); r.font.color.rgb=RGBColor(37,55,73)
                r._element.get_or_add_rPr().rFonts.set(qn('w:eastAsia'),'Consolas')
            in_code=False; code_lang=''; code_lines=[]
        i+=1; continue
    if in_code:
        code_lines.append(line); i+=1; continue
    if not line.strip() or line.strip()=='---': i+=1; continue
    if line.startswith('|'):
        table_lines=[]
        while i<len(lines) and lines[i].startswith('|'):
            table_lines.append(lines[i]); i+=1
        rows=[]
        for tl in table_lines:
            cells=[c.strip() for c in tl.strip().strip('|').split('|')]
            if cells and all(re.fullmatch(r':?-{3,}:?',c or '') for c in cells): continue
            rows.append(cells)
        if rows:
            cols=max(len(r) for r in rows)
            table=doc.add_table(rows=0, cols=cols)
            table.style='Table Grid'; table.alignment=WD_TABLE_ALIGNMENT.CENTER; table.autofit=True
            for ri,row in enumerate(rows):
                cells=table.add_row().cells
                trPr=table.rows[-1]._tr.get_or_add_trPr()
                trPr.append(OxmlElement('w:cantSplit'))
                for ci in range(cols):
                    cell=cells[ci]; cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
                    cell.text=''
                    p=cell.paragraphs[0]; p.paragraph_format.space_after=Pt(1); p.paragraph_format.line_spacing=1.0
                    add_inline(p, row[ci] if ci<len(row) else '')
                    for run in p.runs: run.font.size=Pt(7.7)
                    if ri==0:
                        shade(cell,'DCE8F2')
                        for run in p.runs: run.bold=True; run.font.color.rgb=RGBColor(24,57,86)
            doc.add_paragraph().paragraph_format.space_after=Pt(1)
        continue
    if line.startswith('# '):
        p=doc.add_paragraph(style='Heading 1'); add_inline(p,line[2:].strip()); i+=1; continue
    if line.startswith('## '):
        p=doc.add_paragraph(style='Heading 2'); add_inline(p,line[3:].strip()); i+=1; continue
    if line.startswith('### '):
        p=doc.add_paragraph(style='Heading 3'); add_inline(p,line[4:].strip()); i+=1; continue
    if re.match(r'^\s*[-*]\s+',line):
        p=doc.add_paragraph(style='List Bullet'); add_inline(p,re.sub(r'^\s*[-*]\s+','',line)); i+=1; continue
    if re.match(r'^\s*\d+\.\s+',line):
        # Keep the number from Markdown as literal text. Word's automatic
        # List Number style continues numbering across separate sections.
        m=re.match(r'^\s*(\d+)\.\s+(.*)$',line)
        p=doc.add_paragraph()
        p.paragraph_format.left_indent=Inches(.18)
        p.paragraph_format.first_line_indent=Inches(-.18)
        p.add_run(m.group(1)+'.  ')
        add_inline(p,m.group(2)); i+=1; continue
    p=doc.add_paragraph(); add_inline(p,line.strip()); i+=1

# Document metadata.
doc.core_properties.title='Руководство по модулям и инструментам'
doc.core_properties.subject='Информационная безопасность 2026: команды, форензика, инциденты и SIEM'
doc.core_properties.author=''
out.parent.mkdir(parents=True, exist_ok=True)
doc.save(out)
print(out)
