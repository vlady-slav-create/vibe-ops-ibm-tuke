"""Offline PPTX checks: python3 /workspaces/project/vibe-ops-ibm-tuke/tools/check_presentation.py."""
import ast
import posixpath
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


def main():
    path = Path(__file__).resolve().parents[1] / "Vibe-ops on AWS.pptx"
    ns = {"p": "http://schemas.openxmlformats.org/presentationml/2006/main",
          "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
          "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        for name in names:
            if name.endswith((".xml", ".rels")):
                root = ET.fromstring(archive.read(name))
                if name.endswith(".rels"):
                    base = posixpath.dirname(posixpath.dirname(name))
                    for rel in root:
                        if rel.get("TargetMode") != "External":
                            target = posixpath.normpath(posixpath.join(base, rel.get("Target"))).lstrip("/")
                            assert target in names, (name, target)
        presentation = ET.fromstring(archive.read("ppt/presentation.xml"))
        for name in names:
            if name.startswith("ppt/media/") and name.endswith(".svg"):
                ET.fromstring(archive.read(name))
        rels = {r.get("Id"): r.get("Target") for r in
                ET.fromstring(archive.read("ppt/_rels/presentation.xml.rels"))}
        slides = ["ppt/" + rels[s.get("{" + ns["r"] + "}id")]
                  for s in presentation.find("p:sldIdLst", ns)]
        assert slides == [f"ppt/slides/slide{i}.xml" for i in range(1, 35)]
        size = presentation.find("p:sldSz", ns)
        width, height = int(size.get("cx")), int(size.get("cy"))
        texts = []
        code_count = 0
        pictures = 0
        for name in slides[14:]:
            root = ET.fromstring(archive.read(name))
            texts.append(" ".join(t.text or "" for t in root.findall(".//a:t", ns)))
            ids = [e.get("id") for e in root.findall(".//p:cNvPr", ns)]
            assert len(ids) == len(set(ids)), name
            for pic in root.findall(".//p:pic", ns):
                pictures += 1
                xfrm = pic.find("p:spPr/a:xfrm", ns)
                off, ext = xfrm.find("a:off", ns), xfrm.find("a:ext", ns)
                x, y, w, h = (int(e.get(k)) for e, k in [(off, "x"), (off, "y"), (ext, "cx"), (ext, "cy")])
                # Existing slide 26 SVG extends 0.023 inches below the canvas.
                bottom_bleed = 21000 if name == "ppt/slides/slide26.xml" else 0
                assert 0 <= x <= x + w <= width and 0 <= y <= y + h <= height + bottom_bleed, name
                assert pic.find(".//a:blip/a:extLst/a:ext/{http://schemas.microsoft.com/office/drawing/2016/SVG/main}svgBlip", ns) is not None, name
            for shape in root.findall(".//p:sp", ns):
                xfrm = shape.find("p:spPr/a:xfrm", ns)
                off, ext = xfrm.find("a:off", ns), xfrm.find("a:ext", ns)
                x, y, w, h = (int(e.get(k)) for e, k in
                              [(off, "x"), (off, "y"), (ext, "cx"), (ext, "cy")])
                assert 0 <= x <= x + w <= width and 0 <= y <= y + h <= height, name
                props = shape.find("p:nvSpPr/p:cNvPr", ns)
                if props.get("name", "").startswith("Code "):
                    code = "\n".join("".join(p.itertext()) for p in shape.findall("p:txBody/a:p", ns))
                    ast.parse(code)
                    code_count += 1
        combined = " ".join(texts)
        for term in ("Kinesis", "Step Functions", "AgentCore", "Guardrails", "Security Hub",
                     "Strands", "single", "orchestrator", "graph", "as_tool", "GraphBuilder"):
            assert term in combined, term
        assert code_count == 4, code_count
        assert pictures == 4, pictures
        assert "What we learned" in texts[-2]
        assert "Quick quiz: what would you do?" in texts[-1]
        assert "1 B" in archive.read("ppt/notesSlides/notesSlide34.xml").decode()
    print("PASS: 34 slides; order, XML, relationships, bounds, SVG pictures, coverage, four Python examples, summary and quiz")


if __name__ == "__main__":
    main()