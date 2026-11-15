"""Offline diagram checks: python -m tests.test_architecture from AWS directory."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def main():
    root = Path(__file__).resolve().parents[2]
    ns = {"svg": "http://www.w3.org/2000/svg"}
    for source in sorted(root.glob("architecture*.drawio")):
        drawing = ET.parse(source).getroot()
        svg = ET.parse(source.with_suffix(".svg")).getroot()
        cells = {c.get("id"): c for c in drawing.iter("mxCell")}
        ids = [c.get("id") for c in svg.iter() if c.get("id")]
        assert len(ids) == len(set(ids)), source
        for cell in cells.values():
            for attr in ("parent", "source", "target"):
                assert cell.get(attr) is None or cell.get(attr) in cells, (source, cell.get("id"), attr)
        assert "runtime-controls" not in cells, source
        assert svg.find("svg:g[@id='runtime-controls']", ns) is None, source
        assert "Runtime controls and cross-batch context" not in source.read_text(), source
        model = next(drawing.iter("mxGraphModel"))
        assert model.get("pageHeight") == svg.get("height"), source
        for stale in ("LAZY CACHE", "per-analysis cache", "First call computes", "Shared per-analysis cache"):
            assert stale not in source.read_text() and stale not in source.with_suffix(".svg").read_text(), source
        for match in re.findall(r"url\(#([^)]*)\)", source.with_suffix(".svg").read_text()):
            assert match in ids, (source, match)
        if "alternative-2" in source.stem or "alternative-3" in source.stem:
            prefix = "detail-b-" if "alternative-2" in source.stem else "detail-c-"
            edge = cells[prefix + "comparison-call"]
            assert edge.get("source") == prefix + "runtime"
            assert edge.get("target") == prefix + "comparison"
            assert prefix + "comparison-call-evidence" not in cells
    print("PASS: architecture source/SVG pairs, references, no explanatory panels, compute-once flows")


if __name__ == "__main__":
    main()