"""Place image-only slides before architectures; --check validates offline."""
import sys
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Inches

DECK = Path(__file__).resolve().parents[1] / 'Vibe-ops on AWS.pptx'
WORKSPACE = DECK.parent.parent
PREFIX = 'Architecture analogy'
SLIDES = [
    ('single', WORKSPACE / 'image copy.png'),
    ('orchestrator', DECK.parent / 'ec3950f3-d71d-4c94-abda-8cf2178234e5_text_hi.gif'),
    ('graph', WORKSPACE / 'image copy 2.png'),
]


def architecture(deck, number):
    return next(s for s in deck.slides if any(
        sh.has_text_frame and sh.text.startswith(f'Alternative {number}:') for sh in s.shapes))


GEOMETRY = [
    (476300, 471339, 11715700, 6407183),
    (631594, 633226, 11522697, 6208421),
    (1948602, 622169, 10064288, 6196240),
]


def check():
    from io import BytesIO
    with ZipFile(DECK) as archive:
        assert archive.testzip() is None
    deck = Presentation(DECK)
    slides = list(deck.slides)
    for number, (mode, path, *_rest) in enumerate(SLIDES, 1):
        slide = architecture(deck, number)
        assert not any(sh.name.startswith(PREFIX) for sh in slide.shapes)
        diagrams = [sh for sh in slide.shapes if sh.shape_type == 13]
        assert len(diagrams) == 1
        diagram = diagrams[0]
        assert (diagram.left, diagram.top, diagram.width, diagram.height) == GEOMETRY[number - 1]
        before = slides[slides.index(slide) - 1]
        assert before.name == f'{PREFIX} {mode}'
        assert len(before.shapes) == 1
        picture = before.shapes[0]
        assert picture.image.blob == path.read_bytes()
        with Image.open(BytesIO(picture.image.blob)) as image:
            assert abs(picture.width / picture.height - image.width / image.height) < .001
            if mode == 'orchestrator':
                assert image.n_frames == 45
        assert 0 <= picture.left < picture.left + picture.width <= deck.slide_width
        assert 0 <= picture.top < picture.top + picture.height <= deck.slide_height
    assert sum(s.name.startswith(PREFIX) for s in slides) == 3
    print(f'PASS: {len(slides)} slides; image-only slides precede architectures; '
          'original diagram geometry, source images and GIF frames verified.')


def main():
    if '--check' in sys.argv:
        check()
        return
    deck = Presentation(DECK)
    for slide_id in list(deck.slides._sldIdLst):
        if deck.part.related_slide(slide_id.rId).name.startswith((PREFIX, 'CHARACTER ANALOGY')):
            deck.part.drop_rel(slide_id.rId)
            deck.slides._sldIdLst.remove(slide_id)
    for number, (mode, path, *_rest) in enumerate(SLIDES, 1):
        slide = architecture(deck, number)
        for shape in list(slide.shapes):
            if shape.name.startswith(PREFIX):
                slide.shapes._spTree.remove(shape._element)
        diagram = next(sh for sh in slide.shapes if sh.shape_type == 13)
        diagram.left, diagram.top, diagram.width, diagram.height = GEOMETRY[number - 1]
        before = deck.slides.add_slide(slide.slide_layout)
        before.name = f'{PREFIX} {mode}'
        for shape in list(before.shapes):
            before.shapes._spTree.remove(shape._element)
        before.background.fill.solid()
        before.background.fill.fore_color.rgb = RGBColor(255, 255, 255)
        with Image.open(path) as image:
            scale = min((deck.slide_width - Inches(1)) / image.width,
                        (deck.slide_height - Inches(1)) / image.height)
            width, height = round(image.width * scale), round(image.height * scale)
        picture = before.shapes.add_picture(str(path), (deck.slide_width - width) // 2,
                                            (deck.slide_height - height) // 2,
                                            width=width, height=height)
        picture.name = f'{PREFIX} {mode}'
        slide_id = deck.slides._sldIdLst[-1]
        deck.slides._sldIdLst.remove(slide_id)
        deck.slides._sldIdLst.insert(list(deck.slides).index(slide), slide_id)
    temporary = DECK.with_suffix('.tmp.pptx')
    deck.save(temporary)
    temporary.replace(DECK)
    check()


if __name__ == '__main__':
    main()
