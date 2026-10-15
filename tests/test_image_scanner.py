import pytest
from PIL import Image, ImageDraw
import io
from src.image_scanner import extract_exif_metadata, strip_image_metadata, redact_image_region

def test_strip_image_metadata():
    img = Image.new("RGB", (100, 100), color="blue")
    stripped = strip_image_metadata(img)
    assert stripped.size == (100, 100)
    assert stripped.mode == "RGB"

def test_redact_image_region():
    img = Image.new("RGB", (200, 200), color="white")
    # Redact box (50, 50, 150, 150)
    redacted = redact_image_region(img, (50, 50, 150, 150), color="black")
    
    # Check pixel inside box is black
    pixel_inside = redacted.getpixel((100, 100))
    assert pixel_inside == (0, 0, 0)
    
    # Check pixel outside box is still white
    pixel_outside = redacted.getpixel((10, 10))
    assert pixel_outside == (255, 255, 255)
