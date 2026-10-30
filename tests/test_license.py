"""SafeRun's own license (MIT) is present, names the owner, and the package metadata agrees."""
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_license_file_is_the_standard_mit_text_for_the_owner():
    text = (ROOT / "LICENSE").read_text()
    assert text.startswith("MIT License\n\nCopyright (c) 2026 Vinay Repalle\n")
    assert "Permission is hereby granted, free of charge" in text and 'THE SOFTWARE IS PROVIDED "AS IS"' in text


def test_package_metadata_declares_the_same_license():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert meta["project"]["license"] == "MIT" and meta["project"]["license-files"] == ["LICENSE"]
    assert not [c for c in meta["project"].get("classifiers", []) if c.startswith("License ::")]     # an SPDX expression excludes license classifiers
    assert int(meta["build-system"]["requires"][0].split(">=")[1]) >= 77                           # first setuptools with SPDX license expressions
    assert json.loads((ROOT / "web" / "package.json").read_text())["license"] == "MIT"


def test_readme_and_sdist_reference_the_license():
    assert "[MIT License](LICENSE)" in (ROOT / "README.md").read_text()
    assert "LICENSE" in (ROOT / "MANIFEST.in").read_text()
