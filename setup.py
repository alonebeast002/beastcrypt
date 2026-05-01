from setuptools import setup, find_packages
import os

# README ko long_description ke liye read karo
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    # ── Package identity ────────────────────────────────────────────────────
    name             = "beastcrypt",          # PyPI pe yahi naam aayega
    version          = "1.2.1",
    author           = "ALONE BEAST",
    author_email     = "ytthumbpro@gmail.com",  # apna email daal dena
    description      = "Wayback Hunter + JS Secret Scanner — by ALONE BEAST",
    long_description = long_description,
    long_description_content_type = "text/markdown",

    # ── URLs ────────────────────────────────────────────────────────────────
    url              = "https://github.com/alonebeast002/beastcrypt",
    project_urls     = {
        "Source Code": "https://github.com/alonebeast002/beastcrypt",
        "Bug Tracker": "https://github.com/alonebeast002/beastcrypt/issues",
    },

    # ── Package discovery ───────────────────────────────────────────────────
    packages         = find_packages(),   # beastcrypt/ folder auto-detect

    # ── Python version ──────────────────────────────────────────────────────
    python_requires  = ">=3.8",

    # ── Dependencies ────────────────────────────────────────────────────────
    # Ye tool stdlib + curl (system) use karta hai, koi pip dep nahi
    install_requires = [],

    # ── CLI entry point ─────────────────────────────────────────────────────
    # Yahi magic hai: `pip install beastcrypt` ke baad
    # `beastcrypt` command seedha terminal mein chalta hai
    entry_points     = {
        "console_scripts": [
            "beastcrypt=beastcrypt.main:main",
        ],
    },

    # ── PyPI classifiers ────────────────────────────────────────────────────
    classifiers      = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
    ],

    keywords = (
        "security recon wayback js secrets scanner osint bug-bounty "
        "alone-beast beastcrypt recon hacking pentest"
    ),
)
