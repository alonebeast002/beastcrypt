from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name             = "beastcrypt",
    version          = "1.2.2",
    author           = "ALONE BEAST",
    author_email     = "ytthumbpro@gmail.com",
    description      = "Wayback Hunter + JS Secret Scanner — by ALONE BEAST",
    long_description = long_description,
    long_description_content_type = "text/markdown",

    url              = "https://github.com/alonebeast002/beastcrypt",
    project_urls     = {
        "Source Code": "https://github.com/alonebeast002/beastcrypt",
        "Bug Tracker": "https://github.com/alonebeast002/beastcrypt/issues",
    },

    packages         = find_packages(),

    python_requires  = ">=3.8",

    install_requires = [],

    entry_points     = {
        "console_scripts": [
            "beastcrypt=beastcrypt.main:main",
        ],
    },

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
