"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
from setuptools import setup

with open("README.md", encoding="utf-8") as read:
    README = read.read()

setup(
    name="pythondefender",
    version="1.0.2",
    description="A simple, easy-to-use Python file protector.",
    packages=[
        "pydefender",
        "pydefender.utils",
        "pydefender.modules"
    ],
    license="MIT",
    author="Kova / api",
    url="https://github.com/apilol/PyDefender",
    author_email="email@kova.rip",
    long_description_content_type="text/markdown",
    long_description=README,
    keywords=[
        "protect", "protection",
        "defend", "defender",
        "obfuscate", "obfuscation",
        "pydefend", "pydefender"
    ],
    install_requires=[
        "humanize",
        "loguru",
        "discord-webhook",
        "py-cpuinfo",
        "command_runner",
        "psutil",
        "httpx",
        "WMI",
        "pywin32",
        "Pillow",
        "observable",
        "cryptography",
        "pythondefender"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11",
        "Natural Language :: English",
        "Topic :: Education",
        "Topic :: Internet"
    ]
)
