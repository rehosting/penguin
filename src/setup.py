from setuptools import setup
import os

if os.path.exists("penguin/version.txt"):
    with open("penguin/version.txt") as f:
        version = f.read().strip()
else:
    version = "0.0.1"
setup(version=version)
