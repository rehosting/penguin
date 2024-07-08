from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="unifyroot",
    version="0.1.0",
    author="Andrew Fasano",
    author_email="fasano@mit.edu",
    description="Recover filesystem layouts and combine them into a single archive",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rehosting/fw2tar",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
    install_requires=[
    ],
    entry_points={
        "console_scripts": [
            "unifyroot=unifyroot.cli:main",
        ],
    },
)
