from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="virus-scanner",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A tool for scanning files, directories, and zip archives for viruses, malware, and other threats",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/virus-scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "virus-scan=virus_scan:main",
        ],
    },
) 