from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="phish-tracker",
    version="1.0.0",
    author="Srinjoy3002",
    description="Advanced Multi-Vector Phishing Site Detector for Kali Linux and Windows Terminal",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Srinjoy3002/Phishing_tracker",
    packages=find_packages(),
    py_modules=["phish_tracker"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "phish-tracker=phish_tracker:main",
        ],
    },
)
