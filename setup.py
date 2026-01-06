from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="packet-analyzer",
    version="0.1.0",
    author="yuncaibread",
    description="A network packet sniffer and analyzer for inspecting network traffic",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yuncaibread/packet-analyzer",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.7",
    install_requires=[
        "scapy>=2.4.5",
        "click>=8.0.0",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "packet-analyzer=packet_analyzer.cli:main",
        ],
    },
)
