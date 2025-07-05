                        
import setuptools

# Read the contents of the README file for the long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lfimap-ng",
    version="1.0.0",
    author="RelunSec (Org)",
    author_email="cs7778503@gmail.com",
    description="A Powerful Local File Inclusion (LFI) Exploitation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/relunsec/lfimap",
    project_urls={
        "Bug Tracker": "https://gitlab.com/relunsec/lfimap/-/issues",
    },
    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.org/classifiers/
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    package_dir={"": "."},
    packages=setuptools.find_packages(where="."),
    python_requires=">=3.6",

    # List of dependencies
    install_requires=[
        "requests",
        "rich",
        "requests-ntlm",
    ],

    # Create a command-line entry point
    # This will create an executable 'lfimap' in the user's path
    entry_points={
        "console_scripts": [
            "lfimap=lfimap.cli:main", # Assumes your main function is in a file named lfimap.py
        ],
    },

    # Include non-code files specified in MANIFEST.in
    include_package_data=True,
)
