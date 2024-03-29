from setuptools import setup, find_packages


__title__ = "ssllabsscan"
__version__ = "1.0.0"
__summary__ = "SSL Labs Analysis Reporting"

__requirements__ = [
    "requests>=2.13.0",
]

__entry_points__ = {
    "console_scripts": [
        "ssllabs-scan = ssllabsscan.main:main",
    ]
}

CLASSIFIERS = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3 :: Only",
]

setup(
    classifiers=CLASSIFIERS,
    data_files=[
        ("", ["ReleaseNotes.md"]),
    ],
    description=__summary__,
    entry_points=__entry_points__,
    install_requires=__requirements__,
    name=__title__,
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.6",
    version=__version__,
    zip_safe=False,
)
