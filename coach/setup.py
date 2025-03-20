from setuptools import setup, find_packages

setup(
    name="coach",
    version="1.0.0",
    packages=find_packages(),
    install_requires=open("requirements.txt").readlines(),
    package_data={
        "coach": ["react-security.yaml"],
    },
    entry_points={
        "console_scripts": [
            "coach = coach.__main__:main"
        ]
    },
    author="Bahati",
    description="A comprehensive code security & quality analysis tool",
    url="https://github.com/Rukundo-Bahati/coach",
)