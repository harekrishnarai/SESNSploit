from setuptools import setup, find_packages

setup(
    name="snare",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "boto3",
        "pyfiglet",
        "colorama"
    ],
    entry_points={
        "console_scripts": [
            "snare=main:main"
        ]
    },
    author="Harekrishna Rai",
    description="A tool for identifying and exploiting misconfigurations in AWS SNS and SES services.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/harekrishnarai/snare",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
