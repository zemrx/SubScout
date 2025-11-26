#!/usr/bin/env python3
"""Setup script for SubScout."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
requirements_file = this_directory / "requirements.txt"
if requirements_file.exists():
    requirements = [
        line.strip() 
        for line in requirements_file.read_text(encoding='utf-8').splitlines()
        if line.strip() and not line.startswith('#')
    ]

setup(
    name='subscout',
    version='1.0.0',
    description='Advanced Subdomain Enumeration Tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Hussein Hady',
    author_email='',  # Add your email if desired
    url='https://github.com/yourusername/SubScout',  # Update with your repo URL
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'subscout=subscout.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Internet :: Name Service (DNS)',
    ],
    keywords='subdomain enumeration security reconnaissance dns',
)
