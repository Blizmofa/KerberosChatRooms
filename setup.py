from os import path
from typing import Union
from setuptools import setup, find_packages

dependencies = [
    "pycryptodome==3.20.0",
    "colorama~=0.4.4",
    "setuptools~=58.1.0"
]


def get_description() -> Union[tuple, None]:
    # Read README content
    with open('README.md', 'r') as f:
        readme_contents = f.read()

        # Get just the overview section
        start_marker = '## Overview'

        start_index = readme_contents.find(start_marker)
        # Overview not found
        if start_index == -1:
            return None

        # Find the end index of the overview section
        end_index = readme_contents.find('##', start_index + len(start_marker))
        if end_index == -1:
            end_index = len(readme_contents)

        # Extract the content between the start and end markers
        overview_content = readme_contents[start_index + len(start_marker):end_index]

        # Remove leading and trailing whitespaces and newlines
        overview_content = overview_content.strip()

    return readme_contents, overview_content


setup(
    name=path.basename(path.abspath(path.dirname(__file__))),
    version='1.0',
    author='Blizmofa',
    author_email='blizmofa@gmail.com',
    description=get_description()[1],
    long_description=get_description()[0],
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=dependencies,
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Windows 11',
    ],
)