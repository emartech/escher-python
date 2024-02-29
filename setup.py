#!/usr/bin/env python
from setuptools import setup
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / 'README.md').read_text()

setup(
    name='escherauth',
    description='Python implementation of the AWS4 compatible Escher HTTP request signing protocol.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='1.0.1',
    author='Emarsys Security',
    author_email='security@emarsys.com',
    license='MIT',
    url='http://escherauth.io/',
    download_url='https://github.com/emartech/escher-python',
    py_modules=['escherauth.escherauth'],
    packages=[
        'escherauth',
    ],
    zip_safe=False,
    install_requires=[
        'requests>=2.0.0,<3.0.0'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Environment :: Plugins',
        'License :: OSI Approved :: MIT License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities'
    ],
)
