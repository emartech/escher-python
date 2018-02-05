#!/usr/bin/env python
from setuptools import setup

setup(
    name='escherauth',
    description='Python implementation of the AWS4 compatible Escher HTTP request signing protocol.',
    version='0.3.0',
    author='Andras Barthazi',
    author_email='andras@barthazi.hu',
    license='MIT',
    url='http://escherauth.io/',
    download_url='https://github.com/emartech/escher-python',
    py_modules=['escherauth.escherauth'],
    packages=[
        'escherauth',
    ],
    zip_safe=False,
    install_requires=[
        'requests>=1.2.3,<3.0.0'
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
