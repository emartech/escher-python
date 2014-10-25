#!/usr/bin/env python

from distutils.core import setup

setup(name='EscherAuth',
      version='0.1',
      description='Escher helps you creating secure HTTP requests'
                  '(for APIs) by signing HTTP(s) requests.',
      author='Andras Barthazi',
      author_email='andras.barthazi@emarsys.com',
      url='http://escherauth.io/',
      packages=[
          'escherauth',
          'escherauth.escherauth',
      ],
      )
