#!/usr/bin/env python

import os, sys
import http_replay

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='python-http-replay',
    version=http_replay.__version__,
    description='Replay HTTP trafic extracted from capture files (pcap)',
    author=http_replay.__author__,
    url=http_replay.__url__,
    packages=['http_replay'],
    package_data={'': ['LICENSE']},
    package_dir={'http_replay': 'http_replay'},
    scripts=["bin/python-http-replay"],
    include_package_data=True,
    # install_requires=['py-pypcap', 'dpkt'],
    license=open('LICENSE').read(),
    zip_safe=False,
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
    ),
)
