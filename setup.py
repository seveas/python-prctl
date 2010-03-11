#!/usr/bin/python

from distutils.core import setup, Extension
import os
import sys

if sys.platform != 'linux2':
    print >>sys.stderr, "This module only works on linux"
    sys.exit(1)
kvers = os.uname()[2]
if kvers < '2.6.26':
    print >>sys.stderr, "This module requires linux 2.6.26 or newer"
    sys.exit(1)
if sys.version_info[0] != 2 or sys.version_info[1] < 5:
    print >>sys.stderr, "This module requires python 2.5 or newer (but not 3.x)"
    sys.exit(1)

_prctl = Extension("_prctl",
                   sources = ['_prctlmodule.c'],
                   include_dirs = ['/usr/src/linux-headers-2.6.32-16/include']) #FIXME

setup(name = "prctl",
      version = "1.0",
      author = "Dennis Kaarsemaker",
      author_email = "dennis@kaarsemaker.net",
      url = "http://github.com/seveas/python-prctl",
      description = "Python(ic) interface to the linux prctl syscall",
      py_modules = ["prctl"],
      ext_modules = [_prctl],
      classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: C',
        'Programming Language :: Python :: 2',
        'Topic :: Security',
      ]
)
