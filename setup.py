#!/usr/bin/python

from distutils.core import setup, Extension
import glob
import os
import subprocess
import sys

# Check our environment
# - Need to be on linux
# - Need kernel 2.6.26+
# - Need python 2.5+
# - Need gcc
# - Need C headers
# - Need libcap headers
if not sys.platform.startswith('linux'):
    print >>sys.stderr, "This module only works on linux"
    sys.exit(1)

kvers = os.uname()[2]
if kvers < '2.6.26' and not os.environ.get("PRCTL_SKIP_KERNEL_CHECK",False):
    print >>sys.stderr, "This module requires linux 2.6.26 or newer"
    sys.exit(1)

if sys.version_info[0] != 2 or sys.version_info[1] < 5:
    print >>sys.stderr, "This module requires python 2.5 or newer (but not 3.x)"
    sys.exit(1)

exit = False
try:
    subprocess.call(['gcc','-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except:
    print >>sys.stderr, "You need to install gcc to build this module"
    exit = True

sp = subprocess.Popen(['cpp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sp.communicate('#include <sys/prctl.h>\n')
if sp.returncode:
    print >>sys.stderr, "You need to install libc development headers to build this module"
    exit = True

sp = subprocess.Popen(['cpp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
sp.communicate('#include <sys/capability.h>\n')
if sp.returncode:
    print >>sys.stderr, "You need to install libcap development headers to build this module"
    exit = True

if exit:
    sys.exit(1)

_prctl = Extension("_prctl",
                   sources = ['_prctlmodule.c'],
                   depends = ['securebits.h'],
                   libraries = ['cap'])

setup(name = "python-prctl",
      version = "1.4.0",
      author = "Dennis Kaarsemaker",
      author_email = "dennis@kaarsemaker.net",
      url = "http://github.com/seveas/python-prctl",
      description = "Python(ic) interface to the linux prctl syscall",
      py_modules = ["prctl"],
      ext_modules = [_prctl],
      classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: C',
        'Programming Language :: Python :: 2',
        'Topic :: Security',
      ]
)
