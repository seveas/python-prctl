#!/usr/bin/python

from setuptools import setup, Extension
import glob
import os
import subprocess
import sys

# Check our environment
# - Need to be on linux
# - Need kernel 2.6.18+
# - Need python 2.4+
# - Need gcc
# - Need C headers
# - Need libcap headers
if not sys.platform.startswith('linux'):
    sys.stderr.write("This module only works on linux\n")
    sys.exit(1)

kvers = os.uname()[2]
if kvers < '2.6.18' and not os.environ.get("PRCTL_SKIP_KERNEL_CHECK",False):
    sys.stderr.write("This module requires linux 2.6.18 or newer\n")
    sys.exit(1)

if sys.version_info[:2] < (2,4):
    sys.stderr.write("This module requires python 2.4 or newer\n")
    sys.exit(1)

exit = False
try:
    subprocess.call(['gcc','-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except:
    sys.stderr.write("You need to install gcc to build this module\n")
    sys.exit(1)

sp = subprocess.Popen(['cpp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ)
sp.communicate('#include <sys/prctl.h>\n'.encode())
if sp.returncode:
    sys.stderr.write("You need to install libc development headers to build this module\n")
    exit = True

sp = subprocess.Popen(['cpp'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ)
sp.communicate('#include <sys/capability.h>\n'.encode())
if sp.returncode:
    sys.stderr.write("You need to install libcap development headers to build this module\n")
    exit = True

if exit:
    sys.exit(1)

_prctl = Extension("_prctl",
                   sources = ['_prctlmodule.c'],
                   depends = ['securebits.h'],
                   libraries = ['cap'])

setup(name = "python-prctl",
      version = "1.8.1",
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
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
      ]
)
