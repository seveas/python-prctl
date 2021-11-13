#!/usr/bin/python

from setuptools import setup, Extension
import glob
import os
import subprocess
import sys

# Check our environment
# - Need to be on linux
# - Need kernel 2.6.18+
#   - Skip check by setting the environment variable PRCTL_SKIP_KERNEL_CHECK to TRUE or 1
# - Need python 2.4+
# - Need gcc
#   - Skip check by setting the environment variable PRCTL_SKIP_CC_CHECK to TRUE or 1
# - Need C headers
#   - Skip check by setting the environment variable PRCTL_SKIP_LIBC_CHECK to TRUE or 1
# - Need libcap headers
#   - Skip check by setting the environment variable PRCTL_SKIP_LIBCAP_CHECK to TRUE or 1
if not sys.platform.startswith('linux'):
    sys.stderr.write("This module only works on linux\n")
    sys.exit(1)


truthy_environment_variable = ("true", "yes", "1")

disable_kernel_check = os.environ.get("PRCTL_SKIP_KERNEL_CHECK", "False").lower() in truthy_environment_variable
kvers = os.uname()[2]
if kvers < '2.6.18' and not disable_kernel_check:
    sys.stderr.write("This module requires linux 2.6.18 or newer\n")
    sys.exit(1)

if sys.version_info[:2] < (2,4):
    sys.stderr.write("This module requires python 2.4 or newer\n")
    sys.exit(1)

GCC = os.environ.get('CC', 'gcc')
disable_cc_check = os.environ.get("PRCTL_SKIP_CC_CHECK", "False").lower() in truthy_environment_variable
try:
    subprocess.call([GCC,'-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
except:
    sys.stderr.write("You need to install gcc to build this module\n")
    if not disable_kernel_check:
        sys.exit(1)

CPP = os.environ.get('CPP', 'cpp')
CPPFLAGS = os.environ.get("CPPFLAGS", "").split(' ')
disable_libc_check = os.environ.get("PRCTL_SKIP_LIBC_CHECK", "False").lower() in truthy_environment_variable
sp = subprocess.Popen([CPP] + CPPFLAGS, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ)
sp.communicate('#include <sys/prctl.h>\n'.encode())
if sp.returncode:
    sys.stderr.write("You need to install libc development headers to build this module\n")
    if not disable_libc_check:
        sys.exit(1)

sp = subprocess.Popen([CPP] + CPPFLAGS, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ)
sp.communicate('#include <sys/capability.h>\n'.encode())
disable_libcap_check = os.environ.get("PRCTL_SKIP_LIBCAP_CHECK", "False").lower() in truthy_environment_variable
if sp.returncode:
    sys.stderr.write("You need to install libcap development headers to build this module\n")
    if not disable_libcap_check:
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
      python_requires='>=2.4',
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
