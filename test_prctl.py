# python-pctrl -- python interface to the prctl function
# (c)2010-2015 Dennis Kaarsemaker <dennis@kaarsemaker.net
# See COPYING for licensing details

import distutils.util
import glob
import os
import re
import signal
import sys
import subprocess
import unittest

so = '.so'
try:
    import sysconfig
    so = sysconfig.get_config_var('SO')
except ImportError:
    pass

curdir = os.path.dirname(__file__)
builddir = os.path.join(curdir, 'build', 'lib.%s-%s' % (distutils.util.get_platform(), sys.version[0:3]))

# Always run from the builddir
if not os.path.exists(builddir) or \
   not os.path.exists(os.path.join(builddir, 'prctl.py')) or \
   not os.path.exists(os.path.join(builddir, '_prctl' + so)) or \
   int(os.path.getmtime(os.path.join(curdir, 'prctl.py'))) > int(os.path.getmtime(os.path.join(builddir, 'prctl.py'))) or \
   os.path.getmtime(os.path.join(curdir, '_prctlmodule.c')) > os.path.getmtime(os.path.join(builddir, '_prctl' + so)):
     sys.stderr.write("Please build the extension first, using ./setup.py build\n")
     sys.exit(1)
sys.path.insert(0, builddir)

import prctl
import _prctl

def require(attr):
    def decorator(func):
        if not hasattr(prctl, attr) and not hasattr(_prctl, attr):
            return lambda *args, **kwargs: None
        return func
    return decorator

class PrctlTest(unittest.TestCase):
    # There are architecture specific tests
    arch = os.uname()[4]
    # prctl behaviour differs when root, so you should test as root and non-root
    am_root = os.geteuid() == 0

    def test_constants(self):
        """Test whether copying of constants works"""
        self.assertEqual(prctl.ENDIAN_LITTLE, _prctl.PR_ENDIAN_LITTLE)
        self.assertEqual(prctl.SECBIT_NOROOT, _prctl.SECBIT_NOROOT)
        self.assertEqual(prctl.CAP_SYS_ADMIN, _prctl.CAP_SYS_ADMIN)
        self.assertRaises(AttributeError, getattr, prctl, 'PR_ENDIAN_LITTLE')
        self.assertRaises(AttributeError, getattr, prctl, 'PR_CAPBSET_READ')
        self.assertRaises(AttributeError, getattr, prctl, 'CAPBSET_READ')

    @require('PR_CAPBSET_READ')
    def test_capbset(self):
        """Test the get_capbset/set_capbset functions"""
        self.assertEqual(prctl.capbset_read(prctl.CAP_FOWNER), True)
        if self.am_root:
            self.assertEqual(prctl.capbset_drop(prctl.CAP_FOWNER), None)
            self.assertEqual(prctl.capbset_read(prctl.CAP_FOWNER), False)
        else:
            self.assertRaises(OSError, prctl.capbset_drop, prctl.CAP_MKNOD)
        self.assertRaises(ValueError, prctl.capbset_read, 999)

    @require('PR_CAPBSET_READ')
    def test_capbset_object(self):
        """Test manipulation of the capability bounding set via the capbset object"""
        self.assertEqual(prctl.capbset.sys_admin, True)
        if self.am_root:
            prctl.capbset.kill = False
            self.assertEqual(prctl.capbset.kill, False)
            self.assertEqual(prctl.capbset.sys_admin, True)
            prctl.capbset.drop("setgid", prctl.CAP_SETGID)
            self.assertEqual(prctl.capbset.setgid, False)
            caps = list(prctl.ALL_CAPS)
            caps.remove(prctl.CAP_NET_RAW)
            prctl.capbset.limit(*caps)
            self.assertEqual(prctl.capbset.net_raw, False)
            self.assertEqual(prctl.capbset.net_broadcast, True)

        else:
            def set_false():
                prctl.capbset.kill = False
            self.assertRaises(OSError, set_false)
        def set_true():
            prctl.capbset.kill = True
        self.assertRaises(ValueError, set_true)
        def unknown_attr():
            prctl.capbset.foo = 1
        self.assertRaises(AttributeError, unknown_attr)

    @require('get_child_subreaper')
    def test_child_subreaper(self):
        self.assertEqual(prctl.get_child_subreaper(), 0)
        prctl.set_child_subreaper(1)
        self.assertEqual(prctl.get_child_subreaper(), 1)
        prctl.set_child_subreaper(0)

    def test_dumpable(self):
        """Test manipulation of the dumpable flag"""
        prctl.set_dumpable(True)
        self.assertEqual(prctl.get_dumpable(), True)
        prctl.set_dumpable(False)
        self.assertEqual(prctl.get_dumpable(), False)
        self.assertRaises(TypeError, prctl.get_dumpable, "42")

    def test_endian(self):
        """Test manipulation of the endianness setting"""
        if self.arch == 'powerpc':
            # FIXME untested
            prctl.set_endian(prctl.ENDIAN_BIG)
            self.assertEqual(prctl.get_endian(), prctl.ENDIAN_BIG)
            prctl.set_endian(prctl.ENDIAN_LITTLE)
            self.assertEqual(prctl.get_endian(), prctl.ENDIAN_LITTLE)
            self.assertRaises(ValueError, prctl.set_endian, 999)
        else:
            self.assertRaises(OSError, prctl.get_endian)
            self.assertRaises(OSError, prctl.set_endian)

    def test_fpemu(self):
        """Test manipulation of the fpemu setting"""
        if self.arch == 'ia64':
            # FIXME - untested
            prctl.set_fpemu(prctl.FPEMU_SIGFPE)
            self.assertEqual(prctl.get_fpemu(), prctl.FPEMU_SIGFPE)
            prctl.set_fpemu(prctl.FPEMU_NOPRINT)
            self.assertEqual(prctl.get_fpemu(), prctl.FPEMU_NOPRINT)
            self.assertRaises(ValueError, prctl.set_fpexc, 999)
        else:
            self.assertRaises(OSError, prctl.get_fpemu)
            self.assertRaises(OSError, prctl.set_fpemu, prctl.FPEMU_SIGFPE)

    def test_fpexc(self):
        """Test manipulation of the fpexc setting"""
        if self.arch == 'powerpc':
            # FIXME - untested
            prctl.set_fpexc(prctl.FP_EXC_SW_ENABLE)
            self.assertEqual(prctl.get_fpexc() & prctl.PR_FP_EXC_SW_ENABLE, prctl.PR_FP_EXC_SW_ENABLE)
            self.assertRaises(ValueError, prctl.set_fpexc, 999)
        else:
            self.assertRaises(OSError, prctl.get_fpexc)
            self.assertRaises(OSError, prctl.set_fpexc)

    def test_keepcaps(self):
        """Test manipulation of the keepcaps setting"""
        prctl.set_keepcaps(True)
        self.assertEqual(prctl.get_keepcaps(), True)
        prctl.set_keepcaps(False)
        self.assertEqual(prctl.get_keepcaps(), False)

    @require('set_mce_kill')
    def test_mce_kill(self):
        """Test the MCE_KILL setting"""
        fd = open('/proc/sys/vm/memory_failure_early_kill')
        current = int(fd.read().strip())
        fd.close()
        prctl.set_mce_kill(prctl.MCE_KILL_EARLY)
        self.assertEqual(prctl.get_mce_kill(), prctl.MCE_KILL_EARLY)
        prctl.set_mce_kill(prctl.MCE_KILL_LATE)
        self.assertEqual(prctl.get_mce_kill(), prctl.MCE_KILL_LATE)
        prctl.set_mce_kill(prctl.MCE_KILL_DEFAULT)
        self.assertEqual(prctl.get_mce_kill(), prctl.MCE_KILL_DEFAULT)

    def test_name(self):
        """Test setting the process name"""
        name = prctl.get_name().swapcase() * 16
        prctl.set_name(name)
        self.assertEqual(prctl.get_name(), name[:15])

    @require('get_no_new_privs')
    def test_no_new_privs(self):
        """Test the no_new_privs function"""
        self.assertEqual(prctl.get_no_new_privs(), 0)
        pid = os.fork()
        if pid:
            self.assertEqual(os.waitpid(pid, 0)[1], 0)
        else:
            prctl.set_no_new_privs(1)
            self.assertEqual(prctl.get_no_new_privs(), 1)
            if os.geteuid() != 0:
                sp = subprocess.Popen(['ping', '-c1', 'localhost'], stderr=subprocess.PIPE)
                sp.communicate()
                self.assertNotEqual(sp.returncode, 0)
            os._exit(0)

    def test_proctitle(self):
        """Test setting the process title, including too long titles"""
        title = "This is a test!"
        prctl.set_proctitle(title)
        ps_output = subprocess.Popen(['ps', '-f', '-p', '%d' % os.getpid()],
                                     stdout=subprocess.PIPE).communicate()[0].decode('ascii')
        self.assertTrue(ps_output.strip().endswith(title))
        # This should not segfault but truncate
        title2 = "And this is a test too! Don't segfault."
        prctl.set_proctitle(title2)
        ps_output = subprocess.Popen(['ps', '-f', '-p', '%d' % os.getpid()],
                                     stdout=subprocess.PIPE).communicate()[0].decode('ascii')
        self.assertTrue(ps_output.strip().endswith(title2[:len(title)]))

    def test_pdeathsig(self):
        """Test manipulation of the pdeathsig setting"""
        self.assertRaises(ValueError, prctl.set_pdeathsig, 999)
        self.assertEqual(prctl.get_pdeathsig(), 0)
        prctl.set_pdeathsig(signal.SIGINT)
        self.assertEqual(prctl.get_pdeathsig(), signal.SIGINT)

    @require('set_ptracer')
    def test_ptracer(self):
        """Test manipulation of the ptracer setting"""
        if not os.path.exists('/proc/sys/kernel/yama'):
            return
        self.assertEqual(prctl.get_ptracer(), os.getppid())
        prctl.set_ptracer(1)
        self.assertEqual(prctl.get_ptracer(), 1)
        new_pid = os.fork()
        if new_pid:
            os.waitpid(new_pid, 0)
        else:
            os._exit(0)
        self.assertRaises(OSError, prctl.set_ptracer, new_pid)

    @require('get_seccomp')
    def test_seccomp(self):
        """Test manipulation of the seccomp setting"""
        self.assertEqual(prctl.get_seccomp(), False)
        result = os.fork()
        if result == 0:
            # In child
            prctl.set_seccomp(True)
            # This should kill ourselves
            open('/etc/resolv.conf')
            # If not, kill ourselves anyway
            sys.exit(0)
        else:
            pid, result = os.waitpid(result, 0)
            self.assertTrue(os.WIFSIGNALED(result))
            self.assertEqual(os.WTERMSIG(result), signal.SIGKILL)

    @require('PR_GET_SECUREBITS')
    def test_securebits(self):
        """Test manipulation of the securebits flag"""
        self.assertEqual(prctl.get_securebits(), 0)
        if os.geteuid() == 0:
            prctl.set_securebits(prctl.SECBIT_KEEP_CAPS)
            self.assertEqual(prctl.get_securebits(), prctl.SECBIT_KEEP_CAPS)
        else:
            self.assertRaises(OSError, prctl.set_securebits, prctl.SECBIT_KEEP_CAPS)

    @require('PR_GET_SECUREBITS')
    def test_securebits_obj(self):
        """Test manipulation of the securebits via the securebits object"""
        self.assertEqual(prctl.securebits.noroot, False)
        if os.geteuid() == 0:
            prctl.securebits.noroot = True
            self.assertEqual(prctl.securebits.noroot, True)
            self.assertEqual(prctl.securebits.no_setuid_fixup, False)
            prctl.securebits.noroot_locked = True
            def set_false():
                prctl.securebits.noroot = False
            self.assertRaises(OSError, set_false)
        else:
            def set_true():
                prctl.securebits.noroot = True
            self.assertRaises(OSError, set_true)

    @require('get_timerslack')
    def test_timerslack(self):
        """Test manipulation of the timerslack value"""
        default = prctl.get_timerslack()
        prctl.set_timerslack(1000)
        self.assertEqual(prctl.get_timerslack(), 1000)
        prctl.set_timerslack(0)
        self.assertEqual(prctl.get_timerslack(), default)

    def test_timing(self):
        """Test manipulation of the timing setting"""
        self.assertRaises(OSError, prctl.set_timing, prctl.TIMING_TIMESTAMP);
        self.assertEqual(prctl.get_timing(), prctl.TIMING_STATISTICAL)
        prctl.set_timing(prctl.TIMING_STATISTICAL)
        self.assertEqual(prctl.get_timing(), prctl.TIMING_STATISTICAL)

    @require('set_tsc')
    def test_tsc(self):
        """Test manipulation of the timestamp counter flag"""
        if re.match('i.86|x86_64', self.arch):
            prctl.set_tsc(prctl.TSC_SIGSEGV)
            self.assertEqual(prctl.get_tsc(), prctl.TSC_SIGSEGV)
            prctl.set_tsc(prctl.TSC_ENABLE)
            self.assertEqual(prctl.get_tsc(), prctl.TSC_ENABLE)
        else:
            # FIXME untested
            self.assertRaises(OSError, prctl.get_tsc)
            self.assertRaises(OSError, prctl.set_tsc, prctl.TSC_ENABLE)

    def test_unalign(self):
        """Test manipulation of the unaligned access setting"""
        if self.arch in ('ia64', 'parisc', 'powerpc', 'alpha'):
            # FIXME untested
            prctl.set_unalign(prctl.UNALIGN_NOPRINT)
            self.assertEqual(prctl.get_unalign(), prctl.UNALIGN_NOPRINT)
            prctl.set_unalign(prctl.UNALIGN_SIGBUS)
            self.assertEqual(prctl.get_unalign(), prctl.UNALIGN_SIGBUS)
        else:
            self.assertRaises(OSError, prctl.get_unalign)
            self.assertRaises(OSError, prctl.set_unalign, prctl.UNALIGN_NOPRINT)

    def test_getcaps(self):
        """Test the get_caps function"""
        self.assertEqual(prctl.get_caps(), {prctl.CAP_EFFECTIVE: {}, prctl.CAP_INHERITABLE: {}, prctl.CAP_PERMITTED: {}})
        self.assertEqual(prctl.get_caps((prctl.CAP_SYS_ADMIN, prctl.ALL_FLAGS),(prctl.CAP_NET_ADMIN, prctl.CAP_EFFECTIVE)),
                          {prctl.CAP_EFFECTIVE: {prctl.CAP_SYS_ADMIN: self.am_root, prctl.CAP_NET_ADMIN: self.am_root},
                           prctl.CAP_INHERITABLE: {prctl.CAP_SYS_ADMIN: False},
                           prctl.CAP_PERMITTED: {prctl.CAP_SYS_ADMIN: self.am_root}})
        self.assertEqual(prctl.get_caps(([prctl.CAP_SYS_ADMIN,prctl.CAP_NET_ADMIN], [prctl.CAP_EFFECTIVE,prctl.CAP_PERMITTED])),
                          {prctl.CAP_EFFECTIVE: {prctl.CAP_SYS_ADMIN: self.am_root, prctl.CAP_NET_ADMIN: self.am_root},
                           prctl.CAP_INHERITABLE: {},
                           prctl.CAP_PERMITTED: {prctl.CAP_SYS_ADMIN: self.am_root, prctl.CAP_NET_ADMIN: self.am_root}})
        self.assertRaises(KeyError, prctl.get_caps, (prctl.CAP_SYS_ADMIN,'abc'))
        def fail():
            prctl.get_caps((1234,prctl.ALL_FLAGS))
        self.assertRaises(ValueError, fail)

    def test_setcaps(self):
        """Test the setcaps function"""
        if self.am_root:
            prctl.set_caps((prctl.CAP_SETUID, prctl.ALL_FLAGS, True))
        else:
            self.assertRaises(OSError, prctl.set_caps, (prctl.CAP_SETUID, prctl.ALL_FLAGS, True))
        self.assertEqual(prctl.get_caps((prctl.CAP_SETUID, prctl.ALL_FLAGS)),
                         {prctl.CAP_EFFECTIVE: {prctl.CAP_SETUID: self.am_root},
                          prctl.CAP_PERMITTED: {prctl.CAP_SETUID: self.am_root},
                          prctl.CAP_INHERITABLE: {prctl.CAP_SETUID: self.am_root}})
        prctl.set_caps((prctl.CAP_SETUID, prctl.ALL_FLAGS, False))
        self.assertEqual(prctl.get_caps((prctl.CAP_SETUID, prctl.ALL_FLAGS)),
                         {prctl.CAP_EFFECTIVE: {prctl.CAP_SETUID: False},
                          prctl.CAP_PERMITTED: {prctl.CAP_SETUID: False},
                          prctl.CAP_INHERITABLE: {prctl.CAP_SETUID: False}})
        self.assertRaises(OSError, prctl.set_caps, (prctl.CAP_SETUID, prctl.ALL_FLAGS, True))

    capabilities = [x[4:].lower() for x in dir(_prctl) if x.startswith('CAP_')]
    @require('cap_to_name')
    def test_capabilities_objects(self):
        for cap in self.capabilities:
            if cap in ('all','effective','permitted','inheritable','setuid'):
                continue
            # This one now triggers EINVAL
            if cap == 'wake_alarm':
                continue
            self.assertEqual(getattr(prctl.cap_effective, cap), self.am_root)
            self.assertEqual(getattr(prctl.cap_permitted, cap), self.am_root)
            self.assertEqual(getattr(prctl.cap_inheritable, cap), False)
        for cap in ['dac_override','mac_override','net_raw']:
            if self.am_root:
                setattr(prctl.cap_effective, cap, False)
                setattr(prctl.cap_permitted, cap, False)
                setattr(prctl.cap_inheritable, cap, False)
            self.assertRaises(OSError, setattr, prctl.cap_effective, cap, True)
            self.assertRaises(OSError, setattr, prctl.cap_permitted, cap, True)
            if self.am_root:
                setattr(prctl.cap_inheritable, cap, True)
            else:
                self.assertRaises(OSError, setattr, prctl.cap_inheritable, cap, True)

        if self.am_root:
            prctl.cap_effective.drop('linux_immutable', 'sys_boot', 'sys_pacct')
            self.assertEqual(prctl.cap_effective.linux_immutable, False)
            self.assertEqual(prctl.cap_effective.sys_boot, False)
            self.assertEqual(prctl.cap_effective.sys_pacct, False)

            caps = list(prctl.ALL_CAPS)
            caps.remove(prctl.CAP_SYS_NICE)
            prctl.cap_effective.limit(*caps)
            self.assertEqual(prctl.cap_effective.sys_nice, False)

    @require('cap_to_name')
    def test_captoname(self):
        self.assertEqual(_prctl.cap_to_name(prctl.CAP_SYS_ADMIN), 'sys_admin')

if __name__ == '__main__':
    unittest.main()
