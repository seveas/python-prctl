========================================
Welcome to python-prctl's documentation!
========================================

The linux prctl function allows you to control specific characteristics of a
process' behaviour. Usage of the function is fairly messy though, due to
limitations in C and linux. This module provides a nice non-messy python(ic)
interface. Most of the text in this documentation is based on text from the
linux manpages :manpage:`prctl(2)` and :manpage:`capabilities(7)`

Besides prctl, this library also wraps libcap for complete capability handling
and allows you to set the process name as seen in ps and top.

Downloading and installing
==========================

Before you try to install python-prctl, you will need to install the following:

* gcc
* libc development headers
* libcap development headers

On Debian and Ubuntu, this is done as follows:

.. code-block:: sh

  $ sudo apt-get install build-essential libcap-dev

On Fedora and other RPM-based distributions:

.. code-block:: sh

  $ sudo yum install gcc glibc-devel libcap-devel

The latest stable version can be installed with distutils:

.. code-block:: sh

  $ sudo easy_install python-prctl

The latest development source for python-prctl can be downloaded from `GitHub
<http://github.com/seveas/python-prctl>`_. Installing is again done with distutils.

.. code-block:: sh

  $ git clone http://github.com/seveas/python-prctl
  $ cd python-prctl
  $ python setup.py build
  $ sudo python setup.py install

The prctl module is now ready to use.

:mod:`prctl` -- Control process attributes
==========================================
.. module:: prctl
   :platform: Linux (2.6.25 or newer)
   :synopsis: Control process attributes
.. moduleauthor:: Dennis Kaarsemaker <dennis@kaarsemaker.net>

.. function:: set_child_subreaper(flag)

  When processes double-fork, they get implicitly re-parented to PID 1. Using
  this function, processes can mark themselves as service manager and will
  remain parent of any such processes they launch, becoming a sort of sub-init.
  They will then be responsible for handling :const:`~signal.SIGCHLD` and
  calling :func:`wait` in them.

  This is only available in linux 3.4 and newer

.. function:: get_child_subreaper()

  Determine whether we are a sub-init.

  This is only available in linux 3.4 and newer

.. function:: set_dumpable(flag)

  Set the state of the flag determining whether core dumps are produced for
  this process upon delivery of a signal whose default behavior is to produce a
  core dump. (Normally this flag is set for a process by default, but it is
  cleared when a set-user-ID or set-group-ID program is executed and also by
  various system calls that manipulate process UIDs and GIDs).

.. function:: get_dumpable()

  Return the state of the dumpable flag.

.. function:: set_endian(endianness)

  Set the endian-ness of the calling process. Valid values are
  :const:`~prctl.ENDIAN_BIG`, :const:`~prctl.ENDIAN_LITTLE` and
  :const:`~prctl.ENDIAN_PPC_LITTLE` (PowerPC pseudo little endian).

  .. note::

    This function only works on PowerPC systems. An :exc:`OSError` is raised
    when called on other systems.

.. function:: get_endian()

  Return the endian-ness of the calling process, see :func:`set_endian`.

.. function:: set_fpemu(flag)

  Set floating-point emulation control flag. Pass :const:`~prctl.FPEMU_NOPRINT`
  to silently emulate fp operations accesses, or :const:`~prctl.FPEMU_SIGFPE`
  to not emulate fp operations and send :const:`~signal.SIGFPE` instead.

  .. note::

    This function only works on ia64 systems. An :exc:`OSError` is raised
    when called on other systems.

.. function:: get_fpemu()

  Get floating-point emulation control flag. See :func:`set_fpemu`.

.. function:: set_fpexc(mode)

  Set floating-point exception mode. Pass :const:`FP_EXC_SW_ENABLE` to use
  FPEXC for FP exception, :const:`FP_EXC_DIV` for floating-point divide by
  zero, :const:`FP_EXC_OVF` for floating-point overflow, :const:`FP_EXC_UND`
  for floating-point underflow, :const:`FP_EXC_RES` for floating-point inexact
  result, :const:`FP_EXC_INV` for floating-point invalid operation,
  :const:`FP_EXC_DISABLED` for FP exceptions disabled, :const:`FP_EXC_NONRECOV`
  for async non-recoverable exception mode, :const:`FP_EXC_ASYNC` for async
  recoverable exception mode, :const:`FP_EXC_PRECISE` for precise exception
  mode. Modes can be combined with the :const:`|` operator.

  .. note::

    This function only works on PowerPC systems. An :exc:`OSError` is raised
    when called on other systems.

.. function:: get_fpexc()

  Return the floating-point exception mode as a bitmap of enabled modes. See
  :func:`set_fpexc`.

.. function:: set_io_flusher(is_flusher)

  Put the process in :const:`IO_FLUSHER` state, which, which allows it special
  treatment to make progress when allocating memory. This is used by process
  involved in the block layer or filesystem i/o path, such as fuse daemons or
  scsi device emulation daemons.

  This is only available in linux 5.6 and newer

.. function:: get_io_flusher()

  Return the :const:`IO_FLUSHER` state of the process.

  This is only available in linux 5.6 and newer

.. function:: set_keepcaps(flag)

  Set the state of the thread's "keep capabilities" flag, which determines
  whether the thread's effective and permitted capability sets are cleared
  when a change is made to the thread's user IDs such that the thread's real
  UID, effective UID, and saved set-user-ID all become non-zero when at least
  one of them previously had the value 0. (By default, these credential sets
  are cleared). This value will be reset to :const:`False` on subsequent calls
  to :func:`execve`.


.. function:: get_keepcaps()

  Return the current state of the calling thread's "keep capabilities" flag.

.. function:: set_mce_kill(policy)

  Set the machine check memory corruption kill policy for the current thread.
  The policy can be early kill (:const:`MCE_KILL_EARLY`), late kill
  (:const:`MCE_KILL_LATE`), or the system-wide default
  (:const:`MCE_KILL_DEFAULT`).  Early kill means that the task receives a
  :const:`SIGBUS` signal as soon as hardware memory corruption is detected
  inside its address space. In late kill mode, the process is only killed when
  it accesses a corrupted page.  The policy is inherited by children.  use the
  system-wide default. The system-wide default is defined by
  :file:`/proc/sys/vm/memory_failure_early_kill`

  This is only available in linux 2.6.32 and newer

.. function:: get_mce_kill()

  Return the current per-process machine check kill policy.

  This is only available in linux 2.6.32 and newer

.. function:: pr_mpx_enable_management()

.. function:: pr_mpx_disable_management()

  Enable or disable intel memory protection extensions. See :manpage:`prctl(2)`
  for details and limitations.

  This is only available in linux 3.19 and newer, but no longer available in
  linux 5.4 and newer.

.. function:: set_name(name)

  Set the process name for the calling process, the name can be up to 16 bytes
  long. This name is displayed in the output of :command:`ps` and
  :command:`top`. The initial value is the name of the executable. For python
  applications this will likely be :command:`python`.

  .. note::
    Use :func:`set_proctitle` to set the name that's shown with :func:`ps aux`
    and :func:`top -c`

.. function:: get_name()

  Return the (first 16 bytes of) the name for the calling process.

.. function:: set_no_new_privs()

  Once this is set, no operation that can grant new privileges (such as
  execve'ing a setuid binary) will actually grant new privileges.

  This is only available in linux 3.5 and newer

.. function:: get_no_new_privs()

  Get whether new privileges can be granted to this pid.

  This is only available in linux 3.5 and newer

.. function:: pac_reset_keys(keys)

  Securely reset the thread's pointer authentication keys to fresh random
  values generated by the kernel. The keys must be a logical or of any of the
  keys you want to reset, or 0 to reset all keys. The available keys are
  :const:`PR_PAC_APIAKEY`, :const:`PR_PAC_APIBKEY`, :const:`PR_PAC_APDAKEY`,
  :const:`PR_PAC_APDBKEY` and :const:`PR_PAC_APGAKEY`.

  For more information, see the kernel source file
  Documentation/arm64/pointer-authentication.rst

  This is only available in linux 5.0 and newer

  .. note::
    This function only works on arm64 systems. An :exc:`OSError` is raised
    when called on other systems.

.. function:: set_proctitle(title)

  Set the process name for the calling process by overwriting the C-level
  :c:data:`**argv` variable. The original value of :c:data:`**argv` is then no
  longer visible. in :command:`ps`, :command:`proc`, or
  :file:`/proc/self/cmdline`.

  Names longer that what fits in :c:data:`**argv` will be silently truncated. To
  set a longer title, make your application accept bogus arguments and call the
  application with these arguments.

  .. note::

    This function is not actually part of the standard :func:`pctrl` syscall,
    but was added because it nicely complements :func:`set_name`.

.. function:: set_pdeathsig(signal)

  Set the parent death signal of the calling process (either a valid signal
  value from the :mod:`signal` module, or 0 to clear). This is the signal that
  the calling process will get when its parent dies. This value is cleared for
  the child of a :func:`fork`.

  .. warning::

    The "parent" in this case is considered to be the thread that created
    this process. In other words, the signal will be sent when that
    thread terminates (via, for example, :func:`pthread_exit()`), rather than after all
    of the threads in the parent process terminate.

.. function:: get_pdeathsig()

  Return the current value of the parent process death signal. See
  :func:`set_pdeathsig`.

.. function:: set_ptracer(pid)

  Sets the top of the process tree that is allowed to use :func:`PTRACE` on the
  calling process, assuming other requirements are met (matching uid, wasn't
  setuid, etc). Use pid 0 to disallow all processes. For more details, see
  :file:`/etc/sysctl.d/10-ptrace.conf`.

  This is only available in linux 3.4 and newer

.. function:: get_ptracer(pid)

  Returns the top of the process tree that is allowed to use :func:`PTRACE` on
  the calling process. See :func:`set_ptracer`.

  This is only available in linux 3.4 and newer

.. function:: set_seccomp(mode)

  Set the secure computing mode for the calling thread. In the current
  implementation, mode must be :const:`True`. After the secure computing mode
  has been set to :const:`True`, the only system calls that the thread is
  permitted to make are :func:`read`, :func:`write`, :func:`_exit`, and
  :func:`sigreturn`. Other system calls result in the delivery of a
  :const:`~signal.SIGKILL` signal. Secure computing mode is useful for
  number-crunching applications that may need to execute untrusted byte code,
  perhaps obtained by reading from a pipe or socket. This operation is only
  available if the kernel is configured with :const:`CONFIG_SECCOMP` enabled.

.. function:: get_seccomp()

  Return the secure computing mode of the calling thread. Not very useful for
  the current implementation, but may be useful for other possible future
  modes: if the caller is not in secure computing mode, this operation returns
  False; if the caller is in secure computing mode, then the :func:`prctl` call
  will cause a :const:`~signal.SIGKILL` signal to be sent to the process. This
  operation is only available if the kernel is configured with
  :const:`CONFIG_SECCOMP` enabled.

.. function:: set_speculation_ctrl(feature, value)

  Sets the state of a speculation misfeature (:const:`SPEC_STORE_BYPASS` or
  :const:`SPEC_INDIRECT_BRANCH`). The value is one of :const:`PR_SPEC_ENABLE`
  to enable the feature, :const:`PR_SPEC_DISABLE` to disable it,
  :const:`PR_SPEC_FORCE_DISABLE` to disable it permanently for the thread and
  :const:`PR_SPEC_DISABLE_NOEXEC` to disable it until the next :func:`execve`.

  This is only available in linux 4.17 and newer

.. function:: get_speculation_ctrl(feature)

  Returns the state of a speculation misfeature (:const:`SPEC_STORE_BYPASS` or
  :const:`SPEC_INDIRECT_BRANCH`). The value is one of the values that can be
  set by :func:`pr_set_speculation_ctrl`, possibly logically OR'ed with
  const:`PR_SPEC_PRCTL` to indicate that the value can be controlled er thread
  by that function. If all bits are 0, the CPU is not affected by the
  misfeature.

  This is only available in linux 4.17 and newer

.. function:: task_perf_events_disable()
.. function:: task_perf_events_enable()

  Disable or enable all performance counters attached to the calling process,
  regardless of whether the counters were created by this process or another
  process. Performance counters created by the calling process for other
  processes are unaffected. 

.. function:: set_thp_disable(is_disabled)

  Disable transparent huge ages for the current process. This flag is inhereted
  by child process and preserved across execve.

  This is only available in linux 3.15 and newer

.. function:: get_thp_disable()
 
  Return whether transparent huge pages are disabled for the current process.

  This is only available in linux 3.15 and newer

.. function:: get_tid_address()

  Allows the process to obtain its own `clear_tid_address`, used when
  checkpointing/restoring processes.

  This is only available in linux 3.5 and newer

.. function:: set_timerslack()

  Control the default "rounding" in nanoseconds that is used by :func:`select`,
  :func:`poll` and friends.

  The default value of the slack is 50 microseconds; this is significantly less
  than the kernels average timing error but still allows the kernel to group
  timers somewhat to preserve power behavior.

  This is only available in linux 2.6.28 and newer

.. function:: get_timerslack(value)

  Return the current timing slack, see :func:`get_timing_slack`

  This is only available in linux 2.6.28 and newer

.. function:: set_timing(flag)

  Set whether to use (normal, traditional) statistical process timing or
  accurate timestamp based process timing, by passing
  :const:`~prctl.TIMING_STATISTICAL` or :const:`~prctl.PR_TIMING_TIMESTAMP`.
  :const:`~prctl.TIMING_TIMESTAMP` is not currently implemented (attempting to
  set this mode will cause an :exc:`OSError`).

.. function:: get_timing()

   Return which process timing method is currently in use.

.. function:: set_tsc(flag)

  Set the state of the flag determining whether the timestamp counter can be
  read by the process. Pass :const:`~prctl.TSC_ENABLE` to allow it to be read,
  or :const:`~prctl.TSC_SIGSEGV` to generate a :const:`SIGSEGV` when the
  process tries to read the timestamp counter.

  .. note::

    This function only works on x86 systems. An :exc:`OSError` is raised when
    called on other systems.

.. function:: get_tsc()

  Return the state of the flag determining whether the timestamp counter can be
  read, see :func:`set_tsc`.

.. function:: set_unalign(flag)

  Set unaligned access control flag. Pass :const:`~prctl.UNALIGN_NOPRINT` to
  silently fix up unaligned user accesses, or :const:`~prctl.UNALIGN_SIGBUS` to
  generate :const:`SIGBUS` on unaligned user access.

  .. note::

    This function only works on ia64, parisc, PowerPC and Alpha systems. An
    :exc:`OSError` is raised when called on other systems.

.. function:: get_unalign

  Return unaligned access control bits, see :func:`set_unalign`.

.. function:: set_securebits(bitmap)

  Set the "securebits" flags of the calling thread.

  .. note::

    It is not recommended to use this function directly, use the
    :attr:`~prctl.securebits` object instead.

.. function:: get_securebits()

  Get the "securebits" flags of the calling thread.

  .. note::

    As with :func:`set_securebits`, it is not recommended to use this function
    directly, use the :attr:`~prctl.securebits` object instead.

.. function:: capbset_read(capability)

  Return whether the specified capability is in the calling thread's capability
  bounding set. The capability bounding set dictates whether the process can
  receive the capability through a file's permitted capability set on a
  subsequent call to :func:`execve`. An :exc:`OSError` will be raised when an
  invalid capability is specified.

  .. note::

    It is not recommended to use this function directly, use the
    :attr:`~prctl.capbset` object instead.

.. function:: capbset_drop(capability)

  If the calling thread has the :const:`~prctl.CAP_SETPCAP` capability, then
  drop the specified capability specified by from  the  calling  thread's
  capability bounding set. Any children of the calling thread will inherit the
  newly reduced bounding set.

  An :exc:`OSError` will be raised if the calling thread does not have the
  :const:`~prctl.CAP_SETPCAP` capability or when the specified capability is
  invalid or when capabilities are not enabled in the kernel.

  .. note::

    As with :func:`capbset_read`, it is not recommended to use this function
    directly, use the :attr:`~prctl.capbset` object instead.

Capabilities and the capability bounding set
============================================

For the purpose of performing permission checks, traditional Unix
implementations distinguish two categories of processes: privileged processes
(whose effective user ID is 0, referred to as superuser or root), and
unprivileged processes (whose effective UID is non-zero). Privileged processes
bypass all kernel permission checks, while unprivileged processes are subject
to full permission checking based on the process's credentials (usually:
effective UID, effective GID, and supplementary group list).

Starting with kernel 2.2, Linux divides the privileges traditionally associated
with superuser into distinct units, known as capabilities, which can be
independently enabled and disabled. Capabilities are a per-thread attribute.

Each thread has three capability sets containing zero or  more  of  the
capabilities described below

Permitted (the :attr:`~prctl.cap_permitted` object):
  This is a limiting superset for the effective capabilities that the thread
  may assume. It is also a limiting superset for the capabilities that may be
  added to the inheritable set by a thread that does not have the
  :attr:`setpcap` capability in its effective set.

  If a thread drops a capability from its permitted set, it can never
  re-acquire that capability (unless it :func:`execve` s either a
  set-user-ID-root program, or a program whose associated file capabilities
  grant that capability).

Inheritable (the :attr:`~prctl.cap_inheritable` object):
  This is a set of capabilities preserved across an :func:`execve`. It provides
  a mechanism for a process to assign capabilities to the permitted set of the
  new program during an :func:`execve`.

Effective (the :attr:`~prctl.cap_effective` object):
  This is the set of capabilities used by the kernel to perform permission
  checks for the thread.

A child created via :func:`fork` inherits copies of its parent's capability
sets. See below for a discussion of the treatment of capabilities during
:func:`execve`.

The :attr:`~prctl.capbset` object represents the current capability bounding
set of the process. The capability bounding set dictates whether the process
can receive the capability through a file's permitted capability set on a
subsequent call to :func:`execve`. All attributes of :attr:`~prctl.capbset` are
:const:`True` by default, unless a parent process already removed them from the
bounding set.

These four objects have a number of attributes, all of which are properties.
For the capability bounding set and the effective capabilities, these can only
be set to :const:`False`, this drops them from the corresponding set.

All details about capabilities and capability bounding sets can be found in the
:manpage:`capabilities(7)` manpage, on which most text below is based.

These are the attributes (:class:`set` refers to each of the above objects):

.. attribute:: set.audit_control

  Enable and disable kernel auditing; change auditing filter rules; retrieve
  auditing status and filtering rules.

.. attribute:: set.audit_read

  Allow reading the audit log via a multicast netlink socket.

.. attribute:: set.audit_write

  Write records to kernel auditing log.

.. attribute:: set.block_suspend

  Employ features that can block system suspend (:manpage:`epoll(7)`
  :const:`EPOLLWAKEUP`, :file:`/proc/sys/wake_lock`).

.. attribute:: set.bpf

  Employ privileged BPF operations; see :manpage:`bpf(2)` and
  :manpage:`bpf-helpers(7)`.

.. attribute:: set.chown

  Make arbitrary changes to file UIDs and GIDs (see :manpage:`chown(2)`).

.. attribute:: set.dac_override

  Bypass file read, write, and execute permission checks.  (DAC is an
  abbreviation of "discretionary access control".)

.. attribute:: set.dac_read_search

  Bypass file read permission checks and directory read and execute permission
  checks.

.. attribute:: set.fowner

  * Bypass  permission  checks  on  operations  that  normally require the file
    system UID of the process to match the UID of the file (e.g.,
    :func:`chmod`, :func:`utime`), excluding those operations covered by
    :attr:`dac_override` and :attr:`dac_read_search`.
  * Set extended file attributes (see :manpage:`chattr(1)`) on arbitrary files.
  * Set Access Control Lists (ACLs) on arbitrary files.
  * Ignore directory sticky bit on file deletion.
  * Specify :const:`O_NOATIME` for arbitrary files in :func:`open` and
    :func:`fcntl`.

.. attribute:: set.fsetid

  Don't clear set-user-ID and set-group-ID permission bits when a file is
  modified; set the set-group-ID bit for a file whose  GID  does  not match the
  file system or any of the supplementary GIDs of the calling process.

.. attribute:: set.ipc_lock

  Lock memory (:func:`mlock`, :func:`mlockall`, :func:`mmap`, :func:`shmctl`).

.. attribute:: set.ipc_owner

  Bypass permission checks for operations on System V IPC objects.

.. attribute:: set.kill

  Bypass permission checks for sending signals (see :manpage:`kill(2)`). This
  includes use of the :func:`ioctl` :const:`KDSIGACCEPT` operation.

.. attribute:: set.lease

  Establish leases on arbitrary files (see :manpage:`fcntl(2)`).

.. attribute:: set.linux_immutable

  Set the :const:`FS_APPEND_FL` and :const:`FS_IMMUTABLE_FL` i-node flags (see
  :manpage:`chattr(1)`).

.. attribute:: set.mac_admin

  Allow MAC configuration or state changes. Implemented for the Smack LSM.

.. attribute:: set.mac_override

  Override Mandatory Access Control (MAC). Implemented for the Smack Linux
  Security Module (LSM).

.. attribute:: set.mknod

  Create special files using :func:`mknod`.

.. attribute:: set.net_admin

  Perform various network-related operations (e.g., setting privileged socket
  options, enabling multicasting, interface configuration, modifying routing
  tables).

.. attribute:: set.net_bind_service

  Bind a socket to Internet domain privileged ports (port numbers less than
  1024).

.. attribute:: set.net_broadcast

  (Unused) Make socket broadcasts, and listen to multicasts.

.. attribute:: set.net_raw

  Use :const:`RAW` and :const:`PACKET` sockets.

.. attribute:: set.perfmon

  Employ various performance-monitoring mechanisms, including
  :func:`perf_event_open` and various BPF operations that have performance
  implications..

.. attribute:: set.setgid

  Make arbitrary manipulations of process GIDs and supplementary GID list;
  forge GID when passing socket credentials via Unix domain sockets.

.. attribute:: set.setfcap

  Set file capabilities.

.. attribute:: set.setpcap

  If file capabilities are not supported: grant or remove any capability in the
  caller's permitted capability set to or from any other process. (This
  property of :attr:`setpcap` is not available when the kernel is configured to
  support file capabilities, since :attr:`setpcap` has entirely different
  semantics for such kernels.)

  If file capabilities are supported: add any capability from the calling
  thread's bounding set to its  inheritable  set;  drop  capabilities from the
  bounding set (via :func:`~prctl.capbset_drop`); make changes to the
  securebits flags.

.. attribute:: set.setuid

  Make arbitrary manipulations of process UIDs (:func:`setuid`,
  :func:`setreuid`, :func:`setresuid`, :func:`setfsuid`); make forged UID when
  passing socket credentials via Unix domain sockets.

.. attribute:: set.syslog

  Allow configuring the kernel's syslog (printk behaviour). Before linux 2.6.38
  the :attr:`sys_admin` capability was needed for this.

  This is only available in linux 2.6.38 and newer

.. attribute:: set.sys_admin

  Perform a range of system administration operations, which change per kernel
  version. See :manpage:`capabilities(7)` for details.

.. attribute:: set.sys_boot

  Use :func:`reboot` and :func:`kexec_load`.

.. attribute:: set.sys_chroot

  Use :func:`chroot`.

.. attribute:: set.sys_module

  Load and unload kernel modules (see :manpage:`init_module(2)` and
  :manpage:`delete_module(2)`).

.. attribute:: set.sys_nice

  * Raise process nice value (:func:`nice`, :func:`setpriority`) and change the
    nice value for arbitrary processes.
  * Set real-time scheduling policies for calling process, and set scheduling
    policies and priorities for arbitrary processes
    (:func:`sched_setscheduler`, :func:`sched_setparam`).
  * Set CPU affinity for arbitrary processes (:func:`sched_setaffinity`)
  * Set I/O scheduling class and priority for arbitrary processes
    (:func:`ioprio_set`).
  * Apply :func:`migrate_pages` to arbitrary processes and allow processes to
    be migrated to arbitrary nodes.
  * Apply :func:`move_pages` to arbitrary processes.
  * Use the :const:`MPOL_MF_MOVE_ALL` flag with :func:`mbind` and
    :func:`move_pages`.

.. attribute:: set.sys_pacct

  Use :func:`acct`.

.. attribute:: set.sys_ptrace

  Trace arbitrary processes using :func:`ptrace`.

.. attribute:: set.sys_rawio

  Perform a range of privileged i/o operations, which change per kernel
  version. See :manpage:`capabilities(7)` for details.

.. attribute:: set.sys_resource

  Use a set of privileged resources, which change per kernel version. See
  :manpage:`capabilities(7)` for details.

.. attribute:: set.sys_time

  Set system clock (:func:`settimeofday`, :func:`stime`, :func:`adjtimex`); set
  real-time (hardware) clock.

.. attribute:: set.sys_tty_config

  Use :func:`vhangup`.

.. attribute:: set.wake_alarm

  Allow triggering something that will wake the system.

  This is only available in linux 3.0 and newer

The four capabilities objects also have two additional methods, to make
dropping many capabilities at the same time easier:

.. function:: set.drop(cap [, ...])

  Drop all capabilities given as arguments from the set.

.. function:: set.limit(cap [, ...])

  Drop all but the given capabilities from the set.

These function accept both names of capabilities as given above and the
:data:`CAP_` constants as defined in :file:`capabilities.h`. These constants
are available as :attr:`prctl.CAP_SYS_ADMIN` et cetera.

Capabilities and :func:`execve`
===============================
During an :func:`execve`, the kernel calculates the new capabilities of the process
using the following algorithm:

* P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & cap_bset)
* P'(effective) = F(effective) ? P'(permitted) : 0
* P'(inheritable) = P(inheritable) [i.e., unchanged]

Where:

* P denotes the value of a thread capability set before the :func:`execve`
* P' denotes the value of a capability set after the :func:`execve`
* F denotes a file capability set
* cap_bset is the value of the capability bounding set

The downside of this is that you need to set file capabilities if you want to
make applications capabilities-friendly via wrappers. For instance, to allow an
http daemon to listen on port 80 without it needing root privileges, you could
do the following:

.. code-block:: python

  prctl.cap_inheritable.net_bind_service = True
  os.setuid(pwd.getpwnam('www-data').pw_uid)
  os.execve("/usr/sbin/httpd", ["/usr/sbin/httpd"], os.environ)

This only works if :file:`/usr/sbin/httpd` has :attr:`CAP_NET_BIND_SOCK` in its
inheritable and effective sets. You can do this with the :command:`setcap` tool
shipped with libcap.

.. code-block:: sh

  $ sudo setcap cap_net_bind_service=ie /usr/sbin/httpd
  $ getcap /usr/sbin/httpd
  /usr/sbin/httpd = cap_net_bind_service+ei

Note that it only sets the capability in the inheritable set, so this
capability is only granted if the program calling execve has it in its
inheritable set too. The effective set of file capabilities does not exist in
linux, it is a single bit that specifies whether capabilities in the permitted
set are automatically raised in the effective set upon :func:`execve`.

Establishing a capabilities-only environment with securebits
============================================================
With a kernel in which file capabilities are enabled, Linux implements a set of
per-thread securebits flags that can be used to disable special handling of
capabilities for UID 0 (root). The securebits flags are inherited by child
processes. During an :func:`execve`, all of the flags are preserved, except
:attr:`keep_caps` which is always cleared.

These capabilities are available via :func:`get_securebits`, but are easier
accessed via the :attr:`~prctl.securebits` object. This object has attributes
tell you whether specific securebits are set, or unset.

The following attributes are available:

.. attribute:: securebits.keep_caps

  Setting this flag allows a thread that has one or more 0 UIDs to retain its
  capabilities when it switches all of its UIDs to a non-zero value.  If this
  flag is not set, then such a UID switch causes the thread to lose all
  capabilities. This flag is always cleared on an :func:`execve`.

.. attribute:: securebits.no_setuid_fixup

  Setting this flag stops the kernel from adjusting capability sets when the
  thread's effective and file system UIDs are switched between zero and
  non-zero values. (See the subsection Effect of User ID Changes on
  Capabilities in :manpage:`capabilities(7)`)

.. attribute:: securebits.noroot

  If this bit is set, then the kernel does not grant capabilities when a
  set-user-ID-root program is executed, or when a process with an effective or
  real UID of 0 calls :func:`execve`. (See the subsection Capabilities and
  execution of programs by root in :manpage:`capabilities(7)`)

.. attribute:: securebits.keep_caps_locked

  Like :attr:`keep_caps`, but irreversible

.. attribute:: securebits.no_setuid_fixup_locked

  Like :attr:`no_setuid_fixup`, but irreversible

.. attribute:: securebits.noroot_locked

  Like :attr:`noroot`, but irreversible

:mod:`_prctl` -- Basic C wrapper around prctl
=============================================
.. module:: _prctl
   :platform: Linux (2.6.25 or newer)
   :synopsis: Basic wrapper around prctl
.. moduleauthor:: Dennis Kaarsemaker <dennis@kaarsemaker.net>

This is the lower level C module that wraps the :c:func:`prctl` syscall in a way
that it is easy to call from a python module. It should not be used directly,
applications and other libraries should use the functionality provided by the
:mod:`prctl` module.

This section of the documentation is meant for people who want to contribute to
python-prctl.

.. c:function:: static PyObject\* prctl_prctl(PyObject \*self, PyObject \*args)

  This is the :c:func:`prctl` wrapper. It accepts as argument either one or two
  :obj:`int` variables or an :obj:`int` and a :obj:`str`.

  The mandatory first int must be one of the :const:`PR_SET_*`,
  :const:`PR_GET_*`, or :const:`PR_CAPBSET_*` constants defined in
  :file:`sys/prctl.h`. The accepted values of the second argument depend on the
  first argument, see :manpage:`prctl(2)`.

  The function validates arguments, calls :c:func:`prctl` in the
  argument-specific way and returns the proper value, whether :func:`prctl`
  returns it as return value or stores it in one of the parameters.

.. c:function:: static PyObject\* prctl_set_proctitle(PyObject \*self, PyObject \*args)

  Set the process title by mangling :data:`**argv`. Mandatory argument is a
  :obj:`str`.

.. c:function:: PyMODINIT_FUNC init_prctl(void)

  Create the module instance and add all the relevant constants to the module.
  That means all :const:`PR_*`, :const:`CAP_*` and :const:`SECBIT_*` constants
  mentioned in :manpage:`prctl(2)` and :manpage:`capabilities(7)`. To avoid
  repeating yourself all the time, use the :c:macro:`namedconstant` and
  :c:macro:`namedattribute` macros when adding new values.

.. toctree::
   :maxdepth: 2
