/*
 * python-pctrl -- python interface to the prctl function
 * (c)2010 Dennis Kaarsemaker <dennis@kaarsemaker.net
 * See COPYING for licensing details
 */

#include <Python.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <sys/prctl.h>
#include <sys/signal.h>

void Py_GetArgcArgv(int*, char***);

static PyObject *
prctl_prctl(PyObject *self, PyObject *args)
{
    long option = 0;
    long arg = 0;
    char *argstr = NULL;
    char name[17] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    int result;

    if(!PyArg_ParseTuple(args, "l|l", &option, &arg)) {
        if(!PyArg_ParseTuple(args, "ls", &option, &argstr)) {
            return NULL;
        }
        if(option != PR_SET_NAME) {
            PyErr_SetString(PyExc_TypeError, "an integer is required");
            return NULL;
        }
        PyErr_Clear();
    }
    else {
        if(option == PR_SET_NAME) {
            PyErr_SetString(PyExc_TypeError, "a string is required");
            return NULL;
        }
    }

    /* Validation */
    switch(option) {
        case(PR_CAPBSET_READ):
        case(PR_CAPBSET_DROP):
            if(!cap_valid(arg)) {
                PyErr_SetString(PyExc_ValueError, "Unknown capability");
                return NULL;
            }
            break;
        case(PR_SET_DUMPABLE):
        case(PR_SET_KEEPCAPS):
            /* Only 0 and 1 are allowed */
            arg = arg ? 1 : 0;
            break;
        case(PR_SET_ENDIAN):
            if(arg != PR_ENDIAN_LITTLE && arg != PR_ENDIAN_BIG && arg != PR_ENDIAN_PPC_LITTLE) {
                PyErr_SetString(PyExc_ValueError, "Unknown endianness");
                return NULL;
            }
            break;
        case(PR_SET_FPEMU):
            if(arg != PR_FPEMU_NOPRINT && arg != PR_FPEMU_SIGFPE) {
                PyErr_SetString(PyExc_ValueError, "Unknown floating-point emulation setting");
                return NULL;
            }
            break;
        case(PR_SET_FPEXC):
            if(arg & ~(PR_FP_EXC_SW_ENABLE | PR_FP_EXC_DIV | PR_FP_EXC_OVF |
                       PR_FP_EXC_UND | PR_FP_EXC_RES | PR_FP_EXC_INV | 
                       PR_FP_EXC_DISABLED | PR_FP_EXC_NONRECOV | 
                       PR_FP_EXC_ASYNC | PR_FP_EXC_PRECISE)) {
                PyErr_SetString(PyExc_ValueError, "Unknown floating-point exception mode");
                return NULL;
            }
            break;
        case(PR_SET_NAME):
            if(strlen(argstr) > 16) {
                /* FIXME: warn */

            }
            strncpy(name, argstr, 16);
            break;
        case(PR_SET_PDEATHSIG):
            if(arg < 0 || arg > SIGRTMAX) {
                PyErr_SetString(PyExc_ValueError, "Unknown signal");
                return NULL;
            }
            break;
        case(PR_SET_SECCOMP):
            if(!arg) {
                PyErr_SetString(PyExc_ValueError, "Argument must be 1");
                return NULL;
            }
            arg = 1;
            break;
        case(PR_SET_SECUREBITS):
            if(arg & ~ ((1 << SECURE_NOROOT) | (1 << SECURE_NOROOT_LOCKED) | 
                        (1 << SECURE_NO_SETUID_FIXUP) | (1 << SECURE_NO_SETUID_FIXUP_LOCKED) |
                        (1 << SECURE_KEEP_CAPS) | (1 << SECURE_KEEP_CAPS_LOCKED))) {
                PyErr_SetString(PyExc_ValueError, "Invalid securebits set");
                return NULL;
            }
            break;
        case(PR_SET_TIMING):
            if(arg != PR_TIMING_STATISTICAL && arg != PR_TIMING_TIMESTAMP) {
                PyErr_SetString(PyExc_ValueError, "Invalid timing constant");
                return NULL;
            }
            break;
        case(PR_SET_TSC):
            if(arg != PR_TSC_ENABLE && arg != PR_TSC_SIGSEGV) {
                PyErr_SetString(PyExc_ValueError, "Invalid TSC setting");
                return NULL;
            }
            break;
        case(PR_SET_UNALIGN):
            if(arg != PR_UNALIGN_NOPRINT && arg != PR_UNALIGN_SIGBUS) {
                PyErr_SetString(PyExc_ValueError, "Invalid TSC setting");
                return NULL;
            }
            break;
    }
    /* Calling prctl */
    switch(option) {
        case(PR_CAPBSET_READ):
        case(PR_CAPBSET_DROP):
        case(PR_SET_DUMPABLE):
        case(PR_GET_DUMPABLE):
        case(PR_SET_ENDIAN):
        case(PR_SET_FPEMU):
        case(PR_SET_FPEXC):
        case(PR_SET_KEEPCAPS):
        case(PR_GET_KEEPCAPS):
        case(PR_SET_PDEATHSIG):
        case(PR_SET_SECCOMP):
        case(PR_GET_SECCOMP):
        case(PR_SET_SECUREBITS):
        case(PR_GET_SECUREBITS):
        case(PR_SET_TIMING):
        case(PR_GET_TIMING):
        case(PR_SET_TSC):
        case(PR_SET_UNALIGN):
            result = prctl(option, arg, 0, 0, 0);
            if(result < 0) {
                PyErr_SetFromErrno(PyExc_OSError);
                return NULL;
            }
            switch(option) {
                case(PR_CAPBSET_READ):
                case(PR_GET_DUMPABLE):
                case(PR_GET_KEEPCAPS):
                case(PR_GET_SECCOMP):
                case(PR_GET_TIMING):
                    return PyBool_FromLong(result);
                case(PR_GET_SECUREBITS):
                    return PyInt_FromLong(result);
            }
            break;
        case(PR_GET_ENDIAN):
        case(PR_GET_FPEMU):
        case(PR_GET_FPEXC):
        case(PR_GET_PDEATHSIG):
        case(PR_GET_TSC):
        case(PR_GET_UNALIGN):
            result = prctl(option, &arg, 0, 0, 0);
            if(result < 0) {
                PyErr_SetFromErrno(PyExc_OSError);
                return NULL;
            }
            return PyInt_FromLong(arg);
        case(PR_SET_NAME):
        case(PR_GET_NAME):
            result = prctl(option, name, 0, 0, 0);
            if(result < 0) {
                PyErr_SetFromErrno(PyExc_OSError);
                return NULL;
            }
            if(option == PR_GET_NAME) {
                return PyString_FromString(name);
            }
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "Unkown prctl option");
            return NULL;
    }

    /* None is returned by default */
    Py_RETURN_NONE;
}
static PyObject *
prctl_set_proctitle(PyObject *self, PyObject *args)
{
    int argc;
    char **argv;
    int len;
    char *title;
    if(!PyArg_ParseTuple(args, "s", &title)) {
        return NULL;
    }
    Py_GetArgcArgv(&argc, &argv);
    /* Determine up to where we can write */
    len = (int)(argv[argc-1]) + strlen(argv[argc-1]) - (int)(argv[0]);
    strncpy(argv[0], title, len);
    memset(argv[0] + strlen(title), 0, len);
    Py_RETURN_NONE;
}
/* TODO: Add a getter? */

static PyMethodDef PrctlMethods[] = {
    {"prctl", prctl_prctl, METH_VARARGS, "Call prctl"},
    {"set_proctitle", prctl_set_proctitle, METH_VARARGS, "Set the process title"},
    {NULL, NULL, 0, NULL} /* Sentinel */
};

#define namedconstant(x) PyModule_AddIntConstant(_prctl, #x, x)
#define namedattribute(x) do{ \
    PyModule_AddIntConstant(_prctl, "PR_GET_" #x,  PR_GET_ ## x); \
    PyModule_AddIntConstant(_prctl, "PR_SET_" #x,  PR_SET_ ## x); \
} while(0)

PyMODINIT_FUNC
init_prctl(void)
{
    PyObject *_prctl = Py_InitModule("_prctl", PrctlMethods);
    /* Add the PR_* constants */
    namedconstant(PR_CAPBSET_READ);
    namedconstant(PR_CAPBSET_DROP);
    namedattribute(DUMPABLE);
    namedattribute(ENDIAN);
    namedconstant(PR_ENDIAN_BIG);
    namedconstant(PR_ENDIAN_LITTLE);
    namedconstant(PR_ENDIAN_PPC_LITTLE);
    namedattribute(FPEMU);
    namedconstant(PR_FPEMU_NOPRINT);
    namedconstant(PR_FPEMU_SIGFPE);
    namedattribute(FPEXC);
    namedconstant(PR_FP_EXC_SW_ENABLE);
    namedconstant(PR_FP_EXC_DIV);
    namedconstant(PR_FP_EXC_OVF);
    namedconstant(PR_FP_EXC_UND);
    namedconstant(PR_FP_EXC_RES);
    namedconstant(PR_FP_EXC_INV);
    namedconstant(PR_FP_EXC_DISABLED);
    namedconstant(PR_FP_EXC_NONRECOV);
    namedconstant(PR_FP_EXC_ASYNC);
    namedconstant(PR_FP_EXC_PRECISE);
    namedattribute(KEEPCAPS);
    namedattribute(NAME);
    namedattribute(PDEATHSIG);
    namedattribute(SECCOMP);
    namedattribute(SECUREBITS);
    namedattribute(TIMING);
    namedconstant(PR_TIMING_STATISTICAL);
    namedconstant(PR_TIMING_TIMESTAMP);
    namedattribute(TSC);
    namedconstant(PR_TSC_ENABLE);
    namedconstant(PR_TSC_SIGSEGV);
    namedattribute(UNALIGN);
    namedconstant(PR_UNALIGN_NOPRINT);
    namedconstant(PR_UNALIGN_SIGBUS);
    /* Add the CAP_* constants too */
    namedconstant(CAP_CHOWN);
    namedconstant(CAP_DAC_OVERRIDE);
    namedconstant(CAP_DAC_READ_SEARCH);
    namedconstant(CAP_FOWNER);
    namedconstant(CAP_FSETID);
    namedconstant(CAP_KILL);
    namedconstant(CAP_SETGID);
    namedconstant(CAP_SETUID);
    namedconstant(CAP_SETPCAP);
    namedconstant(CAP_LINUX_IMMUTABLE);
    namedconstant(CAP_NET_BIND_SERVICE);
    namedconstant(CAP_NET_BROADCAST);
    namedconstant(CAP_NET_ADMIN);
    namedconstant(CAP_NET_RAW);
    namedconstant(CAP_IPC_LOCK);
    namedconstant(CAP_IPC_OWNER);
    namedconstant(CAP_SYS_MODULE);
    namedconstant(CAP_SYS_RAWIO);
    namedconstant(CAP_SYS_CHROOT);
    namedconstant(CAP_SYS_PTRACE);
    namedconstant(CAP_SYS_PACCT);
    namedconstant(CAP_SYS_ADMIN);
    namedconstant(CAP_SYS_BOOT);
    namedconstant(CAP_SYS_NICE);
    namedconstant(CAP_SYS_RESOURCE);
    namedconstant(CAP_SYS_TIME);
    namedconstant(CAP_SYS_TTY_CONFIG);
    namedconstant(CAP_MKNOD);
    namedconstant(CAP_LEASE);
    namedconstant(CAP_AUDIT_WRITE);
    namedconstant(CAP_AUDIT_CONTROL);
    namedconstant(CAP_SETFCAP);
    namedconstant(CAP_MAC_OVERRIDE);
    namedconstant(CAP_MAC_ADMIN);
    /* And the securebits constants */
    namedconstant(SECURE_KEEP_CAPS);
    namedconstant(SECURE_NO_SETUID_FIXUP);
    namedconstant(SECURE_NOROOT);
    namedconstant(SECURE_KEEP_CAPS_LOCKED);
    namedconstant(SECURE_NO_SETUID_FIXUP_LOCKED);
    namedconstant(SECURE_NOROOT_LOCKED);
}
