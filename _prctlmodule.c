/*
 * python-pctrl -- python interface to the prctl function
 * (c)2010 Dennis Kaarsemaker <dennis@kaarsemaker.net
 * See COPYING for licensing details
 */

#include <Python.h>
#if PY_MAJOR_VERSION >= 3
#define PyInt_FromLong PyLong_FromLong
#define PyInt_Check PyLong_Check
#define PyInt_AsLong PyLong_AsLong
#endif
#include "securebits.h"
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/signal.h>

/* New in 2.6.32, but named and implemented inconsistently. The linux
 * implementation has two ways of setting the policy to the default, and thus
 * needs an extra argument. We ignore the first argument and always call
 * PR_MCE_KILL_SET. This makes our implementation simpler and keeps the prctl
 * interface more consistent
 */
#ifdef PR_MCE_KILL
#define PR_GET_MCE_KILL PR_MCE_KILL_GET
#define PR_SET_MCE_KILL PR_MCE_KILL
#endif

/* New in 2.6.XX (Ubuntu 10.10) */
#define NOT_SET (-1)
#ifdef PR_SET_PTRACER
/* This one has no getter for some reason, but guard agains that being fixed  */
#ifndef PR_GET_PTRACER
#define PR_GET_PTRACER NOT_SET
/* Icky global variable to cache ptracer */
static int __cached_ptracer = NOT_SET;
#endif
#endif

/* This function is not in Python.h, so define it here */
#if PY_MAJOR_VERSION < 3
void Py_GetArgcArgv(int*, char***);
#else
void Py_GetArgcArgv(int*, wchar_t***);
#endif

/* The prctl wrapper */
static PyObject *
prctl_prctl(PyObject *self, PyObject *args)
{
    long option = 0;
    long arg = 0;
    char *argstr = NULL;
    char name[17] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    int result;

    /* 
     * Accept single int, two ints and int+string. That covers all current
     * prctl possibilities. int+string is required for (and only accepted for)
     * PR_SET_NAME
     */
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

    /* Validate the optional arguments */
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
#ifdef PR_MCE_KILL
        case(PR_SET_MCE_KILL):
            if(arg != PR_MCE_KILL_DEFAULT && arg != PR_MCE_KILL_EARLY && arg != PR_MCE_KILL_LATE) {
                PyErr_SetString(PyExc_ValueError, "Unknown memory corruption kill policy");
                return NULL;
            }
            break;
#endif
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
    /*
     * Calling prctl 
     * There are 3 basic call modes:
     * - Setters and getters for which the return value is the result
     * - Getters for which the result is placed in arg2
     * - Getters and setters that deal with strings.
     *
     * This function takes care of all that and always returns Py_None for
     * settings or the result of a getter call as a PyInt or PyString.
     */
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
#ifdef PR_MCE_KILL
        case(PR_GET_MCE_KILL):
#endif
        case(PR_SET_PDEATHSIG):
#if defined(PR_GET_PTRACER) && (PR_GET_PTRACER != NOT_SET)
        case(PR_GET_PTRACER):
#endif
#ifdef PR_SET_PTRACER
        case(PR_SET_PTRACER):
#endif
        case(PR_SET_SECCOMP):
        case(PR_GET_SECCOMP):
        case(PR_SET_SECUREBITS):
        case(PR_GET_SECUREBITS):
#ifdef PR_GET_TIMERSLACK
        case(PR_GET_TIMERSLACK):
        case(PR_SET_TIMERSLACK):
#endif
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
#ifdef PR_MCE_KILL
                case(PR_GET_MCE_KILL):
#endif
#if defined(PR_GET_PTRACER) && (PR_GET_PTRACER != NOT_SET)
                case(PR_GET_PTRACER):
#endif
                case(PR_GET_SECUREBITS):
#ifdef PR_GET_TIMERSLACK
                case(PR_GET_TIMERSLACK):
#endif
                    return PyInt_FromLong(result);
#if defined(PR_GET_PTRACER) && (PR_GET_PTRACER == NOT_SET)
                case(PR_SET_PTRACER):
                    __cached_ptracer = arg;
                    break;
#endif
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
                return Py_BuildValue("s", name);
            }
            break;
#if defined(PR_GET_PTRACER) && (PR_GET_PTRACER == NOT_SET)
        case(PR_GET_PTRACER):
            if(__cached_ptracer == NOT_SET)
                return PyInt_FromLong(getppid());
            return PyInt_FromLong(__cached_ptracer);
#endif
#ifdef PR_MCE_KILL
        case(PR_SET_MCE_KILL):
            result = prctl(option, PR_MCE_KILL_SET, arg, 0, 0);
            if(result < 0) {
                PyErr_SetFromErrno(PyExc_OSError);
                return NULL;
            }
            break;
#endif
        default:
            PyErr_SetString(PyExc_ValueError, "Unkown prctl option");
            return NULL;
    }

    /* None is returned by default */
    Py_RETURN_NONE;
}

/* While not part of prctl, this complements PR_SET_NAME */
static int __real_argc = -1;
static char **__real_argv = NULL;
#if PY_MAJOR_VERSION < 3
#define _Py_GetArgcArgv Py_GetArgcArgv
#else
/* In python 3, Py_GetArgcArgv doesn't actually return the real argv, but an
 * encoded copy of it. We try to find the real one by going back from the start
 * of environ.
 */
static char * encode(wchar_t *wstr) {
    PyObject *unicodestr = NULL, *bytesstr = NULL;
    char *str = NULL;

    unicodestr = PyUnicode_FromWideChar(wstr, -1);
    if(!unicodestr) {
        PyErr_Clear();
        return NULL;
    }

    bytesstr =  PyUnicode_AsEncodedString(unicodestr, PyUnicode_GetDefaultEncoding(), "strict");
    if(!bytesstr) {
        PyErr_Clear();
        Py_XDECREF(unicodestr);
        return NULL;
    }

    str = PyBytes_AsString(bytesstr);
    Py_XDECREF(unicodestr);
    Py_XDECREF(bytesstr);
    return str;
}

static int _Py_GetArgcArgv(int* argc, char ***argv) {
    int i = 0;
    wchar_t **argv_w;
    char **buf = NULL , *arg0 = NULL, *ptr = 0, *limit = NULL;

    Py_GetArgcArgv(argc, &argv_w);

    buf = (char **)malloc((*argc + 1) * sizeof(char *));
    buf[*argc] = NULL;

    /* Walk back from environ until you find argc-1 null-terminated strings. */
    ptr = environ[0] - 1;
    limit = ptr - 8192;
    for(i=*argc-1; i >= 1; --i) {
        ptr--;
        while (*ptr && ptr-- > limit);
        if (ptr <= limit) {
            free(buf);
            return 0;
        }
        buf[i] = (ptr + 1);
    }

    /* Now try to find argv[0] */
    arg0 = encode(argv_w[0]);
    if(!arg0) {
        free(buf);
        return 0;
    }
    ptr -= strlen(arg0);
    if(strcmp(ptr, arg0)) {
        free(buf);
        return 0;
    }

    buf[0] = ptr;
    *argv = buf;
    return 1;
}
#endif

static PyObject *
prctl_set_proctitle(PyObject *self, PyObject *args)
{
    int argc = 0;
    char **argv;
    int len;
    char *title;
    if(!PyArg_ParseTuple(args, "s", &title)) {
        return NULL;
    }
    if(__real_argc > 0)  {
        argc = __real_argc;
        argv = __real_argv;
    }
    else {
        _Py_GetArgcArgv(&argc, &argv);
        __real_argc = argc;
        __real_argv = argv;
    }

    if(argc <= 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to locate argc/argv");
        return NULL;
    }
    /* Determine up to where we can write */
    len = (int)(argv[argc-1]) + strlen(argv[argc-1]) - (int)(argv[0]);
    strncpy(argv[0], title, len);
    memset(argv[0] + strlen(title), 0, len);
    Py_RETURN_NONE;
}

/* TODO: Add a getter? */

static PyObject * prctl_get_caps_flag(PyObject *list, cap_t caps, int flag) {
    int i;
    PyObject *ret, *item, *val;
    cap_flag_value_t value;

    if(list && !PySequence_Check(list)) {
        PyErr_SetString(PyExc_TypeError, "A sequence of integers is required");
        return NULL;
    }
    ret = PyDict_New();
    if(!list)
        return ret;
    for(i=0; i < PyList_Size(list); i++) {
        item = PyList_GetItem(list, i);
        if(!PyInt_Check(item)) {
            PyErr_SetString(PyExc_TypeError, "A sequence of integers is required");
            return ret; /* Return the list so it can be freed */
        }
        if(cap_get_flag(caps, PyInt_AsLong(item), flag, &value) == -1) {
            PyErr_SetFromErrno(PyExc_OSError);
            return ret;
        }
        val = PyBool_FromLong(value);
        PyDict_SetItem(ret, item, val);
        Py_XDECREF(val);
    }
    return ret;
}

static int prctl_set_caps_flag(PyObject *list, cap_t caps, int flag, cap_flag_value_t value) {
    int i;
    cap_value_t cap;
    PyObject *item;

    if(list && !PySequence_Check(list)) {
        PyErr_SetString(PyExc_TypeError, "A sequence of integers is required");
        return 0;
    }
    if(!list)
        return 1;

    for(i=0; i < PyList_Size(list); i++) {
        item = PyList_GetItem(list, i);
        if(!PyInt_Check(item)) {
            PyErr_SetString(PyExc_TypeError, "A sequence of integers is required");
            return 0;
        }
        cap = PyInt_AsLong(item);
        if(cap_set_flag(caps, flag, 1, &cap, value) == -1) {
            PyErr_SetFromErrno(PyExc_OSError);
            return 0;
        }
    }
    return 1;
}

static PyObject * prctl_get_caps(PyObject *self, PyObject *args)
{
    PyObject *effective = NULL;
    PyObject *permitted = NULL;
    PyObject *inheritable = NULL;
    PyObject *effective_ = NULL;
    PyObject *permitted_ = NULL;
    PyObject *inheritable_ = NULL;
    PyObject *ret = NULL;
    PyObject *key = NULL;
    cap_t caps = NULL;

    if(!PyArg_ParseTuple(args, "O|OO", &effective, &permitted, &inheritable)) {
        return NULL;
    }
    caps = cap_get_proc();
    if(!caps) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    effective_ = prctl_get_caps_flag(effective, caps, CAP_EFFECTIVE);
    if(PyErr_Occurred()) goto error;
    permitted_ = prctl_get_caps_flag(permitted, caps, CAP_PERMITTED);
    if(PyErr_Occurred()) goto error;
    inheritable_ = prctl_get_caps_flag(inheritable, caps, CAP_INHERITABLE);
    if(PyErr_Occurred()) goto error;

    /* Now build the dict */
    ret = PyDict_New();
    key = PyInt_FromLong(CAP_EFFECTIVE);
    PyDict_SetItem(ret, key, effective_);
    Py_XDECREF(key);
    key = PyInt_FromLong(CAP_PERMITTED);
    PyDict_SetItem(ret, key, permitted_);
    Py_XDECREF(key);
    key = PyInt_FromLong(CAP_INHERITABLE);
    PyDict_SetItem(ret, key, inheritable_);
    Py_XDECREF(key);

error:
    cap_free(caps);
    Py_XDECREF(effective_);
    Py_XDECREF(permitted_);
    Py_XDECREF(inheritable_);

    return ret;
}

static PyObject * prctl_set_caps(PyObject *self, PyObject *args)
{
    PyObject *effective_set = NULL;
    PyObject *permitted_set = NULL;
    PyObject *inheritable_set = NULL;
    PyObject *effective_clear = NULL;
    PyObject *permitted_clear = NULL;
    PyObject *inheritable_clear = NULL;
    cap_t caps = NULL;

    if(!PyArg_ParseTuple(args, "O|OOOOO", &effective_set, &permitted_set, &inheritable_set,
                                          &effective_clear, &permitted_clear, &inheritable_clear)) {
        return NULL;
    }
    caps = cap_get_proc();
    if(!caps) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    if(!prctl_set_caps_flag(effective_set, caps, CAP_EFFECTIVE, CAP_SET))
        return NULL;
    if(!prctl_set_caps_flag(permitted_set, caps, CAP_PERMITTED, CAP_SET))
        return NULL;
    if(!prctl_set_caps_flag(inheritable_set, caps, CAP_INHERITABLE, CAP_SET))
        return NULL;
    if(!prctl_set_caps_flag(effective_clear, caps, CAP_EFFECTIVE, CAP_CLEAR))
        return NULL;
    if(!prctl_set_caps_flag(permitted_clear, caps, CAP_PERMITTED, CAP_CLEAR))
        return NULL;
    if(!prctl_set_caps_flag(inheritable_clear, caps, CAP_INHERITABLE, CAP_CLEAR))
        return NULL;

    if(cap_set_proc(caps) == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    
    Py_RETURN_NONE;
}

static PyObject * prctl_cap_to_name(PyObject *self, PyObject *args) {
    cap_value_t cap;
    char *name;
    PyObject *ret;

    if(!PyArg_ParseTuple(args, "i", &cap)){
        return NULL;
    }
    name = cap_to_name(cap);
    if(!name) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    ret = Py_BuildValue("s", name+4); /* Exclude the cap_ prefix */
    cap_free(name);
    return ret;
}

static PyMethodDef PrctlMethods[] = {
    {"get_caps", prctl_get_caps, METH_VARARGS, "Get process capabilities"},
    {"set_caps", prctl_set_caps, METH_VARARGS, "Set process capabilities"},
    {"cap_to_name", prctl_cap_to_name, METH_VARARGS, "Convert capability number to name"},
    {"prctl", prctl_prctl, METH_VARARGS, "Call prctl"},
    {"set_proctitle", prctl_set_proctitle, METH_VARARGS, "Set the process title"},
    {NULL, NULL, 0, NULL} /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef prctlmodule = {
    PyModuleDef_HEAD_INIT,
    "_prctl",
    NULL,
    -1,
    PrctlMethods
};
#endif

/* These macros avoid tediously repeating a name 2 or 4 times */
#define namedconstant(x) PyModule_AddIntConstant(_prctl, #x, x)
#define namedattribute(x) do{ \
    PyModule_AddIntConstant(_prctl, "PR_GET_" #x,  PR_GET_ ## x); \
    PyModule_AddIntConstant(_prctl, "PR_SET_" #x,  PR_SET_ ## x); \
} while(0)

PyMODINIT_FUNC
#if PY_MAJOR_VERSION < 3
init_prctl(void)
#else
PyInit__prctl(void)
#endif
{
#if PY_MAJOR_VERSION < 3
    PyObject *_prctl = Py_InitModule("_prctl", PrctlMethods);
#else
    PyObject *_prctl = PyModule_Create(&prctlmodule);
#endif
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
#ifdef PR_MCE_KILL
    namedattribute(MCE_KILL);
    namedconstant(PR_MCE_KILL_DEFAULT);
    namedconstant(PR_MCE_KILL_EARLY);
    namedconstant(PR_MCE_KILL_LATE);
#endif
    namedattribute(NAME);
    namedattribute(PDEATHSIG);
#ifdef PR_SET_PTRACER
    namedattribute(PTRACER);
#endif
    namedattribute(SECCOMP);
    namedattribute(SECUREBITS);
#ifdef PR_GET_TIMERSLACK
    namedattribute(TIMERSLACK);
#endif
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
    namedconstant(CAP_EFFECTIVE);
    namedconstant(CAP_PERMITTED);
    namedconstant(CAP_INHERITABLE);
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
#ifdef CAP_SYSLOG
    namedconstant(CAP_SYSLOG);
#endif
#ifdef CAP_WAKE_ALARM
    namedconstant(CAP_WAKE_ALARM);
#endif
    /* And the securebits constants */
    namedconstant(SECURE_KEEP_CAPS);
    namedconstant(SECURE_NO_SETUID_FIXUP);
    namedconstant(SECURE_NOROOT);
    namedconstant(SECURE_KEEP_CAPS_LOCKED);
    namedconstant(SECURE_NO_SETUID_FIXUP_LOCKED);
    namedconstant(SECURE_NOROOT_LOCKED);
    namedconstant(SECBIT_KEEP_CAPS);
    namedconstant(SECBIT_NO_SETUID_FIXUP);
    namedconstant(SECBIT_NOROOT);
    namedconstant(SECBIT_KEEP_CAPS_LOCKED);
    namedconstant(SECBIT_NO_SETUID_FIXUP_LOCKED);
    namedconstant(SECBIT_NOROOT_LOCKED);
#if PY_MAJOR_VERSION >= 3
    return _prctl;
#endif
}
