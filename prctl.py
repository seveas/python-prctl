import _prctl # The C interface
import sys

# Code generation functions
def prctl_wrapper(option):
    def call_prctl(arg=0):
        return _prctl.prctl(option, arg)
    return call_prctl

def cap_wrapper(cap):
    def getter(self):
        return _prctl.prctl(_prctl.PR_CAPBSET_READ, cap)
    def setter(self, value):
        if value:
            raise ValueError("Can only drop capabilities from the bounding set, not add new ones")
        _prctl.prctl(_prctl.PR_CAPBSET_DROP, cap) # FIXME, the really should use libcap
    return property(getter, setter)

def sec_wrapper(bit):
    def getter(self):
        return bool(_prctl.prctl(_prctl.PR_GET_SECUREBITS) & (1 << bit))
    def setter(self, value):
        bits = _prctl.prctl(_prctl.PR_GET_SECUREBITS)
        if value:
            bits |= 1 << bit
        else:
            bits &= ~(1 << bit)
        _prctl.prctl(_prctl.PR_SET_SECUREBITS, bits)
    return property(getter, setter)

# Wrap the capability bounding set and securebits in an object
class Capbset(object):
    __slots__ = [name[4:].lower() for name in dir(_prctl) if name.startswith('CAP_')]
    def __init__(self):
        for name in dir(_prctl):
            if name.startswith('CAP_'):
                friendly_name = name[4:].lower()
                setattr(self.__class__, friendly_name, cap_wrapper(getattr(_prctl, name)))

capbset = Capbset()

class Securebits(object):
    __slots__ = [name[7:].lower() for name in dir(_prctl) if name.startswith('SECURE_')]
    def __init__(self):
        for name in dir(_prctl):
            if name.startswith('SECURE_'):
                friendly_name = name[7:].lower()
                setattr(self.__class__, friendly_name, sec_wrapper(getattr(_prctl, name)))

securebits = Securebits()

# Copy constants from _prctl and generate functions
self = sys.modules['prctl']
for name in dir(_prctl):
    if name.startswith(('PR_GET','PR_SET','PR_CAPBSET')):
        val = getattr(_prctl, name)
        friendly_name = name.lower()[3:]
        setattr(self, friendly_name, prctl_wrapper(val))

    elif name.startswith('PR_'):
        setattr(self, name[3:], getattr(_prctl, name))
    elif name.startswith(('CAP_','SECURE_')):
        # Add CAP_*/SECURE_* constants verbatim. You shouldn't use them anyway, use the
        # capbset/securebits object
        setattr(self, name, getattr(_prctl, name))
 
# Functions copied directly
set_proctitle = _prctl.set_proctitle

# Delete the init-only things
del self, friendly_name, name, prctl_wrapper, cap_wrapper, sec_wrapper
del Capbset, Securebits, sys, val
