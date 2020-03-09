
_mod     = None

try:
    from . import _ctsrp
    _mod = _ctsrp
except (ImportError, OSError):
    raise ImportError("Unable to import module")

User                           = _mod.User
create_salted_verification_key = _mod.create_salted_verification_key
