from . import _pysrp
_mod = None

try:
    from . import _ctsrp
    _mod = _ctsrp
except (ImportError, OSError):
    pass

if not _mod:
    _mod = _pysrp

User = _mod.User
create_salted_verification_key = _mod.create_salted_verification_key
