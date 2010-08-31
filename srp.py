
User     = None
Verifier = None
gen_sv   = None

try:
    import _srp
    User     = _srp.User
    Verifier = _srp.Verifier
    gen_sv   = _srp.gen_sv
except ImportError:
    pass

if not User:
    try:
        import _ctsrp
        User     = _ctsrp.User
        Verifier = _ctsrp.Verifier
        gen_sv   = _ctsrp.gen_sv
    except ImportError:
        pass
    
if not User:
    import _pysrp
    User     = _pysrp.User
    Verifier = _pysrp.Verifier
    gen_sv   = _pysrp.gen_sv

        
        

   
   

    
    