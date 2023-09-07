"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
import ctypes, win32api
from ctypes import WinDLL
from ctypes import wintypes
from ..types import Event, Logger
from ..abc import Module
from ..utils.webhook import Webhook

class AntiDump(Module):
    def __init__(self, webhook: Webhook, logger: Logger, exit: bool, report: bool, event: Event) -> None:
        self.webhook: Webhook = webhook
        self.logger: Logger = logger
        self.exit: bool = exit
        self.report: bool = report
        self.event: Event = event

        self.kernel32: WinDLL = ctypes.windll.kernel32
        self.ntdll: WinDLL = ctypes.windll.ntdll
 
    @property
    def name(self) -> str:
        return "Anti DLL"
    
    @property
    def version(self) -> str:
        return "1.0.0"

    def ErasePEHeaderFromMemory(self) -> None:
        """
        Erases PE Header from memory
        """
        oldProtect = wintypes.DWORD(0)

        baseAddress = ctypes.c_int(win32api.GetModuleHandle(None))

        self.kernel32.VirtualProtect(
            ctypes.pointer(baseAddress), 4096, 0x04, ctypes.pointer(oldProtect)
        )
        ctypes.memset(ctypes.pointer(baseAddress), 4096, ctypes.sizeof(baseAddress))
        self.event.dispatch(
            "pe_header_erased", "PE Header Erased From Memory", self.name
        )

    def StartChecks(self) -> None:
        if self.report:
            self.logger.info("Starting Anti Dump")
        if self.report:
            self.logger.info("Erasing PE Header From Memory")
        self.ErasePEHeaderFromMemory()
        if self.report:
            self.logger.info("PE Header Erased From Memory")
            self.logger.info("Finished Anti Dump")