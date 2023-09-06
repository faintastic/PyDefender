"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
import os, time, win32api, win32process
from ..types import Event, Logger
from ..abc import Module
from ..constants import Lists
from ..utils.webhook import Webhook

class AntiDLL(Module):
    def __init__(self, webhook: Webhook, logger: Logger, exit: bool, report: bool, event: Event) -> None:
        self.webhook: Webhook = webhook
        self.logger: Logger = logger
        self.exit: bool = exit
        self.report: bool = report
        self.event: Event = event
 
    @property
    def name(self) -> str:
        return "Anti DLL"
    
    @property
    def version(self) -> str:
        return "1.0.0"
     
    def BlockDLLs(self) -> None:
        """Blocks blacklisted DLL's from being injected"""
        while True:
            try:
                time.sleep(1)
                EvidenceOfSandbox = []
                allPids: tuple = win32process.EnumProcesses()
                for pid in allPids:
                    try:
                        hProcess: int = win32api.OpenProcess(0x0410, 0, pid)
                        try:
                            curProcessDLLs: tuple = win32process.EnumProcessModules(
                                hProcess
                            )
                            for dll in curProcessDLLs:
                                dllName: str = str(
                                    win32process.GetModuleFileNameEx(hProcess, dll)
                                ).lower()
                                for sandboxDLL in Lists.BLACKLISTED_DLLS:
                                    if sandboxDLL in dllName:
                                        if dllName not in EvidenceOfSandbox:
                                            EvidenceOfSandbox.append(dllName)
                        finally:
                            win32api.CloseHandle(hProcess)
                    except BaseException:
                        pass
                if EvidenceOfSandbox:
                    self.logger.info(
                        f"The Following DLL's: {EvidenceOfSandbox} Were Found Loaded"
                    )
                    if self.report:
                        self.webhook.Send(
                            f"The following DLL's were discovered loaded in processes running on the users system. DLLS: {EvidenceOfSandbox}",
                            self.name,
                        )
                        self.event.dispatch(
                            "dll_attach",
                            f"The following DLL's were discovered loaded in processes running on the users system. DLLS: {EvidenceOfSandbox}",
                            self.name,
                            {EvidenceOfSandbox},
                            dlls=EvidenceOfSandbox,
                        )
                        self.event.dispatch(
                            "pyguardian_detect",
                            f"The following DLL's were discovered loaded in processes running on the users system. DLLS: {EvidenceOfSandbox}",
                            self.name,
                            {EvidenceOfSandbox},
                            dlls=EvidenceOfSandbox,
                        )
                    if self.exit:
                        os._exit(1)
            except BaseException:
                pass