"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
import ctypes, os, sys, httpx
from typing import List
from ..types import Event, Logger
from ..abc import Module
from ..constants import Lists, UserInfo
from ..utils.webhook import Webhook

class AntiVM(Module):
    def __init__(self, webhook: Webhook, logger: Logger, exit: bool, report: bool, event: Event) -> None:
        self.webhook: Webhook = webhook
        self.logger: Logger = logger
        self.exit: bool = exit
        self.report: bool = report
        self.event: Event = event

        self.VMWARE_MACS: List[str] = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
        self.HWIDS: List[str] = httpx.get(
            "https://raw.githubusercontent.com/apilol/PyDefender/dev/data/hwid_data.txt"
        ).text
        self.PC_NAMES: List[str] = httpx.get(
            "https://raw.githubusercontent.com/apilol/PyDefender/dev/data/pc_names_data.txt"
        ).text
        self.PC_USERNAMES: List[str] = httpx.get(
            "https://raw.githubusercontent.com/apilol/PyDefender/dev/data/pc_usernames_data.txt"
        ).text
        self.IPS: List[str] = httpx.get(
            "https://raw.githubusercontent.com/apilol/PyDefender/dev/data/ip_data.txt"
        ).text
        self.MACS: List[str] = httpx.get(
            "https://raw.githubusercontent.com/apilol/PyDefender/dev/data/mac_data.txt"
        ).text
        self.GPUS: List[str] = httpx.get(
            "https://raw.githubusercontent.com/apilol/PyDefender/dev/data/gpu_data.txt"
        ).text
        self.PLATFORMS: List[str] = httpx.get(
            "https://raw.githubusercontent.com/apilol/PyDefender/dev/data/pc_platform_data.txt"
        ).text

    @property
    def name(self) -> str:
        return "Anti VM"
    
    @property
    def version(self) -> str:
        return "1.0.0"

    def _get_base_prefix_compat(self) -> None:
        return (
            getattr(sys, "base_prefix", None)
            or getattr(sys, "real_prefix", None)
            or sys.prefix
        )

    def CheckLists(self) -> None:
        """
        Checks if the user's hardware ID, PC username, PC name, IP address, MAC address, or GPU are in the blacklists files.
        """
        if UserInfo.HWID in self.HWIDS:
            self.logger.info(f"Blacklisted HWID Detected. HWID: {UserInfo.HWID}")
            if self.report:
                self.webhook.Send(
                    f"Blacklisted HWID detected: `{UserInfo.HWID}`", self.name
                )
                self.event.dispatch(
                    "blacklisted_hwid",
                    "Blacklisted HWID Detected",
                    self.name,
                    hwid=UserInfo.HWID,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "Blacklisted HWID Detected",
                    self.name,
                    hwid=UserInfo.HWID,
                )
            if self.exit:
                os._exit(1)

        if UserInfo.USERNAME in self.PC_USERNAMES:
            self.logger.info(f"Blacklisted PC User: {UserInfo.USERNAME}")
            if self.report:
                self.webhook.Send(
                    f"Blacklisted PC User: `{UserInfo.USERNAME}`", self.name
                )
                self.event.dispatch(
                    "blacklisted_pc_username",
                    "Blacklisted PC User Detected",
                    self.name,
                    pc_username=UserInfo.USERNAME,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "Blacklisted PC User Detected",
                    self.name,
                    pc_username=UserInfo.USERNAME,
                )
            if self.exit:
                os._exit(1)

        if UserInfo.PC_NAME in self.PC_NAMES:
            self.logger.info(f"Blacklisted PC Name: {UserInfo.PC_NAME}")
            if self.report:
                self.webhook.Send(
                    f"Blacklisted PC Name: `{UserInfo.PC_NAME}`", self.name
                )
                self.event.dispatch(
                    "blacklisted_pc_name",
                    "Blacklisted PC Name Detected",
                    self.name,
                    pc_name=UserInfo.PC_NAME,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "Blacklisted PC Name Detected",
                    self.name,
                    pc_name=UserInfo.PC_NAME,
                )
            if self.exit:
                os._exit(1)

        if UserInfo.IP in self.IPS:
            self.logger.info(f"Blacklisted IP: {UserInfo.IP}")
            if self.report:
                self.webhook.Send(f"Blacklisted IP address: `{UserInfo.IP}`", self.name)
                self.event.dispatch(
                    "blacklisted_ip",
                    "Blacklisted IP Detected",
                    self.name,
                    ip=UserInfo.IP,
                )
                self.event.dispatch(
                    "blacklisted_ip",
                    "Blacklisted IP Detected",
                    self.name,
                    ip=UserInfo.IP,
                )
            if self.exit:
                os._exit(1)

        if UserInfo.MAC in self.MACS:
            self.logger.info(f"Blacklisted MAC address: {UserInfo.MAC}")
            if self.report:
                self.webhook.Send(f"Blacklisted MAC: `{UserInfo.MAC}`", self.name)
                self.event.dispatch(
                    "blacklisted_mac_address",
                    "Blacklisted MAC Detected",
                    self.name,
                    mac_addr=UserInfo.MAC,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "Blacklisted MAC Detected",
                    self.name,
                    mac_addr=UserInfo.MAC,
                )
            if self.exit:
                os._exit(1)

        if UserInfo.GPU in self.GPUS:
            self.logger.info(f"Blacklisted GPU: {UserInfo.GPU}")
            if self.report:
                self.webhook.Send(f"Blacklisted GPU: `{UserInfo.GPU}`", self.name)
                self.event.dispatch(
                    "blacklisted_gpu",
                    "Blacklisted GPU Detected",
                    self.name,
                    gpu=UserInfo.GPU,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "Blacklisted GPU Detected",
                    self.name,
                    gpu=UserInfo.GPU,
                )
            if self.exit:
                os._exit(1)

    def CheckVirtualEnv(self) -> None:
        """
        Checks sys.prefix
        """
        if self._get_base_prefix_compat() != sys.prefix and self.exit:
            os._exit(1)

    def CheckRegistry(self) -> None:
        """
        Checks VMWare Registry Keys
        """
        reg1: int = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul"
        )
        reg2: int = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul"
        )

        if reg1 != 1 and reg2 != 1:
            self.logger.info("VMWare Registry Detected")
            if self.report:
                self.webhook.Send("VMWare registry detected", self.name)
                self.event.dispatch(
                    "vmware_registry",
                    "VMWare Registry Detected",
                    self.name,
                    reg1=reg1,
                    reg2=reg2,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "VMWare Registry Detected",
                    self.name,
                    reg1=reg1,
                    reg2=reg2,
                )
            if self.exit:
                os._exit(1)

    def CheckMacAddress(self) -> None:
        """
        Checks MAC address to see if it is against the blacklisted list
        """
        if UserInfo.MAC[:8] in self.VMWARE_MACS:
            self.logger.info("VMWare MAC Address Detected")
            if self.report:
                self.webhook.Send("VMWare MAC address detected", self.name)
                self.event.dispatch(
                    "vmware_mac",
                    "VMWare MAC Address Detected",
                    self.name,
                    mac_addr=UserInfo.MAC,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "VMWare MAC Address Detected",
                    self.name,
                    mac_addr=UserInfo.MAC,
                )
            if self.exit:
                os._exit(1)

    def CheckScreenSize(self) -> None:
        """
        Checks the screen size for being less than 200x200
        """
        x: int = ctypes.windll.user32.GetSystemMetrics(0)
        y: int = ctypes.windll.user32.GetSystemMetrics(1)
        if x <= 200 or y <= 200:
            self.logger.info(f"Screen Size X: {x} | Y: {y}")
            if self.report:
                self.webhook.Send(f"Screen size is: **x**: {x} | **y**: {y}", self.name)
                self.event.dispatch(
                    "screen_size", f"Screen Size X: {x} | Y: {y}", self.name, x=x, y=y
                )
                self.event.dispatch(
                    "pydefender_detect",
                    f"Screen Size X: {x} | Y: {y}",
                    self.name,
                    x=x,
                    y=y,
                )
            if self.exit:
                os._exit(1)

    def CheckProcessesAndFiles(self) -> None:
        """
        Checks For Blacklisted Processes and Files
        """
        vmware_dll: str = os.path.join(
            os.environ["SystemRoot"], "System32\\vmGuestLib.dll"
        )
        virtualbox_dll: str = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")

        process: str = os.popen(
            'TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="'
        ).read()
        processList = []

        for processNames in process.split(" "):
            if ".exe" in processNames:
                processList.append(processNames.replace("K\n", "").replace("\n", ""))

        if any(Lists.VIRTUAL_MACHINE_PROCESSES) in processList:
            self.logger.info("Blacklisted Virtual Machine Process Running")
            if self.report:
                self.webhook.Send("Blacklisted virtual machine process running", self.name)
                self.event.dispatch(
                    "vm_process_running",
                    "Blacklisted Virtual Machine Process Running",
                    self.name,
                    processes=processList,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "Blacklisted Virtual Machine Process Running",
                    self.name,
                    processes=processList,
                )
            if self.exit:
                os._exit(1)

        if os.path.exists(vmware_dll):
            self.logger.info("VMWare DLL Detected")
            if self.report:
                self.webhook.Send("VMWare DLL detected", self.name)
                self.event.dispatch(
                    "vmware_dll", "VMWare DLL Detected", self.name, dll=vmware_dll
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "VMWare DLL Detected",
                    self.name,
                    dll=vmware_dll,
                )
            if self.exit:
                os._exit(1)

        if os.path.exists(virtualbox_dll):
            self.logger.info("VirtualBox DLL detected")
            if self.report:
                self.webhook.Send("VirtualBox DLL Detected", self.name)
                self.event.dispatch(
                    "virtualbox_dll",
                    "VirtualBox DLL Detected",
                    self.name,
                    dll=virtualbox_dll,
                )
                self.event.dispatch(
                    "pydefender_detect",
                    "VirtualBox DLL Detected",
                    self.name,
                    dll=virtualbox_dll,
                )
            if self.exit:
                os._exit(1)

    def StartChecks(self) -> None:
        if self.report:
            self.logger.info("Starting VM Checks")
        self.CheckVirtualEnv()
        self.CheckRegistry()
        self.CheckMacAddress()
        self.CheckScreenSize()
        self.CheckProcessesAndFiles()
        self.CheckLists()
        if self.report:
            self.logger.info("Finished VM Checks")
