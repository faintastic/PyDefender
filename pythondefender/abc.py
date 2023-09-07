"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
from abc import ABCMeta, abstractmethod

class Module(metaclass=ABCMeta):
    def __init__(self, webhook, logger, exit, report, event) -> None:
        self.webhook = webhook
        self.logger = logger
        self.exit = exit
        self.report = report
        self.event = event
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def version(self) -> float:
        pass