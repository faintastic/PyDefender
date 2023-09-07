"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
from observable import Observable

class DefenderEvent:
    def __init__(self, event: str, text: str, module: str, **kwargs) -> None:
        self.event: str = event
        self.text: str = text
        self.module:str = module
        self.misc: dict = kwargs

class DefenderObservable:
    def __init__(self) -> None:
        self.obs: Observable = Observable()
    
    def dispatch(self, event: str, text: str, module: str, **kwargs) -> DefenderEvent:
        """
        Triggers an event

        Arguments:
            event (string): The event name
            text (string): The text that was given
            module (string): The name of the module that has been triggered
        
        Returns:
            DefenderEvent
        """
        self.obs.trigger(event, text, module, **kwargs)
        return DefenderEvent(event, text, module, **kwargs)