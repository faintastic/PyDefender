"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
class DefenderException(Exception):
    """Base class for all PyDefender exceptions"""

class ModulesNotValid(DefenderException):
    def __init__(self, message: str) -> None:
        super().__init__(message)

class DetectionsNotValid(DefenderException):
    def __init__(self, message: str) -> None:
        super().__init__(message)

class LogsPathEmpty(DefenderException):
    def __init__(self, message: str) -> None:
        super().__init__(message)