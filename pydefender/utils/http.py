"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
import httpx

def getIpAddress() -> str:
    """
    Get the IP address of a user

    Returns:
        string: The IP address of the machine
    """
    try:
        response = httpx.get("https://ipinfo.io/json")
        response.raise_for_status()
    except (httpx.TimeoutException, httpx.RequestError, httpx.ConnectError, httpx.HTTPError):
        return "No IP address"

    response = response.json()
    ip = response.get("ip")
    return ip

def hasInternet() -> bool:
    """
    Checks if the user has an internet connection or not

    Returns:
        Boolean Value
    """
    try:
        return httpx.get("https://google.com")
    except (httpx.TimeoutException, httpx.RequestError, httpx.ConnectError, httpx.HTTPError):
        return False