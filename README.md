
# PyDefender
Made with program protection in mind.

![PyDefender](https://media.discordapp.net/attachments/1092082158723666071/1149085362254266499/Untitled-1.png?ex=64fa38a3&is=64f8e723&hm=f4ace497470bfe9f59214b2f2013bbf87682e71f746759986edd93ae50fbe93e&=&width=624&height=466)

## Acknowledgements

 - [Kova / api](https://kova.rip)
 - [Python Protector](https://github.com/xFGhoul/PythonProtector)

## Story
I found [Python Protector](https://github.com/xFGhoul/PythonProtector) a couple months ago and have been using it! But recently, I have been encountering issues, the github hasn't been updated since June 7th (As of September 6th), so I decided, lets use there base, fix the issues, and hopefully update it more in the future!

## Features

- Configurable module system (Enable / Disable Modules)
- Configurable detection system (What it does when something is detected)
- Encrypted logging system with remote uploading
- Discord webhook support
- Clean code
- Constantly updated

## Installation

**Python 3.11 or higher is required**

Install via [PyPi](https://pypi.org/):
```
py -3 -m pip install -U pythondefender
```

## Usage

```py
from pathlib import Path
from threading import Thread

from pydefender import PyDefender

Defender = PyDefender(
    debug=True,
    modules=[
        "AntiProcess",
        "AntiVM",
        "Miscellaneous",
        "AntiDLL",
        "AntiAnalysis",
        "AntiDump"],
    logs_path=Path.home() / "AppData/Roaming/PyDefender/logs/[Security].log",
    webhook_url="%INSERT_WEBHOOK_URL&",
    on_detect=[
        "Report",
        "Exit",
        "Screenshot"],
)

if __name__ == "__main__":
    DefenderThread = Thread(
        name = "PyDefender Security", target=Defender.start
    )
    DefenderThread.start()
```

