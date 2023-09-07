from pathlib import Path
from threading import Thread

from pythondefender import PyDefender

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
