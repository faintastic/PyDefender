"""
   ___       ___      ___            __       
  / _ \__ __/ _ \___ / _/__ ___  ___/ /__ ____
 / ___/ // / // / -_) _/ -_) _ \/ _  / -_) __/
/_/   \_, /____/\__/_/ \__/_//_/\_,_/\__/_/   
     /___/                                    


Made with 💞 by kova / api
- Made with program protection in mind.
"""
import io
from io import BytesIO
from PIL import Image, ImageGrab
from base64 import b64decode
from typing import Optional, List
from discord_webhook import DiscordEmbed, DiscordWebhook
from ..constants import EmbedCfg, LoggingInfo, UserInfo

class Webhook:
     def __init__(self, wh_url: Optional[str], logs: Optional[str], screenshot: Optional[bool]) -> None:
        self.wh_url = wh_url
        self.logs = logs
        self.screenshot = screenshot
     
     def takeScreenshot(self) -> bytes:
          """
          Takes a screenshot of the entire screen (including second moniters)

          Returns:
              Byte array
          """
          screenshot: Image = ImageGrab.grab(bbox=None, include_layered_windows=False, all_screens=True, xdisplay=None)
          bytes_array: BytesIO = io.BytesIO()
          screenshot.save(bytes_array, format="PNG")
          bytes_array = bytes_array.getvalue()
          return bytes_array

     def decryptLogs(self) -> bytes:
          """
          Decrypts the logs file

          Returns:
               string: Decrpted logs file
          """
          with open(self.logs, "r") as logs_file:
               decrypted_logs_file = io.StringIO()
               lines: List[str] = logs_file.readlines()
               for line in lines:
                    if not line.strip():
                         continue
                    encrypted_message: str = line.split(" ")[4]
                    encoded_message: bytes = b64decode(encrypted_message.encode("latin1"))
                    decrypted_message: str = LoggingInfo.CIPHER.decrypt(
                         encoded_message
                    ).decode("utf-8")
                    line: str = line.replace(str(encrypted_message), str(decrypted_message))
                    decrypted_logs_file.write(f"{line}\n")
               return decrypted_logs_file.getvalue()
     
     def Send(self, content:str, module:str) -> None:
          """
          Sends a log message with the discord webhook containing the user's username IP address, and a screenshot of their screen (if enabled)

          Arguments:
               content (string): The content of the message
               module (string): The module that triggered the webhook send
          
          Returns:
               Nothing
          """
          webhook: DiscordWebhook = DiscordWebhook(self.wh_url, rate_limit_retry=True, username="PyDefender Logs")
          
          webhook.add_file(file=self.decryptLogs(), filename=f"{UserInfo.USERNAME}-[SECURITY].log")
          
          embed: DiscordEmbed = DiscordEmbed(title=EmbedCfg.TITLE, color=EmbedCfg.COLOR)

          if self.screenshot:
               webhook.add_file(file=self.takeScreenshot(), filename="screenshot.png")
               embed.set_image(url="attachment://screenshot.png")
          
          embed.add_embed_field(name="Username", value=UserInfo.USERNAME, inline=True)
          embed.add_embed_field(name="IP Address", value=UserInfo.IP, inline=True)
          embed.add_embed_field(name="Module Triggered", value=module, inline=True)
          embed.set_timestamp()
          embed.set_description(content)
          embed.set_thumbnail(url=EmbedCfg.ICON)
          embed.set_footer(text=f"PyDefender - Made with program protection in mind.", icon_url=EmbedCfg.ICON)
          webhook.add_embed(embed)
          webhook.execute()