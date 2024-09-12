from strutils import find, split
from streams import newStringStream
from os import joinPath, dirExists, createDir, getEnv
from zippy/ziparchives import ZipArchive, open, extractAll, clear

type WCHAR = uint16 

proc toString*(wchars: array[260, WCHAR]): string =
  result = ""
  for ch in wchars:
    if ch == '\0'.ord:
      break
    result.add(char(ch))

proc fromString*(s: string): array[260, WCHAR] = 
  var wchars: array[260, WCHAR]
  var i = 0

  for ch in s:
    if i >= wchars.len:
      break 
    wchars[i] = WCHAR(ch.ord)
    inc(i)
  
  wchars[i] = '\0'.ord 
  result = wchars

func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

proc getFullPath*(envString: string): string =
  let startIdx = envString.find('"') + 1
  let endIdx = envString.find('"', startIdx)
  let envVarName = envString[startIdx .. endIdx - 1]

  let envVarValue = getEnv(envVarName)
  let pathSuffix = envString[endIdx + 1 .. ^1]

  return joinPath(envVarValue, pathSuffix)

proc splitNestedPath(path: string): seq[string] = 
  result = path.split('\\')

proc unzip*(destPath: string, resource: string): void =
  var  
    dirPath = ""
    archive = ZipArchive()

  let dirs = splitNestedPath(destPath)
  for dir in dirs[0 ..< dirs.len - 1]:
    dirPath = joinPath(dirPath, dir)
    if not dirExists(dirPath):
      createDir(dirPath)

  let dataStream = newStringStream(resource)
  archive.open(dataStream)
  archive.extractAll(destPath)
  archive.clear() 

proc convertSeconds*(seconds: int64): int64 = 
  return seconds * 10_000_000

