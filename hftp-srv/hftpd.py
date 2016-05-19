#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer

import socketserver
import rsa
import os
import cgi
import random
import glob
import string
import binascii
import glob
import subprocess

from rsa.bigfile import *

from floatingutils.conf import YamlConf
from floatingutils.log  import Log
from floatingutils.network.server import * 
from floatingutils.network.encryption import *
from floatingutils.network.errors import *

log = Log()
config = YamlConf("hftpd.conf")

IP = config.getValue("server", "ip")
PORT = config.getValue("server", "port")

log.info("Loading RSA keyd...")
keydir = os.path.expanduser("~/.hftpd")
keyd = LocalKeys(keydir=keydir)

rand = random.Random()


class HFTPD(Server):
  pass

def cmdPath(session, postvals):
  if session.getAuthState() != 1:
    return {"STATUS":"FAIL", "CODE": code("ACCESS_DENIED"),
            "OUTPUT":"NOT AUTHENTICATED"}
  
  cd = str(subprocess.check_output("pwd"), 'utf-8').replace("\n", "")
  try:
    os.chdir(session.path)
  except AttributeError:
    pass
  cmd = postvals["CMD"]
  log.info(cmd)  
  if cmd == "LS":
    i = glob.glob("*")
    for j in range(len(i)):
      if os.path.isdir(i[j]):
        i[j]+="/"
    a = "..\n" + "\n".join([x for x in glob.glob("*") if "rsa-enc" not in x and x!="tmp"])
    os.chdir(cd)
    return {"STATUS":"OK", "OUTPUT":a}
  
  if cmd == "CD":
    if "ARGS" not in postvals:
      cda = str(subprocess.check_output("pwd"), 
                'utf-8').replace("\n", "")
      os.chdir(cd)
      return {"STATUS":"OK", "OUTPUT":cda}
    try:
      if "~" in postvals["ARGS"]:
        session.path = (os.path.expanduser(
                postvals["ARGS"]))
      elif postvals["ARGS"][0] == "/":
        session.path = postvals["ARGS"]
      else:
        session.path += "/"+postvals["ARGS"]
      os.chdir(cd)
      return {"STATUS":"OK", "OUTPUT":"DIR CHANGED"}
    except FileNotFoundError:
      os.chdir(cd)
      return {"STATUS":code("FAIL"), "CODE":code("FILE_NOT_FOUND"), "OUTPUT":"ERROR"}
  if cmd == "PULL":
    try:
      filename = postvals["FILENAME"]
      x = keyd.encryptFile(filename, session.getPublic(), True)
      os.chdir(cd)
      return {"STATUS":"OK", 
              "FILE_DATA":x, 
              "OUTPUT":"{} TRANSFER SUCCESSFUL".format(
                                                      filename)
            }   
    except FileNotFoundError:
      os.chdir(cd)
      return {"STATUS":"FAIL", "CODE":code("FILE_NOT_FOUND"),
               "OUTPUT":"FILE '{}' NOT FOUND".format(filename)}
 
  if cmd == "PUSH":
    filename = postvals["FILENAME"]
    data = postvals["FILE_DATA"]
    log.info(data)
    keyd.decryptFile(data, filename, True)
    os.chdir(cd)
    return {"STATUS":"OK", "OUTPUT":"{} TRANSFER SUCCESSFUL".format(filename)} 
  os.chdir(cd)
  return {"STATUS":"OK", "OUTPUT":"Command Not Found."}

addPathway("/command", cmdPath)

serverMainLoop(HFTPD, IP, PORT)
