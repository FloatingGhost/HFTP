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
from rsa.bigfile import *

from floatingutils.conf import YamlConf
from floatingutils.log  import Log
from floatingutils.network.server import * 
from floatingutils.network.encryption import *

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
    return {"STATUS":"FAIL", "OUTPUT":"NOT AUTHENTICATED"}

  cmd = postvals["CMD"]
  log.info(cmd)  
  if cmd == "LS":
    a = "\n".join([x for x in glob.glob("*") if "rsa-enc" not in x and x!="tmp"])
    return {"STATUS":"OK", "OUTPUT":a}

  if cmd == "PULL":
    try:
      filename = postvals["FILENAME"]
      x = keyd.encryptFile(filename, session.getPublic(), True)
      return {"STATUS":"OK", "FILE_DATA":x, "OUTPUT":"{} TRANSFER SUCCESSFUL".format(
                                                      filename)
            }   
    except FileNotFoundError:
      return {"STATUS":"FAIL", "OUTPUT":"FILE NOT FOUND"}
 
  if cmd == "PUSH":
    filename = postvals["FILENAME"]
    data = postvals["FILE_DATA"]
    log.info(data)
    keyd.decryptFile(data, filename, True)
    
    return {"STATUS":"OK", "OUTPUT":"{} TRANSFER SUCCESSFUL".format(filename)} 
  return {"STATUS":"OK", "OUTPUT":"Command Not Found."}

addPathway("/command", cmdPath)

serverMainLoop(HFTPD, IP, PORT)
