#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer

import socketserver
import rsa
import os
import cgi
import random
import string
import binascii
import glob
from rsa.bigfile import *

from floatingutils.conf import YamlConf
from floatingutils.log  import Log

log = Log()
config = YamlConf("hftpd.conf")

IP = config.getValue("server", "ip")
PORT = config.getValue("server", "port")

log.info("Loading RSA keys...")
keydir = os.path.expanduser("~/.hftpd")


rand = random.Random()

try:
  if not os.path.exists(keydir):
    log.info("{} does not exist. Creating...".format(keydir))
    os.mkdir(keydir)
    os.system("touch {}/known_hosts".format(keydir))
    raise FileNotFoundError
  with open("{}/private.pem".format(keydir), "r") as f:
    PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(f.read())
  with open("{}/public.pem".format(keydir), "r") as f:
    PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())
  with open("{}/known_hosts".format(keydir), "rb") as f:
    known_hosts = pickle.load(f)
except FileNotFoundError as e:
  log.info("Could not find one of your keys -- {}".format(e))
  log.info("Generating keys...")
  PUBLIC_KEY,PRIVATE_KEY = rsa.newkeys(512)
  log.info("Saving keys to {}".format(keydir))
                           
  with open("{}/private.pem".format(keydir), "w") as f:
    f.write(str(PRIVATE_KEY.save_pkcs1(), 'utf-8'))
  with open("{}/public.pem".format(keydir), "w") as f:
    f.write(str(PUBLIC_KEY.save_pkcs1(), 'utf-8'))
                           
log.info("Keys succesfully loaded.")

class Session:
  def __init__(self, ip, pubkey, sessionkey, username):
    self.ip = ip 
    self.pubkey = rsa.PublicKey.load_pkcs1(pubkey)
    self.sessionkey = sessionkey
    self.username = username 

  def encrypt(self, msg):
    return str(rsa.encrypt(msg, self.pubkey), 'utf-8')

  def getPub(self):
    return self.pubkey

  def setCheck(self, i):
    self.verification = i

  def getCheck(self):
    return self.verification

sessions = {}

def genSessionKey():
  key = ""
  for i in range(20):
    key += random.choice(string.ascii_letters)
  return key

class HFTPD(BaseHTTPRequestHandler):
    
  def do_GET(self):
    log.info("Processing GET Req from {}".format(self.client_address))

    log.info("Sending response...")
   
    log.info("Reqest asked for {}".format(self.path)) 
  
    resp = 404
    msg = "WE ONLY DO POST SORRY FAM"    

    self.send_response(resp)
    
    self.send_header("content-type", "text/plain")

    self.end_headers()

    self.wfile.write(self.fmt(msg))

 
  def do_POST(self):
    log.info("Processing POST Req from {}".format(self.client_address))

    form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
    post = {}
    ##Convert to dict 
    log.line("+")
    log.info("Post info:")
    for i in form.keys():
      post[i] = form.getvalue(i)
      log.info("  {} : '{}'".format(i, form.getvalue(i)))
    log.line("+")
    
    if self.path == "/auth":
      resp = 100
      msg = "REQUEST NOT RECOGNISED"

      if post["request"] == "HELLO":
        resp,msg = self.do_AUTH(post["pubkey"], post["username"])
      else:
        log.debug(sessions)
        if not post["session"] in sessions:
          #Deny access
          self.send_response(100)
          self.send_header("content-type", "text/plain")
          self.end_headers()
          self.wfile.write(self.fmt("ACCESS DENIED - AUTH FIRST"))
          return
      
      if post["request"] == "LOOKIE":
        resp,msg = self.do_HANDSHAKE(post["number"], post["session"])

      if post["request"] == "I_LOOKED":
        resp,msg = self.do_FINALIZE(post["number"], post["session"])

    
    if self.path == "/ftp":
      resp = 200
      cmd = post["request"]
      if cmd == "LS":
        msg = self.do_LS(post["session"])
      elif cmd == "PULL":
        msg = self.do_PULL(post["arg"], post["session"])
      elif cmd == "PUSH":
        msg = self.do_PUSH(post["arg"], post["file"], post["session"])
      else:
        msg = "Command not recognised"

        

    self.send_response(resp)

    self.send_header("content-type", "text/plain")

    self.end_headers()

    self.wfile.write(self.fmt("{}".format(msg)))
    log.line()
    
    return 

  def do_LS(self, key):
    return "\n".join(glob.glob("*"))

  def do_PUSH(self, filename, file, key):
    log.info("Recieving File {}".format(filename))
    with open("tmp", "wb") as f:
      f.write(binascii.unhexlify(file[2:-1]))
    with open("tmp", "rb") as i, open(filename, "wb") as o:
      decrypt_bigfile(i, o, PRIVATE_KEY)
    log.info("Recieved succesfully") 
    return "OK"

  def do_PULL(self, filename, key):
    try:
      with open(filename, "rb") as inf, open(filename+".rsa-enc", "wb") as out:
        encrypt_bigfile(inf, 
                        out, 
                        sessions[key].getPub()
                                )

      with open(filename + ".rsa-enc", "rb") as f:
        x= "-----FILE FOLLOWS-----\n"
        x += filename + "\n"
        x += str(binascii.hexlify(f.read())) + "\n"
        return x + "-----END FILE-----"
    except FileNotFoundError:
      return "ERROR: File Not Found"

  def do_AUTH(self, key, username):
    if not key:
      return 100, "NO FRIEND THAT IS NOT A KEY"
    ##Check it matches what we have
    #if not (username,key) in known_hosts:
    #  return 200, "I DON'T RECOGNISE YOU FRIEND"

    newkey = genSessionKey()
    sessions[newkey] = Session(self.client_address[0], key, newkey, username)
    return 200, "HELLO_FRIEND\t\n{}\t\n{}".format(str(PUBLIC_KEY.save_pkcs1(), 'utf-8'),
                                              newkey)

  def do_HANDSHAKE(self, number, sessionkey):
    number = binascii.unhexlify(number)
    try:
      decr = int(rsa.decrypt(number, PRIVATE_KEY))
    except rsa.pkcs1.DecryptionError:
      return 200, "DECRYPTION FAILED - CHECK IT ALL PLS\t\n{}".format(number)
    log.info(decr)
    
    addone = bytes(str(decr + 1), 'utf-8')
    addone = binascii.hexlify(rsa.encrypt(addone, sessions[sessionkey].getPub()))
    newint = rand.randint(1, 1000000)
    sessions[sessionkey].setCheck(newint)
    newint = bytes(str(newint), 'utf-8')
    newint = binascii.hexlify(rsa.encrypt(newint, sessions[sessionkey].getPub()))
    return 200, "I_LOOKED\t\n{}\t\nNOW_U\t\n{}".format(addone, newint)

  def do_FINALIZE(self, number, session):
    expecting = sessions[session].getCheck()+1
    
    got = int(rsa.decrypt(binascii.unhexlify(number), PRIVATE_KEY))
    
    if expecting == got:
      return 200, "WE_COOL"
    else:
      return 200, "NO_FAM"

  def get_file(self):
    return 200, "GETTING"

  def fmt(self, msg):
    return bytes(msg, 'utf-8')


try:
  log.info("Starting server on {}:{}".format(IP, PORT))

  server = HTTPServer((IP, PORT), HFTPD)

  log.info("Server running.")

  log.line()

  server.serve_forever()

except KeyboardInterrupt:
  log.newline()
  log.line()
  
  log.warning("Keyboard interrupt recieved. Shutting down...")
  server.socket.close()
  log.info("Socket closed, exiting.")

