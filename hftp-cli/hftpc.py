import argparse
import requests
import rsa
import sys
import os
import random
import binascii

from floatingutils.log import Log

log = Log()


parser = argparse.ArgumentParser(description='Connect to a HFTP server.')

parser.add_argument("username", help="Your username")
parser.add_argument('host', help='The address of the server')
parser.add_argument('--port', default=9072,
                    help='The port to access')
parser.add_argument("--keydir", default=os.path.expanduser("~/.hftp"), 
                    help="The directory containing your RSA keys")

args = parser.parse_args()

log.info("Using Server {}@{}:{}".format(args.username, args.host, args.port))
log.info("Using {}".format(args.keydir))


try:
  if not os.path.exists(args.keydir):
    log.info("{} does not exist. Creating...".format(args.keydir))
    os.mkdir(args.keydir)
    raise FileNotFoundError
  with open("{}/private.pem".format(args.keydir), "r") as f:
    PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(f.read())
  with open("{}/public.pem".format(args.keydir), "r") as f:
    PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())
except FileNotFoundError as e:
  log.info("Could not find one of your keys -- {}".format(e))
  log.info("Generating keys...")
  PUBLIC_KEY,PRIVATE_KEY = rsa.newkeys(512)
  log.info("Saving keys to {}".format(args.keydir))

  with open("{}/private.pem".format(args.keydir), "w") as f:
    f.write(str(PRIVATE_KEY.save_pkcs1(), 'utf-8'))
  with open("{}/public.pem".format(args.keydir), "w") as f:
    f.write(str(PUBLIC_KEY.save_pkcs1(), 'utf-8'))

log.info("Keys succesfully loaded.")

sock = "http://{}:{}".format(args.host, args.port)
log.info("Connecting to {}...".format(sock))

r = requests.post("{}/auth".format(sock), data = {"request":"HELLO",
                                        "username":args.username,
                                        "pubkey":str(PUBLIC_KEY.save_pkcs1(), 'utf-8')})

resp = r.text
try:
  auth_resp,srv_key,session_key = resp.split("\t\n")
except ValueError:
  log.error("Server response was invalid")
  log.error("We got\n{}".format(resp))
  sys.exit(1)

if auth_resp != "HELLO_FRIEND":
  log.error("The server responded with some weird auth string")
  log.error("I wouldn't recommend connecting to it")
  log.error(resp)
  sys.exit(1)

log.info("Recieved server key, checking it is who it says it is")

SERV_KEY = rsa.PublicKey.load_pkcs1(srv_key)

rand = random.Random()

VERIFICATION_INTEGER = rand.randint(1, 1000000)
enc = rsa.encrypt(bytes(str(VERIFICATION_INTEGER), 'utf-8'), SERV_KEY)
enc = binascii.hexlify(enc)
r = requests.post("{}/auth".format(sock), data = {"request":"LOOKIE", 
                                                  "number":enc,
                                                  "session":session_key}
                  )
resp = (r.text).split("\t\n")
if resp[0] == "DECRYPTION FAILED - CHECK IT ALL PLS":
  log.error("Server could not decrypt.")
  log.error("It says we sent {}".format(bytes(resp[1], 'utf-8')))
  sys.exit(1)
else:
  plusone = resp[1][2:-1]
  number = int(rsa.decrypt(binascii.unhexlify(plusone), PRIVATE_KEY))
  if number != VERIFICATION_INTEGER+1:
    log.error("Server sent back the wrong number!")
    sys.exit(1)
  log.info("Server authenticated itself to us...")

assert(resp[2] == "NOW_U")

server_integer = binascii.unhexlify(resp[3][2:-1])
server_integer = int(rsa.decrypt(server_integer, PRIVATE_KEY))

addone = server_integer+1
addone = binascii.hexlify(rsa.encrypt(bytes(str(addone),'utf-8'), SERV_KEY))

r = requests.post("{}/auth".format(sock), data = {
                                             "request":"I_LOOKED",
                                             "session":session_key,
                                             "number":addone}
            )

if r.text == "WE_COOL":
  log.info("Server has accepted our credentials!")
else:
  log.error("The server rejected us :(")
  sys.exit(1)

#mainloop
while True:
  log.line()
  print("\n\n")
  action = input("HFTP@{} :: ".format(args.host)).strip()
  #Possible:
  #PUT, GET, LS, CD
  try:
    cmd, sep, arg = action.partition(" ")
  except ValueError:
    cmd = action
    arg = ""

  f = None
  if cmd.lower() == "push":
    try:
      with open(arg.partition(" ")[0], "r") as g:
        f = g.read()
    except FileNotFoundError:
      pass
    except ValueError:
      pass
  
  r = requests.post("{}/ftp".format(sock), data = {
                      "request": cmd.upper(),
                      "arg": arg,
                      "file": f,
                      "session": session_key
                    })
  r = r.text.split("\n")
  print("\n\n{}\n\n".format(r))
  if "FILE FOLLOWS" in r[0]:
    with open(r[1], "w") as f:
      for i in r[2:]:
        if "END FILE" in i:
          break
        else:
          i = str(rsa.decrypt(binascii.unhexlify(i), PRIVATE_KEY))[2:-1]
          f.write(i + "\n")
