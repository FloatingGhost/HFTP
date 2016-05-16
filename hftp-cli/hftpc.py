import argparse
import requests
import rsa
import sys
import os
import random
import binascii
from rsa.bigfile import *

from floatingutils.log import Log
from floatingutils.network.encryption import *
from floatingutils.network.client import Client

key = LocalKeys()

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
sock = "http://{}:{}".format(args.host, args.port)

cli = Client(args.host, args.port)

r = cli.post("auth", data = {"REQUEST":"HELLO",
                             "USERNAME":args.username,
                             "RSA_KEY":key.getNetworkPublic() 
                            }
            )


log.debug("Initial handshake...")
assert(r["ACK"] == "HELLO_FRIEND")

challenge = key.networkDecrypt(r["AUTH_CHALLENGE"])
answer = key.networkEncrypt(str(int(challenge)+1), cli.getServerPub())

rand = random.Random()
challeng_int = rand.randint(1, 10000000)
my_challenge = key.networkEncrypt(str(challeng_int), cli.getServerPub())

r = cli.post("auth", data = {"REQUEST":"AUTH_CONFIRM",
                             "CHALLENGE_ANSWER":answer,
                             "AUTH_CHALLENGE":my_challenge
                            }
            )
log.debug("Finalizing authentication...")
try:
  assert(r["ACK"] == "SERV_IDENT")
except AssertionError:
  log.error("Server rejected auth!")
  sys.exit(1)

serv_challenge = key.networkDecrypt(r["CHALLENGE_ANSWER"])

try:
  assert(int(serv_challenge) == challeng_int+1)
except AssertionError: 
  log.error("Server failed to authenticate itself!")
  sys.exit(1)

log.info("Server Connection Successful.\n")


#mainloop
while True:
  print("\n")
  action = input("HFTP@{} :: ".format(args.host)).strip()
  #Possible:
  #PUT, GET, LS, CD
  try:
    cmd, sep, arg = action.partition(" ")
  except ValueError:
    cmd = action
    arg = ""

  cmd = cmd.upper()

  if cmd not in ["PUSH", "PULL"]:
    r= cli.post("command", data={
                "CMD":cmd,
                "ARGS":arg,
                             }
              ) 
    if r["STATUS"] == "OK":
      print(r["OUTPUT"])
    else:
      print("Could not run: {}".format(r["OUTPUT"])) 
  elif cmd == "PULL":
    r = cli.post("command", data={
          "CMD":"PULL",
          "FILENAME":arg
                                  }
        )

    if r["STATUS"] == "OK":
      key.decryptFile(r["FILE_DATA"][2:-1], arg, True)
      print("Server Says: {}".format(r["OUTPUT"]))
    else:
      print("Server Error: {}".format(r["OUTPUT"]))

  elif cmd == "PUSH":
    try:
      print(cli.getServerPub())
      data = key.encryptFile(arg, cli.getServerPub(), True)
      r= cli.post("command", data={
                  "CMD":"PUSH",
                  "FILENAME": arg,
                  "FILE_DATA": data
                             }
                 )
      assert (r["STATUS"] == "OK")
      print("Server Says: {}".format(r["OUTPUT"]))

    except FileNotFoundError:
      print("Client Error: FILE NOT FOUND")
    except AssertionError:
      print("Server Error: {}".format(r["OUTPUT"]))
