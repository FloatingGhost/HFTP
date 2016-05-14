#!/usr/bin/env python3

import pickle

user = input("Username: ")
key  = input("Public Key: ")

with open("/home/hannah/.hftpd/known_hosts") as f:
  pickle.dump([(user, key)], f)


