eProtocol Definition

##Notation

- C: Client
- S: Server

##Handshake

Simple 3-step auth

```
C: HELLO <C's RSA PUB>
S: HELLO_FRIEND <S's RSA PUB> <Session Key>

C: LOOKIE Enc<Random Integer, i> <Sesson Key>
S: I_LOOKED Enc<i+1> NOW_U Enc<Random Integer, j>

C: I_LOOKED Enc<j+1> <Session Key>

on success:
S: WE_COOL

on faliure:
S: NO_FAM
```

##Main Client

- PUT <filename> : C to S transfer
- GET <filename> : S to C transfer
- LS  <dir (default .)> : List dir contents
- CD  <dir (default .)> : Change directory to dir

