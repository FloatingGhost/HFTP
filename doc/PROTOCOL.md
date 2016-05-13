#Protocol Definition

##Notation

- C: Client
- S: Server

##Handshake

Simple 3-step auth

```
C: HELLO <C's RSA PUB>
S: HELLO_FRIEND <S's RSA PUB>

C: LOOKIE Enc<Random Integer, i>
S: I_LOOKED Enc<i+1> Enc<Random Integer, j>

C: I_LOOKED Enc<j+1>
S: WE_COOL
```

##Main Client

- PUT <filename> : C to S transfer
- GET <filename> : S to C transfer
- LS  <dir (default .)> : List dir contents
- CD  <dir (default .)> : Change directory to dir

