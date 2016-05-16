eProtocol Definition

##Notation

- C: Client
- S: Server

##Handshake

Simple 3-step auth

`endpoint: http://address.of.server/auth`
```
All sent via POST to end endpoint

C:  REQUEST: HELLO 
    RSA_KEY: <C's RSA PUB>

S:  ACK: HELLO_FRIEND 
    RSA_PUBLIC: <S's RSA PUB>
    SESSION_KEY: <Session Key>
    AUTH_CHALLENGE: Enc<Rand Integer, i>

C:  REQUEST: AUTH_CONFIRM
    CHALLENGE_ANSWER: Enc<i+1>
    AUTH_CHALLENGE: Enc<Rand Integer, j> 
    SESSION_KEY: <Sesson Key>

S:  ACK: SERV_IDENT
    CHALLENGE_ANSWER Enc<j+1>

on faliure:
S:  ACK: FAILED
```

##Main Client

- PUT <filename> : C to S transfer
- GET <filename> : S to C transfer
- LS  <dir (default .)> : List dir contents
- CD  <dir (default .)> : Change directory to dir

