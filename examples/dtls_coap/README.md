# dtls-coap

Integrate the nanocoap and TinyDTLS


Reference

Adeola Bannis has integrated TinyDTLS and libcoap.
https://github.com/thecodemaiden/tinydtls-coap

Nanocoap follows client and server example.

Client
https://github.com/yangwenca/RIOT/tree/master/examples/gcoap

Server
https://github.com/yangwenca/RIOT/tree/master/examples/nanocoap_server

DTLS follows dtls-echo example.
https://github.com/yangwenca/RIOT/tree/master/examples/dtls-echo


## FIT-LAB

The code has been tested in the FIT-LAB with M3 nodes.


## Confgiuration between M3 Nodes


For the server instance:

    ifconfig
    dtlss start
    
For the client:

    dtlsc get <IPv6's server address> /.well-known/core [delay]
    
    