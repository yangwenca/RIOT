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

DTLS follows dtls-echo example. (Latest version)
https://github.com/RIOT-OS/RIOT/pull/6430

IoT-LAB
The code has been tested on the IoT-LAB M3 node. For some unknown reasons, the server does not receive packet in the second round.