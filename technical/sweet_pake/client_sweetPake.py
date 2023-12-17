#!/usr/bin/env python
import hashlib


def main():

    print("SweetPAKE protocol!")

    # params = "Params2048"
    from sweet_pake import SweetPAKE_Client, SweetPAKE_Server
    from sweet_pake.groups import Params3072

    client_password = hashlib.scrypt(b"stenkt420", salt=b"NaCl", n=16384, r=8, p=16)

    client = SweetPAKE_Client(b"Steve", client_password, params=Params3072)
    server = SweetPAKE_Server(b"our password", params=Params3072)

    client_gen = client.gen()
    server_enc = server.enc(client_gen)
    client_dec = client.dec(server_enc)
    server_retrieve = server.retrieve_key_ask_honeychecker(client_dec)

    sk_client = client.session_key.hex()
    sk_server = server.session_key.hex() 

    print("Client key: " + sk_client)
    print("Server key: " + sk_server)
    print(sk_client == sk_server)


if __name__ == "__main__":
    main()
