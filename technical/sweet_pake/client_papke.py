#!/usr/bin/env python


def main():

    print("Welcome to PAPKE protocol.")

    # params = "Params2048"
    from papke import PAPKE_Client, PAPKE_Server
    from papke.groups import Params3072

    client = PAPKE_Client(b"our password", params=Params3072)
    server = PAPKE_Server(b"our password", params=Params3072)

    client_gen = client.gen()
    server_enc = server.enc(client_gen)
    client_dec = client.dec(server_enc)

    sk_client = client.session_key.hex()
    sk_server = server.session_key.hex() 

    print(sk_client)
    print(sk_server)
    print(sk_client == sk_server)


if __name__ == "__main__":
    main()
