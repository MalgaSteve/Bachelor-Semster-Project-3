#!/usr/bin/env python
import hashlib
import time


def main():

    print("SweetPAKE protocol!")

    # params = "Params2048"
    from sweet_pake import SweetPAKE_Client, SweetPAKE_Server
    from sweet_pake.groups import Params3072

    start_time = time.time()


    c_time1 = time.time()
    client_password = hashlib.scrypt(b"stenkt420", salt=b"NaCl", n=16384, r=8, p=16)
    client = SweetPAKE_Client(b"Steve", client_password, params=Params3072)
    c_time1_end = time.time()
    c_time1_res = c_time1_end - c_time1

    s_time1 = time.time()
    server = SweetPAKE_Server(b"our password", params=Params3072)
    s_time1_end = time.time()
    s_time1_res = s_time1_end - s_time1

    c_time2 = time.time()
    client_gen = client.gen()
    c_time2_end = time.time()
    c_time2_res = c_time2_end - c_time2

    s_time2 = time.time()
    server_enc = server.enc(client_gen)
    s_time2_end = time.time()
    s_time2_res = s_time2_end - s_time2

    c_time3 = time.time()
    client_dec = client.dec(server_enc)
    c_time3_end = time.time()
    c_time3_res = c_time3_end - c_time3

    s_time3 = time.time()
    server_retrieve = server.retrieve_key_ask_honeychecker(client_dec)
    s_time3_end = time.time()
    s_time3_res = s_time3_end - s_time3

    sk_client = client.session_key.hex()
    sk_server = server.session_key.hex() 

    end_time = time.time()
    elapsed_time = end_time - start_time

    client_time_res = c_time1_res + c_time2_res + c_time3_res
    server_time_res = s_time1_res + s_time2_res + s_time3_res

    print("Time: ", elapsed_time)
    print("Client time: ", client_time_res)
    print("Server time: ", server_time_res)
    print("Client key: " + sk_client)
    print("Server key: " + sk_server)
    print(sk_client == sk_server)


if __name__ == "__main__":
    main()
