import socket
import logging
import json
import requests
import nacl.secret

from spake2 import SPAKE2_A

client_identifier = ""
host = "http://spake.obscurepeak.com"
port = 80
password = ""

if __name__ == "__main__":
    try:

        # REQUEST 1: Get server identifier
        response = requests.get(
            host + ":" + str(port) + "/getServerIdentifier"
        )

        # REQUEST 2: Send your identifier and a password to the server, receive a session_id value and the server's outbound message in response
        message_1 = json.loads(response.text)
        print(response.json())

        # message_2 = {"identifier": "", "password": ""}
        # print(json.dumps(message_2))
        # response = requests.post(host+":"+str(port)+"/sendPassword", json=json.dumps(message_2))

        # REQUEST 3 Send your outbound message to the server and receive a ciphertext in response
        # print(response.json())
        # message_3 = json.loads(response.text)
        # sess_id = message_3['session_id']
        # message = message_3['message']

        # message_4 = {"message": "", "session_id": ""}
        # response = requests.post(host+":"+str(port)+"/sendMessage", json=json.dumps(message_4))
        # print(response.json())

    except Exception as e:
        print(e)
        print("Unexpected exception")
