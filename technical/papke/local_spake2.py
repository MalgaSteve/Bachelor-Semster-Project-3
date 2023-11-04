#!/usr/bin/env python


def main():

    print("Welcome to SPAKE2 protocol.")

    # params = "Params2048"
    from spake2 import SPAKE2_A, SPAKE2_B
    from spake2.groups import Params3072

    alice = SPAKE2_A(b"our password", params=Params3072)
    bob = SPAKE2_B(b"our password", params=Params3072)
    msg_out_a = alice.start()  # this is message A->B
    msg_out_b = bob.start()
    code_a = alice.compute(msg_out_b)
    code_b = bob.compute(msg_out_a)
    key_alice = alice.finish(code_b)
    key_bob = bob.finish(code_a)
    print(key_alice.hex())
    print(key_bob.hex())
    print(key_bob == key_alice)


if __name__ == "__main__":
    main()
