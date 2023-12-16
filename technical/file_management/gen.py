import random
import hashlib


def gen_chaff_digits(p, k):
    positions = []
    i = 0

    sugarwords = []

    for c in p:
        if c.isdigit():
            positions.append(i)
        i += 1

    sys_random = random.SystemRandom()
    for n in range(k):
        sugarwords.append(p)
        for x in positions:
            rand = sys_random.randint(0, 9)
            sugarwords[n] = sugarwords[n][:x] + str(rand) + sugarwords[n][x+1:]

    sugarwords.append(p)
    return sugarwords


def gen_by_model(p, k):
    sugarwords = []

    word_index = 0
    words = []
    for i in range(len(p)):
        if p[i].isdigit():
            if i != 0 and not p[i-1].isdigit():
                word_index += 1
        else:
            if i == 0 or p[i-1].isdigit():
                words.append(p[i])
            else:
                words[word_index] += (p[i])

    for n in range(k):
        x = p
        for word in words:
            x = x.replace(word, get_rnd_pw_word())
        sugarwords.append(x)

    return sugarwords


def get_rnd_pw_word():
    words = []
    rnd = 0
    sys_random = random.SystemRandom()
    with open("c_pws") as f:
        words = f.readlines()
        rnd = sys_random.randint(0, len(words)-1)

    return words[rnd][0:-1]


def append_user_to_file(name, pw):
    k = 3
    sugarwords = gen_by_model(pw, k)
    for i in range(len(sugarwords)):
        sugarwords += gen_chaff_digits(sugarwords[i], k)

    fisher_yates(sugarwords)
    pw_index = random.randint(0, len(sugarwords) - 1)
    sugarwords[pw_index] = pw
    encrypt_pws(sugarwords)

    with open("pw_file", 'a') as file:
        file.write(name + ":")

        for word in sugarwords:
            file.write(word)
            if not word == sugarwords[-1]:
                file.write(":")

        file.write("\n")


def encrypt_pws(arr):
    for i in range(len(arr)):
        dk = hashlib.scrypt(bytes(arr[i], 'utf-8'), salt=b"NaCl", n=16384, r=8, p=16)
        arr[i] = dk.hex()


def fisher_yates(arr):
    for i in range(1, len(arr)):
        j = random.randint(0, i)
        arr[j], arr[-i] = arr[-i], arr[j]


append_user_to_file("Marie", "stenkt420")
append_user_to_file("Steve", "stenkt420")
append_user_to_file("Marjan", "stenkt420")
append_user_to_file("Bob", "stenkt420")
append_user_to_file("Alice", "stenkt420")
