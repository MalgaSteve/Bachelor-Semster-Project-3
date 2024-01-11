import os.path
import random

def get_dict_from_entries(filename):
    entries = read_file(filename)
    database = {}
    for entry in entries:
        entry_split = entry.split(":")
        database[entry_split[0]] = entry_split[1:] 
    return database
        

def read_file(filename):
    if not os.path.isfile(filename):
        raise EOFError("File does not exist!")
    else:
        with open(filename) as f:
            entries = f.read().splitlines()

    return entries


def fisher_yates(input_array):
    arr = input_array.copy()
    pmap = list(range(len(arr)))

    for i in range(len(arr)-1, -1, -1):
        j = random.randint(0, i)
        arr[j], arr[i] = arr[i], arr[j]
        pmap[j], pmap[i] = pmap[i], pmap[j]

    return arr, pmap
