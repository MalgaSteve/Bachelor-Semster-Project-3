import os.path

def get_dictionary_from_entries(filename):
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

print(get_dictionary_from_entries("pw_file"))
