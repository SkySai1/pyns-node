def parser(data:bytes, i:int=13):
    struct = data[i:]
    for t in range(struct.__len__()):
        if struct[t] == 0:
            return struct[:t+5].__hash__()

def iterater(data, buff):
    key = parser(data)
    for save in buff:
        if key == parser(save,11):
            return save, key
    return None, key