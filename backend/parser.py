
def parser(data:bytes, i:int=13):
        DO = b'\x80\x00'
        struct = data[i:]
        for t in range(struct.__len__()):
            if struct[t] == 0:
                if DO in data[t+5:]:
                    return (struct[:t+5] + DO).__hash__()
                else:
                    return struct[:t+5].__hash__()

def iterater(data:bytes, buff:dict):
        key = parser(data)
        return buff.get(key), key