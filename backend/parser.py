
def parser(data:bytes, i:int=13):
        part = data[i:]
        for t in range(part.__len__()):
            if part[t] == 0:
                break
        return part[:t+13].__hash__()

def iterater(data:bytes, buff:dict):
        key = parser(data)
        return buff.get(key), key