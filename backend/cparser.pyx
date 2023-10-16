cpdef parser(data:bytes, i:int=13):
        cdef bytes DO = b'\x80\x00'
        cdef object struct = data[i:]
        for t in range(struct.__len__()):
            if struct[t] == 0:
                if DO in data[t+5:]:
                    return (struct[:t+5] + DO).__hash__()
                else:
                    return struct[:t+5].__hash__()

cpdef iterater(data:bytes, buff:dict):
        cdef object key = parser(data)
        return buff.get(key), key