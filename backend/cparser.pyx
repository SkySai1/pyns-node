
cpdef parser(data:bytes, i:int=13):
    cdef object struct = data[i:]
    for t in range(struct.__len__()):
        if struct[t] == 0:
            return struct[:t+5].__hash__()