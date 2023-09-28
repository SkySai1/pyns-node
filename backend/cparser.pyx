
cpdef parser(data:bytes, i:int=13):
    cdef object struct = data[i:]
    for t in range(struct.__len__()):
        if struct[t] == 0:
            return struct[:t+5].__hash__()

cpdef iterater(data, buff):
    key = parser(data)
    cdef set array = buff
    for save in array:
        if key == parser(save,11):
            return save, key
    return None, key