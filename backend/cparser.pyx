cpdef parser(data:bytes, i:int=13):
        cdef object struct = data[i:]
        for t in range(struct.__len__()):
            if struct[t] == 0:
                return struct[:t+5].__hash__()

cpdef iterater(data:bytes, buff:list):
        key = parser(data)
        cdef list array = buff
        cdef int i = 0
        for save in array:
            if key == parser(save,11):
                if i > 0: array.insert(i-1, array.pop(i))
                return save, key, array
            i+=1
        return None, key, buff