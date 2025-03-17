from sortedcontainers import SortedKeyList

class ITree:
    """Fast search in intervals (begin, end, associated data)"""
    # WARNING! Based on the fact that unique_idx cannot overflow!
    def __init__(self):
        self.unique_idx = 0
        self.keys = SortedKeyList(key=lambda x: x[0])
        self.values = {}

    def __getitem__(self, elem):
        try:
            key_idx = self.keys.bisect_key_left(elem)
            begin, unique_idx = self.keys[key_idx]
        except IndexError:
            raise KeyError
        end, data = self.values[unique_idx]
        if begin <= elem < end:
            return (begin, end, data)
        raise KeyError

    def __contains__(self, elem):
        try:
            self.__getitem__(elem)
        except KeyError:
            return False
        return True
    
    def add(self, start, end, data):
        self.keys.add((start, self.unique_idx))
        self.values[self.unique_idx] = (end, data)
        self.unique_idx += 1
    
    def remove(self, elem):
        try:
            key_idx = self.keys.bisect_key_left(elem)
            begin, unique_idx = self.keys[key_idx]
        except IndexError:
            return
        end, _ = self.values[unique_idx]
        if begin <= elem < end:
            self.keys.pop(key_idx)
            self.values.pop(unique_idx)
