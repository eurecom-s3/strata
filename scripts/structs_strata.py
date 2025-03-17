from dataclasses import dataclass
from collections import defaultdict
from typing import Dict, Union, List, Set

@dataclass
class PageTiming:
    start_time: int
    end_time: int


@dataclass
class Versioning:
    pointers: Dict
    extra_fields: Dict

@dataclass
class Field:
    last_modify: int
    value: Union[int, None]
    dump_type: str
    dump_value: int
    dump_target_version: Versioning

class DataStructType:
    def __init__(self, name, size, ops, extra_fields, open_heads=False):
        self.name = name
        self.size = size
        self.ops = ops # offset: lambda
        self.extra_fields = extra_fields
        self.has_open_heads = open_heads

class DataStruct:
    next_idx = 1
    index2struct = {}
    datastruct_types = {}

    @classmethod
    def new_idx(cls):
        tmp = cls.next_idx
        cls.next_idx += 1
        return tmp

    @classmethod
    def new(cls, address: int, start_timestamp: int, struct_type: str, ppages: List[int]):
        next_idx = DataStruct.new_idx()
        new_struct = DataStruct(next_idx, address, start_timestamp, struct_type, ppages)
        cls.index2struct[next_idx] = new_struct
        return new_struct

    def __init__(self, index: int, address: int, start_timestamp: int, struct_type: str, ppages: List[int]):
        self.index = index
        self.address = address

        self.start_timestamp = start_timestamp
        self.end_timestamp = None

        self.struct_type = struct_type
        self.fields = defaultdict(Field)
        self.extra_fields = defaultdict(Field)
        self.ppages = ppages
        self.ref_counter = set()
        self.dump_version = Versioning({},{})
        self.dumped = False
        self.last_modify = start_timestamp
        self.ops = self.datastruct_types[struct_type].ops

    def get_version(self):
        extra = {k:v.value for k,v in self.extra_fields.items()}
        ptrs = {k:v.value for k,v in self.fields.items()}
        return Versioning(ptrs, extra)

class StrataPtrArray(DataStruct):
    @classmethod
    def new(cls, address: int, size: int, ops: Dict,  start_timestamp: int, struct_type: str, ppages: List[int]):
        next_idx = DataStruct.new_idx()
        new_struct = StrataPtrArray(next_idx, address, size, ops, start_timestamp, struct_type, ppages)
        DataStruct.index2struct[next_idx] = new_struct
        return new_struct

    def __init__(self, index: int, address: int, size:int, ops: Dict, start_timestamp: int, struct_type: str, ppages: List[int]):
        DataStruct.__init__(self, index, address, start_timestamp, struct_type, ppages)
        self.size = size
        self.ops = ops

    def get_version(self):
        extra = {k:v.value for k,v in self.extra_fields.items()}
        ptrs = {k:v.value for k,v in self.fields.items()}
        return Versioning(ptrs, extra)
