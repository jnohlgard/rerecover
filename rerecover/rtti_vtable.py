import json
import struct
from collections import OrderedDict


def ntbs(segment, offset):
    """Parse a Null-terminated byte string from a Segment"""
    len = 0
    memory = memoryview(segment.buffer)[offset - segment.base_offset:]
    while memory[len] != 0:
        len += 1
    return bytes(memory[:len]).decode()


class Segment(object):
    def __init__(self, buffer, base_offset):
        self.buffer = buffer
        self.base_offset = base_offset


class RodataProcessor(object):
    formats = {
        '__class_type_info': '<PP',
        '__si_class_type_info': '<PPP',
        '__vmi_class_type_info': '<PPII',
        '__base_class_type_info': '<Pl',
    }

    def __init__(self, config):
        self.segment = None
        self.config = config
        self.typeinfos = {}
        self.symbols_by_addr = {}
        self.symbols_by_name = {}

    def load_rodata(self, rodata, base_offset):
        self.rodata = Segment(memoryview(rodata.read()), base_offset)

    def set_symbol(self, addr, name):
        self.symbols_by_name[name] = addr
        self.symbols_by_addr[addr] = name

    def add_typeinfo(self, addr, typeinfo):
        self.typeinfos[addr] = typeinfo
        name = typeinfo.name
        # type_info object
        self.set_symbol(addr, '_ZTI' + name)
        # type_info name
        self.set_symbol(typeinfo.name_addr, '_ZTS' + name)

    def found_typeinfo_at(self, typeinfo_cls, addr):
        typeinfo = typeinfo_cls.from_segment_at(self.rodata, addr)
        self.add_typeinfo(addr, typeinfo)
        return typeinfo.size_bytes

    def recover_typeinfo(self):
        pointer_format = self.config['pointer_format']
        pointer_stride = struct.calcsize(pointer_format)
        num = 0
        pointer_view = self.rodata.buffer.cast(pointer_format)
        class_info_addr = self.symbols_by_name['_ZTVN10__cxxabiv117__class_type_infoE'] + 8
        si_class_info_addr = self.symbols_by_name['_ZTVN10__cxxabiv120__si_class_type_infoE'] + 8
        vmi_class_info_addr = self.symbols_by_name['_ZTVN10__cxxabiv121__vmi_class_type_infoE'] + 8
        while num < len(pointer_view):
            value = pointer_view[num]
            addr = num * pointer_stride + self.rodata.base_offset
            typeinfo_cls = None
            if value == class_info_addr:
                typeinfo_cls = ClassTypeInfo
            elif value == si_class_info_addr:
                typeinfo_cls = SiClassTypeInfo
            elif value == vmi_class_info_addr:
                typeinfo_cls = VmiClassTypeInfo

            if typeinfo_cls is not None:
                num += self.found_typeinfo_at(typeinfo_cls, addr) // pointer_stride
            else:
                num += 1

        for typeinfo in self.typeinfos.values():
            for num, base in enumerate(typeinfo.inherits_from):
                if isinstance(base, int):
                    typeinfo.inherits_from[num] = self.typeinfos[base]


class CStruct(object):
    format = ''

    def __init__(self, *, segment, offset):
        self.size_bytes = struct.calcsize(self.format)

    @classmethod
    def from_segment_at(cls, segment, offset):
        return cls(*struct.unpack_from(cls.format, segment.buffer, offset - segment.base_offset), segment=segment,
                   offset=offset)


class TypeInfo(CStruct):
    format = '<II'

    def __init__(self, vtable_addr, name_addr, *, segment, offset):
        super().__init__(segment=segment, offset=offset)
        self.vtable_addr = vtable_addr
        self.name = ntbs(segment, name_addr)
        self.name_addr = name_addr
        self.inherits_from = []

    def __str__(self):
        return self.name


class ClassTypeInfo(TypeInfo):
    pass


class SiClassTypeInfo(ClassTypeInfo):
    format = ClassTypeInfo.format + 'I'

    def __init__(self, vtable_addr, name_addr, base_typeinfo_addr, *, segment, offset):
        super().__init__(vtable_addr, name_addr, segment=segment, offset=offset)
        self.inherits_from.append(base_typeinfo_addr)


class VmiClassTypeInfo(ClassTypeInfo):
    format = ClassTypeInfo.format + 'II'

    def __init__(self, vtable_addr, name_addr, flags, base_count, *, segment, offset):
        super().__init__(vtable_addr, name_addr, segment=segment, offset=offset)
        self.flags = flags
        self.bases = []
        offset = offset + self.size_bytes
        for _ in range(base_count):
            base = BaseClassTypeInfo.from_segment_at(segment, offset)
            self.inherits_from.append(base.typeinfo_addr)
            offset += base.size_bytes
            self.bases.append(base)


class BaseClassTypeInfo(CStruct):
    format = '<II'

    def __init__(self, typeinfo_addr, flags_offset, *, segment, offset):
        super().__init__(segment=segment, offset=offset)
        self.typeinfo_addr = typeinfo_addr
        self.flags_offset = flags_offset
        self.flags = flags_offset & 0xff
        self.offset = flags_offset >> 8
