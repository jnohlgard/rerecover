import json
import sys
import argparse
import rerecover


def main(argv):
    """Recover symbol names and addresses based on some known addresses of C++ ABI classes and typeinfo"""
    parser = argparse.ArgumentParser()
    parser.add_argument("rodata", type=argparse.FileType('rb'),
                        help="file containing a .rodata section raw binary dump")
    # parser.add_argument("config", type=argparse.FileType('r', encoding='UTF-8'),
    #                     help="file containing what is known beforehand")
    parser.add_argument("output", type=argparse.FileType('w', encoding='UTF-8'),
                        help="output file to write the recovered symbol information to")

    args = parser.parse_args()
    config = rerecover.config.load("args.config")
    processor = rerecover.rtti_vtable.RodataProcessor(config)
    processor.load_rodata(args.rodata, 0x009c5da0)
    processor.set_symbol(0x00c8e9d8, '_ZTVN10__cxxabiv117__class_type_infoE')
    processor.set_symbol(0x00c8ea08, '_ZTVN10__cxxabiv120__si_class_type_infoE')
    processor.set_symbol(0x00c8e9a8, '_ZTVN10__cxxabiv121__vmi_class_type_infoE')

    processor.recover_typeinfo()

#    print(repr(processor.symbols_by_name))
#    print(str(processor.symbols_by_addr))

    for addr, sym in processor.symbols_by_addr.items():
        print(f'{addr:08x}: {sym}')

    for addr, typeinfo in processor.typeinfos.items():
        print(f'{addr:08x}: {typeinfo.name} : {", ".join([str(base) for base in typeinfo.inherits_from])}')


if __name__ == '__main__':
    exit(main(sys.argv))
