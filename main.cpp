/*
 * Recover symbols based on RTTI information in a given executable
 */
#include <LIEF/LIEF.hpp>
#include <bits/ranges_algo.h>
#include <bits/ranges_base.h>
#include <bits/ranges_util.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace std::literals;

struct SectionNames {
  static inline /*constexpr*/ const auto rodata{".rodata"s};
  static inline /*constexpr*/ const auto text{".text"s};
  static inline /*constexpr*/ const auto plt{".plt"s};
};

struct SymbolNames {
  //  std::string operator""s fails in constexpr on GCC 12.2 with an error about
  //  heap allocation and returning that pointer.

  // Base classes
  static inline /*constexpr*/ const auto class_type_info{
      "_ZTVN10__cxxabiv117__class_type_infoE"s};
  // Single inheritance derived classes
  static inline /*constexpr*/ const auto si_class_type_info{
      "_ZTVN10__cxxabiv120__si_class_type_infoE"s};
  // Virtual or multiple inheritance derived classes
  static inline /*constexpr*/ const auto vmi_class_type_info{
      "_ZTVN10__cxxabiv121__vmi_class_type_infoE"s};
};

struct NamePrefix {
  static constexpr const auto typeinfo_obj = "_ZTI"sv;
  static constexpr const auto typeinfo_name = "_ZTS"sv;
  static constexpr const auto vtable = "_ZTV"sv;
  static constexpr const auto vtt = "_ZTT"sv;
};

enum class RerecoverError {
  no_rtti_usage,
  missing_rodata,
};

std::ostream &operator<<(std::ostream &os, RerecoverError error) {
  std::string_view error_msg;
  switch (error) {
    using enum RerecoverError;
    case no_rtti_usage:
      error_msg = "No typeinfo base class references found"sv;
      break;
    case missing_rodata:
      error_msg = "Missing rodata section"sv;
      break;
  }
  return os << error_msg;
}

enum class Content {
  unknown,
  code,
  data,
};

enum class Inheritance : unsigned {
  virtual_mask = 1,
  public_mask = 2,
};

std::ostream &operator<<(std::ostream &os, Inheritance inheritance) {
  auto &&underlying = std::to_underlying(inheritance);
  if (underlying & std::to_underlying(Inheritance::public_mask)) {
    os << "public ";
  }
  if (underlying & std::to_underlying(Inheritance::virtual_mask)) {
    os << "virtual ";
  }
  return os;
}

template <typename ElementType, size_t Extent = std::dynamic_extent>
constexpr std::span<ElementType, Extent> as_span(auto backing) {
  auto bytes = std::as_bytes(std::span(backing.data(), backing.size()));
  size_t nelems = backing.size_bytes() / sizeof(ElementType);
  // Does this violate the constexpr-ness of this function?
  const void *data = bytes.data();
  return {static_cast<ElementType *>(data), nelems};
}

template <typename AddrType = std::uint32_t>
class RttiRecover {
 public:
  using addr_type = AddrType;

  static constexpr auto inheritance_flags_mask =
      static_cast<addr_type>(std::to_underlying(Inheritance::public_mask) |
                             std::to_underlying(Inheritance::virtual_mask));

  struct Typeinfo;
  struct TypeinfoDep {
    Typeinfo *typeinfo{};
    Inheritance flags{};
  };
  struct Typeinfo {
    LIEF::Symbol *symbol{};
    std::string name{};
    addr_type name_addr{};
    // Primary vtable for this class, i.e. not secondary vtables of other
    // classes and not construction vtables
    addr_type primary_vtable{};
    /// Base classes for this class
    std::vector<TypeinfoDep> base_classes{};
    // All vtables for this class, ungrouped and including the primary vtable.
    std::vector<addr_type> vtables{};
  };
  struct Vtable {
    Typeinfo *typeinfo{};
    addr_type symbol_offset{};
    addr_type offset_to_top{};
    addr_type func_table_begin{};
    addr_type func_table_end{};
  };
  struct VTT {
    Typeinfo *typeinfo{};
    std::vector<Vtable *> vtables{};
  };

  using typeinfo_map = std::map<addr_type, std::unique_ptr<Typeinfo>>;

  // keys are the address of the typeinfo
  using vtable_addr_map = std::map<addr_type, Vtable>;

  static auto scan_for_typeinfo(LIEF::ELF::Binary &binary)
      -> std::expected<typeinfo_map, RerecoverError>;

 private:
  void scan_section_for_typeinfo(LIEF::ELF::Binary &binary,
                                 const LIEF::ELF::Section &section);
  void scan_section_for_vtables(LIEF::ELF::Binary &binary,
                                const LIEF::ELF::Section &section);
  void scan_section_for_vtt(LIEF::ELF::Binary &binary,
                            const LIEF::ELF::Section &section);
  void guess_primary_vtables();
  void create_vtable_symbols(LIEF::ELF::Binary &binary);
  auto step_past_typeinfo(addr_type addr) const -> addr_type;

  void init_cti_addrs(LIEF::Binary &binary);
  void init_dependency_map(LIEF::Binary &binary);
  auto parse_typeinfo(LIEF::ELF::Binary &binary, addr_type typeinfo_addr)
      -> Typeinfo *;
  static LIEF::ELF::Symbol typeinfo_name(std::string_view name_without_prefix,
                                         addr_type address);
  static LIEF::ELF::Symbol typeinfo_obj(std::string_view name_without_prefix,
                                        addr_type address);
  static LIEF::ELF::Symbol make_symbol(std::string_view name_without_prefix,
                                       addr_type address,
                                       std::string_view name_prefix);
  static std::string default_class_name(addr_type address);
  /// Extract null-terminated byte string
  static std::string ntbs(const LIEF::ELF::Binary &binary, addr_type address);
  std::unique_ptr<Typeinfo> add_class_info(LIEF::ELF::Binary &binary,
                                                  const std::string &name,
                                                  addr_type typeinfo_addr);

  /// Typeinfo objects found
  // keys are address of the typeinfo
  typeinfo_map typeinfos{};
  /// Identified vtables
  // keys are address of the vtable
  vtable_addr_map vtables{};
  addr_type cti_addr{};
  addr_type si_addr{};
  addr_type vmi_addr{};
  uint16_t rodata_shndx{14};
  uint16_t text_shndx{12};
};

template <typename AddrType>
auto RttiRecover<AddrType>::step_past_typeinfo(addr_type addr) const
    -> addr_type {
  if (auto after = typeinfos.upper_bound(addr); after != begin(typeinfos)) {
    const auto &[typeinfo_addr, node] = *prev(after);
    const auto addr_after = typeinfo_addr + node->symbol->size();
    if (addr_after > addr) {
      // There is a typeinfo object here, skip past it.
      //      std::cerr << "Skipping past " << node->symbol->name() << " @ " <<
      //      std::hex
      //                << typeinfo_addr << ": " << std::hex << addr;
      addr = (addr_after + sizeof(addr_type) - 1) & ~(sizeof(addr_type) - 1);
      //      std::cerr << " - " << std::hex << addr << std::endl;
      return addr;
    }
  }
  return addr;
}

template <typename AddrType>
void RttiRecover<AddrType>::scan_section_for_vtt(
    LIEF::ELF::Binary &binary, const LIEF::ELF::Section &section) {
  addr_type base_addr = section.virtual_address();
  auto data = as_span<const addr_type>(section.content());
  auto count = data.size();

  for (decltype(count) offset = 0; offset < count; ++offset) {
    auto value = data[offset];
    if (auto vtable_it = vtables.find(value); vtable_it != end(vtables)) {
      auto &&[addr, primary_vtable] = *vtable_it;
      // the primary vtable for the class is the first vtable found in the VTT
      auto &&typeinfo = *primary_vtable.typeinfo;
      std::cerr << "Found VTT @ " << std::hex
                << offset * sizeof(addr_type) + base_addr << " for "
                << typeinfo.name << " @ " << typeinfo.symbol->value()
                << std::endl;
      VTT vtt{
          .typeinfo = primary_vtable.typeinfo,
      };
      vtt.vtables.push_back(&primary_vtable);
      if (typeinfo.primary_vtable != 0 && typeinfo.primary_vtable != addr) {
        std::cerr << "Multiple primary vtables for " << typeinfo.symbol->name()
                  << " @ " << std::hex << typeinfo.symbol->value() << ": "
                  << typeinfo.primary_vtable << ", " << addr << " from VTT @ "
                  << offset * sizeof(addr_type) + base_addr << std::endl;
      } else {
        typeinfo.primary_vtable = addr;
      }
      while ((vtable_it = vtables.find(data[++offset])) != vtables.end()) {
        auto &&[_, vtable] = *vtable_it;
        if (vtable.typeinfo != vtt.typeinfo) {
          std::cerr << "Mismatched typeinfo in VTT for " << vtt.typeinfo->name
                    << " @ " << std::hex << vtt.typeinfo->symbol->value()
                    << ": " << std::hex
                    << offset * sizeof(addr_type) + base_addr << " -> "
                    << vtable.typeinfo->name << " @ " << std::hex
                    << vtable.typeinfo->symbol->value() << std::endl;
        }
        vtt.vtables.push_back(&vtable);
      }
      if (vtt.vtables.size() < 2) {
        std::cerr << "Suspicious lonely vtable reference at " << std::hex
                  << base_addr + (offset - 1) * sizeof(addr_type) << " to "
                  << typeinfo.name << " @ " << std::hex
                  << typeinfo.symbol->value() << std::endl;
      } else {
        std::cerr << "VTT for " << typeinfo.name << " @ " << std::hex
                  << typeinfo.symbol->value() << ": ";
        for (auto &&vtable : vtt.vtables) {
          std::cerr << vtable->func_table_begin << ", ";
        }
        std::cerr << std::endl;
      }
    }
  }
}

template <typename AddrType>
void RttiRecover<AddrType>::guess_primary_vtables() {
  for (auto &&[addr, vtable] : vtables) {
    if (vtable.typeinfo->primary_vtable == 0) {
      vtable.typeinfo->primary_vtable = addr;
    }
  }
}

template <typename AddrType>
void RttiRecover<AddrType>::create_vtable_symbols(LIEF::ELF::Binary &binary) {
  for (auto &&[addr, typeinfo] : typeinfos) {
    if (!typeinfo.vtables.empty()) {
      auto vtable_symbol = make_symbol(
          typeinfo.name, typeinfo.primary_vtable, NamePrefix::vtable);
      vtable_symbol.size(vtables[typeinfo.vtables.back()].func_table_end -
                         vtables[typeinfo.primary_vtable].func_table_begin);
      vtable_symbol.shndx(rodata_shndx);
      binary.add_static_symbol(vtable_symbol);
    }
  }
}

template <typename AddrType>
LIEF::ELF::Symbol RttiRecover<AddrType>::make_symbol(
    std::string_view name_without_prefix,
    addr_type address,
    std::string_view name_prefix) {
  LIEF::ELF::Symbol symbol{std::string{name_prefix}.append(name_without_prefix),
                           LIEF::ELF::ELF_SYMBOL_TYPES::STT_OBJECT,
                           LIEF::ELF::SYMBOL_BINDINGS::STB_WEAK};
  symbol.value(address);
  return symbol;
}
template <typename AddrType>
void RttiRecover<AddrType>::scan_section_for_vtables(
    LIEF::ELF::Binary &binary, const LIEF::ELF::Section &section) {
  std::map<addr_type, Content> content_class;
  content_class.try_emplace(0, Content::unknown);

  // Crude heuristic to detect vtables:
  // Look for pointers to typeinfo objects.
  // If the next word in memory contains a pointer into a code section (e.g.
  // .text), then assume that this is part of a vtable.

  for (const auto &section_name : {SectionNames::text, SectionNames::plt}) {
    if (auto sec = binary.get_section(section_name)) {
      content_class[sec->virtual_address()] = Content::code;
      content_class.try_emplace(sec->virtual_address() + sec->size(),
                                Content::unknown);
    }
  }

  addr_type addr = section.virtual_address();
  const addr_type end_addr = addr + section.size();
  while (addr < end_addr) {
    // skip any typeinfo objects we encounter
    addr = step_past_typeinfo(addr);
    auto value =
        as_span<const addr_type>(
            binary.get_content_from_virtual_address(addr, sizeof(addr_type)))
            .front();
    if (auto ti_it = typeinfos.find(value); ti_it != end(typeinfos)) {
      auto &&[typeinfo_addr, typeinfo_ptr] = *ti_it;
      // found a reference to a typeinfo
      // object, which is not part of another typeinfo object. This is possibly
      // a vtable or a VTT (virtual table table).

      auto vtable_data =
          as_span<const addr_type>(binary.get_content_from_virtual_address(
              addr - sizeof(addr_type), 8000));

      Vtable vtable{
          .typeinfo = typeinfo_ptr.get(),
          .offset_to_top = vtable_data[0],
          .func_table_begin = static_cast<addr_type>(addr + sizeof(addr_type)),
      };
      auto offset = 2;
      auto count_vfuncs = 0;
      do {
        auto vfunc_addr = vtable_data[offset++];
        if (auto content_type_it = content_class.upper_bound(vfunc_addr);
            content_type_it != begin(content_class)) {
          auto pointer_class = prev(content_type_it)->second;
          if (pointer_class != Content::code) {
            // Not a function pointer, continue scanning for the next vtable
            break;
          }
          // Function pointer
          ++count_vfuncs;
        } else {
          break;
        }
      } while (true);
      addr = addr - sizeof(addr_type) + offset * sizeof(addr_type);
      if (count_vfuncs == 0) {
        std::cerr << "Suspicious empty vtable @ " << std::hex
                  << vtable.func_table_begin << " for "
                  << typeinfo_ptr->symbol->name() << " @ " << typeinfo_addr
                  << " offset-to-top?: " << std::dec << vtable.offset_to_top
                  << std::endl;
        continue;
      } else {
        vtable.func_table_end = addr;
        vtable.typeinfo->vtables.push_back(vtable.func_table_begin);
        vtables.insert({vtable.func_table_begin, std::move(vtable)});
      }
    } else {
      // not a typeinfo pointer
      addr += sizeof(addr_type);
    }
  }
}

template <typename AddrType>
void RttiRecover<AddrType>::scan_section_for_typeinfo(
    LIEF::ELF::Binary &binary, const LIEF::ELF::Section &section) {
  addr_type addr = section.virtual_address();
  const addr_type end_addr = addr + section.size();

  while (addr < end_addr) {
    // Attempt to parse to determine if the current address contains a type_info
    // object.
    if (auto typeinfo = parse_typeinfo(binary, addr)) {
      // Rounding up to nearest sizeof addr_type multiple for alignment
      size_t consumed_bytes =
          (typeinfo->symbol->size() + sizeof(addr_type) - 1) &
          ~(sizeof(addr_type) - 1);
      if (consumed_bytes == 0) {
        consumed_bytes = sizeof(addr_type);
      }
      // Skip past the whole type_info struct
      addr += consumed_bytes;
    } else {
      // Nothing found here, try the next word
      addr += sizeof(addr_type);
    }
  }
}

template <typename AddrType>
auto RttiRecover<AddrType>::parse_typeinfo(LIEF::ELF::Binary &binary,
                                           addr_type typeinfo_addr)
    -> Typeinfo * {
  if (typeinfo_addr == 0) {
    return nullptr;
  }
  if (auto it = typeinfos.find(typeinfo_addr); it != end(typeinfos)) {
    const auto &[addr, typeinfo] = *it;
    return typeinfo.get();
  }
  size_t offset = 0;
  auto data = as_span<const addr_type>(
      binary.get_content_from_virtual_address(typeinfo_addr, 8000));
  addr_type value = data[offset++];

  if (value == cti_addr || value == si_addr || value == vmi_addr) {
    std::string name;
    auto name_addr = data[offset++];
    if (name_addr != 0) {
      name = ntbs(binary, name_addr);
      binary.add_static_symbol(typeinfo_name(name, name_addr))
          .shndx(rodata_shndx);
    } else {
      name = default_class_name(typeinfo_addr);
    }

    auto &typeinfo = [&]() -> auto & {
      auto &typeinfo_ptr = typeinfos[typeinfo_addr] =
          add_class_info(binary, name, typeinfo_addr);
      return *typeinfo_ptr;
    }();
    typeinfo.name_addr = name_addr;

    // si_... and vmi_... are subclasses of __class_type_info, handle the extra
    // fields below
    if (value == si_addr) {
      // single, public, non-virtual base class
      auto base_ti_addr = data[offset++];
      typeinfo.symbol->size(sizeof(addr_type) * offset);

      if (auto base_typeinfo = parse_typeinfo(binary, base_ti_addr)) {
        typeinfo.base_classes.emplace_back(base_typeinfo,
                                           Inheritance::public_mask);
      } else {
        std::cerr << std::hex << typeinfo_addr << ": Missing class info for "
                  << typeinfo.name << " dependency @" << std::hex
                  << base_ti_addr << std::endl;
      }
    } else if (value == vmi_addr) {
      // virtual or multiple inheritance
      auto flags = data[offset++];
      auto base_count = data[offset++];
      typeinfo.symbol->size(sizeof(addr_type) * (offset + base_count * 2));
      for (addr_type idx = 0; idx < base_count; ++idx) {
        auto base_ti_addr = data[offset++];
        auto base_offset_flags = data[offset++];
        auto inheritance_flags{static_cast<Inheritance>(
            base_offset_flags & inheritance_flags_mask)};
        if (auto base_typeinfo = parse_typeinfo(binary, base_ti_addr)) {
          typeinfo.base_classes.emplace_back(base_typeinfo, inheritance_flags);
        } else {
          std::cerr << std::hex << typeinfo_addr << ": Missing class info for "
                    << name << " dependency @" << std::hex << base_ti_addr
                    << std::endl;
        }
      }
    }
    return &typeinfo;
  }
  return nullptr;
}

template <typename AddrType>
void RttiRecover<AddrType>::init_cti_addrs(LIEF::Binary &binary) {
  if (const auto *class_type_info_vtable =
          binary.get_symbol(SymbolNames::class_type_info)) {
    cti_addr = class_type_info_vtable->value() + 2 * sizeof(addr_type);
  }
  if (const auto *si_class_type_info_vtable =
          binary.get_symbol(SymbolNames::si_class_type_info)) {
    si_addr = si_class_type_info_vtable->value() + 2 * sizeof(addr_type);
  }
  if (const auto *vmi_class_type_info_vtable =
          binary.get_symbol(SymbolNames::vmi_class_type_info)) {
    vmi_addr = vmi_class_type_info_vtable->value() + 2 * sizeof(addr_type);
  }
}

template <typename AddrType>
void RttiRecover<AddrType>::init_dependency_map(LIEF::Binary &binary) {
  for (auto &sym : binary.symbols()) {
    if (sym.name().starts_with(NamePrefix::typeinfo_obj)) {
      typeinfos.try_emplace(sym.value(), std::make_unique<Typeinfo>(&sym));
    }
  }
}

template <typename AddrType>
auto RttiRecover<AddrType>::add_class_info(LIEF::ELF::Binary &binary,
                                           const std::string &name,
                                           addr_type typeinfo_addr)
    -> std::unique_ptr<Typeinfo> {
  auto typeinfo = typeinfo_obj(name, typeinfo_addr);
  typeinfo.size(sizeof(addr_type) * 2);
  typeinfo.shndx(rodata_shndx);
  auto typeinfo_ptr =
      std::make_unique<Typeinfo>(&binary.add_static_symbol(typeinfo), name);
  return typeinfo_ptr;
}

template <typename AddrType>
std::string RttiRecover<AddrType>::ntbs(const LIEF::ELF::Binary &binary,
                                        addr_type address) {
  // get_content_from_virtual_address will clamp the size, so we don't read out
  // of bounds
  auto data = binary.get_content_from_virtual_address(address, 8000);
  auto end = std::ranges::find(data, '\0');
  return {data.begin(), end};
}

template <typename AddrType>
std::string RttiRecover<AddrType>::default_class_name(addr_type address) {
  std::ostringstream oss;
  oss << "Class" << std::hex << std::setw(6) << address;
  auto name = oss.str();
  name = std::to_string(name.size()) + name;
  return name;
}

template <typename AddrType>
LIEF::ELF::Symbol RttiRecover<AddrType>::typeinfo_obj(
    std::string_view name_without_prefix, addr_type address) {
  auto symbol =
      make_symbol(name_without_prefix, address, NamePrefix::typeinfo_obj);
  return symbol;
}

template <typename AddrType>
LIEF::ELF::Symbol RttiRecover<AddrType>::typeinfo_name(
    std::string_view name_without_prefix, addr_type address) {
  auto symbol =
      make_symbol(name_without_prefix, address, NamePrefix::typeinfo_name);
  symbol.size(name_without_prefix.size() + 1);
  return symbol;
}

template <typename AddrType>
auto RttiRecover<AddrType>::scan_for_typeinfo(LIEF::ELF::Binary &binary)
    -> std::expected<typeinfo_map, RerecoverError> {
  RttiRecover<AddrType> recover;
  recover.init_dependency_map(binary);
  recover.init_cti_addrs(binary);
  if (recover.cti_addr == 0) {
    std::cerr << "No typeinfo base class references found" << std::endl;
    return std::unexpected{RerecoverError::no_rtti_usage};
  }

  if (const auto *section_p = binary.get_section(SectionNames::rodata)) {
    const auto &section = *section_p;
    recover.scan_section_for_typeinfo(binary, section);
    recover.scan_section_for_vtables(binary, section);
    recover.scan_section_for_vtt(binary, section);
    recover.guess_primary_vtables();

    // NB: std::move() is necessary here, C++17 RVO does not apply because we
    // are moving from a member variable of `recover`
    return std::move(recover.typeinfos);
  } else {
    std::cerr << "Missing section <" << SectionNames::rodata << ">"
              << std::endl;
    return std::unexpected{RerecoverError::missing_rodata};
  }
}

void myparse(std::string_view filename) {
  auto binary(LIEF::ELF::Parser::parse(std::string{filename}));
  if (auto res = RttiRecover<std::uint32_t>::scan_for_typeinfo(*binary)) {
    auto &deps = res.value();
    for (auto &[addr, typeinfo] : deps) {
      std::cout << std::hex << std::setw(8) << addr << ": " << typeinfo->name;
      if (!typeinfo->base_classes.empty()) {
        std::cout << " : ";
        for (const auto &base : typeinfo->base_classes) {
          std::cout << base.flags << base.typeinfo->name << ", ";
        }
      }
      std::cout << std::endl;
      if (typeinfo->primary_vtable == 0) {
        std::cerr << "Missing vtable for " << typeinfo->name << std::endl;
      }
    }
    auto out_filename = std::string{filename}.append("-new.elf");
    std::cout << "Saving " << out_filename << "..." << std::endl;
    binary->write(out_filename);
  } else {
    std::cerr << "Error: " << res.error() << std::endl;
  }
}

int main(int argc, const char **argv) {
  if (argc != 2) {
    const auto *myname = argv[0] ? argv[0] : "rerecover";
    std::cerr << "Usage: "sv << myname << " <program file>"sv << std::endl;
    return 2;
  }
  myparse(argv[1]);

  return 0;
}

class CopyVisitor : public LIEF::Visitor {
 public:
  using LIEF::Visitor::Visitor;

  void visit(const LIEF::Symbol &symbol) override { do_visit(symbol); }
  void visit(const LIEF::ELF::Symbol &symbol) override { do_visit(symbol); }

  [[nodiscard]] const std::unique_ptr<LIEF::Symbol> &get() const { return ptr; }
  [[nodiscard]] std::unique_ptr<LIEF::Symbol> &get() { return ptr; }

 private:
  template <class RealType>
  void do_visit(const RealType &symbol) {
    ptr = std::make_unique<RealType>(symbol);
  }

  std::unique_ptr<LIEF::Symbol> ptr{nullptr};
};
