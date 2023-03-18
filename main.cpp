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
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace std::literals;

struct ClassNode {
  LIEF::Symbol *symbol{};
  std::vector<ClassNode *> deps{};
};

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

enum class Content {
  unknown,
  code,
  data,
};

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
  using typeinfo_map = std::map<addr_type, std::unique_ptr<ClassNode>>;
  // keys are the address of the typeinfo, values are (first_vfunc_ptr,
  // past_last_vfunc_ptr) of the vtable or vtable group
  // note that the vtable object has data before the first function pointer, so
  // this needs to be adjusted before adding a symbol to the binary
  using vtable_addr_map =
      std::multimap<addr_type, std::pair<addr_type, addr_type>>;

  static auto scan_for_typeinfo(LIEF::ELF::Binary &binary)
      -> std::expected<typeinfo_map, RerecoverError>;

 private:
  void scan_section_for_typeinfo(LIEF::ELF::Binary &binary,
                                 const LIEF::ELF::Section &section);

  void scan_section_for_vtables(LIEF::ELF::Binary &binary,
                                const LIEF::ELF::Section &section);
  void scan_section_for_vtt(LIEF::ELF::Binary &binary,
                            const LIEF::ELF::Section &section);
  auto step_past_typeinfo(addr_type addr) const -> addr_type;

  void init_cti_addrs(LIEF::Binary &binary);
  void init_dependency_map(LIEF::Binary &binary);
  ClassNode *parse_typeinfo(LIEF::ELF::Binary &binary, addr_type addr);
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
  static std::unique_ptr<ClassNode> add_class_info(LIEF::ELF::Binary &binary,
                                                   const std::string &name,
                                                   addr_type address);

  /// Typeinfo objects found
  // keys are address of the typeinfo
  typeinfo_map typeinfos{};
  /// Potential vtables for each typeinfo
  // Some of these may turn out to be construction vtables for X-in-Y
  vtable_addr_map vtables{};
  addr_type cti_addr{};
  addr_type si_addr{};
  addr_type vmi_addr{};
};
template <typename AddrType>
auto RttiRecover<AddrType>::step_past_typeinfo(addr_type addr) const
    -> addr_type {
  if (auto after = typeinfos.upper_bound(addr); after != begin(typeinfos)) {
    const auto &[addr_before, node_before] = *prev(after);
    if (addr_before + node_before->symbol->size() > addr) {
      // There is a typeinfo object here, skip past it.
      addr =
          (addr_before + node_before->symbol->size() + sizeof(addr_type) - 1) &
          ~(sizeof(addr_type) - 1);
      return addr;
    }
  }
  return addr;
}
template <typename AddrType>
void RttiRecover<AddrType>::scan_section_for_vtt(
    LIEF::ELF::Binary &binary, const LIEF::ELF::Section &section) {
  const addr_type base_addr = section.virtual_address();
  const addr_type end_addr = base_addr + section.size();
  auto addr = base_addr;
  while (addr < end_addr) {
    addr += sizeof(addr_type);
  }
}

template <typename AddrType>
LIEF::ELF::Symbol RttiRecover<AddrType>::make_symbol(
    std::string_view name_without_prefix,
    addr_type address,
    std::string_view name_prefix) {
  LIEF::ELF::Symbol symbol{std::string{name_prefix}.append(name_without_prefix),
                           LIEF::ELF::ELF_SYMBOL_TYPES::STT_OBJECT,
                           LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL};
  symbol.value(address);
  return symbol;
}
template <typename AddrType>
void RttiRecover<AddrType>::scan_section_for_vtables(
    LIEF::ELF::Binary &binary, const LIEF::ELF::Section &section) {
  std::map<addr_type, Content> content_class;

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

  const addr_type base_addr = section.virtual_address();
  const addr_type end_addr = base_addr + section.size();
  auto addr = base_addr;
  auto last_vtable_it = vtables.end();
  while (addr < end_addr) {
    // skip any typeinfo objects we encounter
    addr = step_past_typeinfo(addr);
    auto value =
        as_span<const addr_type>(
            binary.get_content_from_virtual_address(addr, sizeof(addr_type)))
            .front();
    if (auto ti_it = typeinfos.find(value); ti_it != end(typeinfos)) {
      // found a reference to a typeinfo
      // object, which is not part of another typeinfo object. This is possibly
      // a vtable or a VTT (virtual table table).
      auto addr_start = addr + sizeof(addr_type);
      auto vtable =
          as_span<const addr_type>(binary.get_content_from_virtual_address(
              addr_start - 2 * sizeof(addr_type), 8000));
      auto offset_to_top = vtable[0];
      auto typeinfo_addr = vtable[1];
      auto offset = 2;
      auto count_vfuncs = 0;
      do {
        auto vfunc_addr = vtable[offset++];
        if (auto content_type_it = content_class.upper_bound(vfunc_addr);
            content_type_it != begin(content_class)) {
          auto pointer_class = prev(content_type_it)->second;
          if (pointer_class != Content::code) {
            // Not a function pointer, continue scanning for the next vtable
            break;
          }
          // Function pointer
          ++count_vfuncs;
        }
      } while (true);
      addr = addr_start + offset * sizeof(addr_type);
      if (offset_to_top == 0) {
        if (count_vfuncs == 0) {
          std::cerr << "Suspicious empty vtable @ " << std::hex << addr_start
                    << " for " << ti_it->second->symbol->name() << " @ "
                    << typeinfo_addr << std::endl;
          continue;
        }
        // Primary vtable for class X, or a construction vtable for X-in-Y
        last_vtable_it = vtables.insert({typeinfo_addr, {addr_start, addr}});
      } else if (last_vtable_it != vtables.end() &&
                 last_vtable_it->first == typeinfo_addr) {
        // this is a vtable that is part of a vtable group iff the previously
        // seen typeinfo is the same as this one
        // extend the range of the previously seen vtable to include this
        // vtable.
        last_vtable_it->second.second = addr;
      } else {
        std::cerr << "Suspicious non-zero-offset vtable @ " << std::hex << addr_start
                  << " for " << ti_it->second->symbol->name()
                  << " @ " << typeinfo_addr << " offset-to-top?: " << std::dec
                  << static_cast<int>(offset_to_top) << ", " << count_vfuncs
                  << " function pointers" << std::endl;
        continue;
      }
    } else {
      // not a typeinfo pointer
      addr += sizeof(addr_type);
    }
  }
  for (auto &[ti_addr, node] : typeinfos) {
    if (!vtables.contains(ti_addr)) {
      std::cerr << "Missing vtable for " << node->symbol->name() << " @ " << std::hex << ti_addr << std::endl;
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
    if (auto node = parse_typeinfo(binary, addr)) {
      // Rounding up to nearest sizeof addr_type multiple for alignment
      size_t consumed_bytes = (node->symbol->size() + sizeof(addr_type) - 1) &
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
ClassNode *RttiRecover<AddrType>::parse_typeinfo(LIEF::ELF::Binary &binary,
                                                 addr_type ti_addr) {
  if (ti_addr == 0) {
    return nullptr;
  }
  if (auto it = typeinfos.find(ti_addr); it != end(typeinfos)) {
    const auto &[addr, node] = *it;
    return node.get();
  }
  size_t offset = 0;
  auto data = as_span<const addr_type>(
      binary.get_content_from_virtual_address(ti_addr, 8000));
  addr_type value = data[offset++];

  if (value == cti_addr || value == si_addr || value == vmi_addr) {
    std::string name;
    if (auto name_addr = data[offset++]; name_addr != 0) {
      name = ntbs(binary, name_addr);
      binary.add_static_symbol(typeinfo_name(name, name_addr));
    } else {
      name = default_class_name(ti_addr);
    }

    auto &node = [&]() -> auto & {
      auto &node_ptr = typeinfos[ti_addr] =
          add_class_info(binary, name, ti_addr);
      return *node_ptr;
    }();
    // si_... and vmi_... are subclasses of __class_type_info, handle the extra
    // fields below
    if (value == si_addr) {
      // single inheritance
      auto base_ti_addr = data[offset++];
      node.symbol->size(sizeof(addr_type) * offset);

      if (auto dep = parse_typeinfo(binary, base_ti_addr)) {
        node.deps.push_back(dep);
      } else {
        std::cerr << std::hex << ti_addr << ": Missing class info for " << name
                  << " dependency @" << std::hex << base_ti_addr << std::endl;
      }
    } else if (value == vmi_addr) {
      // virtual or multiple inheritance
      auto flags = data[offset++];
      auto base_count = data[offset++];
      node.symbol->size(sizeof(addr_type) * (offset + base_count * 2));
      for (addr_type idx = 0; idx < base_count; ++idx) {
        auto base_ti_addr = data[offset++];
        auto base_offset_flags = data[offset++];
        if (auto dep = parse_typeinfo(binary, base_ti_addr)) {
          node.deps.push_back(dep);
        } else {
          std::cerr << std::hex << ti_addr << ": Missing class info for "
                    << name << " dependency @" << std::hex << base_ti_addr
                    << std::endl;
        }
      }
    }
    return &node;
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
      typeinfos.try_emplace(sym.value(), std::make_unique<ClassNode>(&sym));
    }
  }
}

template <typename AddrType>
std::unique_ptr<ClassNode> RttiRecover<AddrType>::add_class_info(
    LIEF::ELF::Binary &binary, const std::string &name, addr_type ti_addr) {
  auto node_ptr = std::make_unique<ClassNode>();
  auto ti_obj = typeinfo_obj(name, ti_addr);
  ti_obj.size(sizeof(addr_type) * 2);
  node_ptr->symbol = &binary.add_static_symbol(ti_obj);
  return node_ptr;
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
  std::cout << *binary << std::endl;
  if (auto res = RttiRecover<std::uint32_t>::scan_for_typeinfo(*binary)) {
    auto &deps = res.value();
    for (auto &[addr, node] : deps) {
      std::cout << std::hex << std::setw(8) << addr << ": "
                << node->symbol->name();
      if (!node->deps.empty()) {
        std::cout << " : ";
        for (const auto &dep : node->deps) {
          std::cout << dep->symbol->name() << ", ";
        }
      }
      std::cout << std::endl;
    }
  } else {
    std::cerr << "Error: " << std::to_underlying(res.error()) << std::endl;
  }
  if (const auto *cti =
          binary->get_symbol("_ZTVN10__cxxabiv117__class_type_infoE"s)) {
    std::cout << cti->name() << ": "sv << std::setw(16) << std::hex
              << cti->value() << " "sv << std::setw(8) << cti->size()
              << std::endl;
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
