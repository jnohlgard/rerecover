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
#include <set>
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
};

enum class RerecoverError { no_rtti_usage, missing_rodata };

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
  using dependency_map = std::map<addr_type, std::unique_ptr<ClassNode>>;

  static auto scan_for_typeinfo(LIEF::ELF::Binary &binary)
      -> std::expected<dependency_map, RerecoverError>;

 private:
  auto scan_section_for_typeinfo(LIEF::ELF::Binary &binary,
                                 LIEF::ELF::Section &section)
      -> std::expected<dependency_map, RerecoverError>;

  void init_cti_addrs(LIEF::Binary &binary);
  void init_dependency_map(LIEF::Binary &binary);
  ClassNode *parse_typeinfo(LIEF::ELF::Binary &binary, addr_type addr);
  static LIEF::ELF::Symbol typeinfo_name(std::string_view name_without_prefix,
                                         addr_type address);
  static LIEF::ELF::Symbol typeinfo_obj(std::string_view name_without_prefix,
                                        addr_type address);
  static std::string default_class_name(addr_type address);
  /// Extract null-terminated byte string
  static std::string ntbs(const LIEF::ELF::Binary &binary, addr_type address);
  static std::string add_class_info(LIEF::ELF::Binary &binary,
                                    addr_type address);

  dependency_map dependencies{};
  addr_type cti_addr{};
  addr_type si_addr{};
  addr_type vmi_addr{};
};
template <typename AddrType>
ClassNode *RttiRecover<AddrType>::parse_typeinfo(LIEF::ELF::Binary &binary,
                                                 addr_type ti_addr) {
  if (ti_addr == 0) {
    return nullptr;
  }
  if (auto it = dependencies.find(ti_addr); it != end(dependencies)) {
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
    } else {
      name = default_class_name(ti_addr);
    }

    auto &node = [&]() -> auto & {
      auto [it, added] =
          dependencies.try_emplace(ti_addr, std::make_unique<ClassNode>());
      auto &[addr, node_ptr] = *it;
      auto ti_obj = typeinfo_obj(name, ti_addr);
      ti_obj.size(sizeof(addr_type) * 2);
      node_ptr->symbol = &binary.add_static_symbol(ti_obj);
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
      dependencies.try_emplace(sym.value(), std::make_unique<ClassNode>(&sym));
    }
  }
}
template <typename AddrType>
std::string RttiRecover<AddrType>::add_class_info(LIEF::ELF::Binary &binary,
                                                  addr_type address) {
  if (auto name_addr =
          as_span<const addr_type>(binary.get_content_from_virtual_address(
              address, sizeof(addr_type) * 2))[1];
      name_addr != 0) {
    auto name = ntbs(binary, name_addr);
    binary.add_static_symbol(typeinfo_name(name, name_addr));
    return name;
  } else {
    return default_class_name(address);
  }
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
  LIEF::ELF::Symbol symbol{
      std::string{NamePrefix::typeinfo_obj}.append(name_without_prefix),
      LIEF::ELF::ELF_SYMBOL_TYPES::STT_OBJECT,
      LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL};
  symbol.value(address);
  return symbol;
}

template <typename AddrType>
LIEF::ELF::Symbol RttiRecover<AddrType>::typeinfo_name(
    std::string_view name_without_prefix, addr_type address) {
  LIEF::ELF::Symbol symbol{
      std::string{NamePrefix::typeinfo_name}.append(name_without_prefix),
      LIEF::ELF::ELF_SYMBOL_TYPES::STT_OBJECT,
      LIEF::ELF::SYMBOL_BINDINGS::STB_LOCAL};
  symbol.value(address);
  symbol.size(name_without_prefix.size() + 1);
  return symbol;
}

template <typename AddrType>
auto RttiRecover<AddrType>::scan_for_typeinfo(LIEF::ELF::Binary &binary)
    -> std::expected<dependency_map, RerecoverError> {
  RttiRecover<AddrType> recover;
  recover.init_dependency_map(binary);
  recover.init_cti_addrs(binary);
  if (recover.cti_addr == 0) {
    std::cerr << "No typeinfo base class references found" << std::endl;
    return std::unexpected{RerecoverError::no_rtti_usage};
  }

  const auto *section = binary.get_section(SectionNames::rodata);
  if (section == nullptr) {
    std::cerr << "Missing section <" << SectionNames::rodata << ">"
              << std::endl;
    return std::unexpected{RerecoverError::missing_rodata};
  }
  addr_type addr = section->virtual_address();
  const addr_type end_addr = addr + section->size();

  while (addr < end_addr) {
    // Attempt to parse to determine if the current address contains a type_info
    // object.
    if (auto node = recover.parse_typeinfo(binary, addr)) {
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
  // NB: std::move() is necessary here, C++17 RVO does not apply because we are
  // moving from a member variable of `recover`
  return std::move(recover.dependencies);
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
