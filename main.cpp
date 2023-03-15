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

  static auto init_dependency_map(LIEF::Binary &binary) -> dependency_map;

 private:
  static LIEF::ELF::Symbol typeinfo_name(std::string_view name_without_prefix,
                                         addr_type address);
  static LIEF::ELF::Symbol typeinfo_obj(std::string_view name_without_prefix,
                                        addr_type address);
  static std::string default_class_name(addr_type address);
  /// Extract null-terminated byte string
  static std::string ntbs(const LIEF::ELF::Binary &binary, addr_type address);
  static std::string add_class_info(LIEF::ELF::Binary &binary,
                                    addr_type address);
};
template <typename AddrType>
auto RttiRecover<AddrType>::init_dependency_map(LIEF::Binary &binary)
    -> RttiRecover::dependency_map {
  dependency_map result;
  for (auto &sym : binary.symbols()) {
    if (sym.name().starts_with(NamePrefix::typeinfo_obj)) {
      result.try_emplace(sym.value(), std::make_unique<ClassNode>(&sym));
    }
  }
  return result;
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
  // not bounds checked:
  return std::string(reinterpret_cast<const char *>(
      binary.get_content_from_virtual_address(address, 240).data()));
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
  auto deps = init_dependency_map(binary);
  const auto *class_type_info_vtable =
      binary.get_symbol(SymbolNames::class_type_info);
  if (class_type_info_vtable == nullptr) {
    std::cerr << "No typeinfo base class references found" << std::endl;
    return std::unexpected{RerecoverError::no_rtti_usage};
  }
  const auto *si_class_type_info_vtable =
      binary.get_symbol(SymbolNames::si_class_type_info);
  const auto *vmi_class_type_info_vtable =
      binary.get_symbol(SymbolNames::vmi_class_type_info);

  const auto *section = binary.get_section(SectionNames::rodata);
  if (section == nullptr) {
    std::cerr << "Missing section <" << SectionNames::rodata << ">"
              << std::endl;
    return std::unexpected{RerecoverError::missing_rodata};
  }
  const addr_type base_offset = section->virtual_address();
  auto data = as_span<const addr_type>(section->content());
  const addr_type cti_addr =
      class_type_info_vtable->value() + 2 * sizeof(addr_type);
  const addr_type si_addr =
      si_class_type_info_vtable->value() + 2 * sizeof(addr_type);
  const addr_type vmi_addr =
      vmi_class_type_info_vtable->value() + 2 * sizeof(addr_type);

  for (size_t offset = 0; offset < data.size(); ++offset) {
    auto value = data[offset];
    if (value == 0) {
      continue;
    }
    auto ti_addr = offset * sizeof(addr_type) + base_offset;
    if (deps.contains(ti_addr)) {
      continue;
    }
    if (value == cti_addr || value == si_addr || value == vmi_addr) {
      auto name = add_class_info(binary, ti_addr);
      auto ti_obj = typeinfo_obj(name, ti_addr);
      ti_obj.size(sizeof(addr_type) * 2);
      ++offset;  // skip past name pointer
      auto &symbol = binary.add_static_symbol(ti_obj);

      auto &node = [&]() -> auto & {
        auto [it, added] =
            deps.try_emplace(ti_addr, std::make_unique<ClassNode>());
        auto &[addr, node_ptr] = *it;
        return *node_ptr;
      }();
      node.symbol = &symbol;
      if (value == si_addr) {
        // single inheritance
        ++offset;
        auto base_ti_addr = data[offset];
        if (auto it = deps.find(base_ti_addr); it != end(deps)) {
          auto &[addr, dep] = *it;
          node.deps.push_back(dep.get());
        } else {
          std::cerr << "Missing class info for " << name
                    << " -> " << std::hex << base_ti_addr << std::endl;
        }
      } else if (value == vmi_addr) {
      }
    }
  }
  return deps;
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
