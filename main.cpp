/*
 * Recover symbols based on RTTI information in a given executable
 */
#include <LIEF/LIEF.hpp>
#include <bits/ranges_algo.h>
#include <bits/ranges_algobase.h>
#include <bits/ranges_base.h>
#include <bits/ranges_util.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <concepts>
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
#include <type_traits>
#include <vector>

using namespace std::literals;

/// Default names for specific sections in ELF
struct SectionNames {
  static inline /*constexpr*/ const auto rodata{".rodata"s};
  static inline /*constexpr*/ const auto text{".text"s};
  static inline /*constexpr*/ const auto plt{".plt"s};
};

/// Names of some libstdc++ symbols
struct SymbolNames {
  //  std::string operator""s fails in constexpr on GCC 12.2 with an error about
  //  heap allocation and returning that pointer.

  /// Base classes use typeinfo objects of class __class_type_info
  static inline /*constexpr*/ const auto class_type_info{
      "_ZTVN10__cxxabiv117__class_type_infoE"s};
  /// Single inheritance derived classes use typeinfo objects of class
  /// __si_class_type_info
  static inline /*constexpr*/ const auto si_class_type_info{
      "_ZTVN10__cxxabiv120__si_class_type_infoE"s};
  /// Virtual or multiple inheritance derived classes use typeinfo objects of
  /// class __vmi_class_type_info
  static inline /*constexpr*/ const auto vmi_class_type_info{
      "_ZTVN10__cxxabiv121__vmi_class_type_infoE"s};
  /// Pure virtual function call error handler
  static inline /*constexpr*/ const auto cxa_pure_virtual{
      "__cxa_pure_virtual"s};

  /// Mangled name of a deleting destructor
  static inline /*constexpr*/ const auto deleting_destructor{"D0"s};
  /// Mangled name of a complete object destructor
  static inline /*constexpr*/ const auto complete_object_destructor{"D1"s};
};

/// Symbol name prefixes used in mangled C++ names
struct NamePrefix {
  static constexpr const auto typeinfo_obj = "_ZTI"sv;
  static constexpr const auto typeinfo_name = "_ZTS"sv;
  static constexpr const auto vtable = "_ZTV"sv;
  static constexpr const auto vtt = "_ZTT"sv;
  static constexpr const auto member_function = "_ZN"sv;
};

/// Error codes returned from some API functions
enum class RerecoverError {
  no_rtti_usage,
  missing_rodata,
};

/// String conversions for the error codes
std::string_view error_msg(RerecoverError error) {
  switch (error) {
    using enum RerecoverError;
    case no_rtti_usage:
      return "No typeinfo base class references found"sv;
    case missing_rodata:
      return "Missing rodata section"sv;
  }
  return "<unknown error>"sv;
}

/// Convenience function for printing error codes
std::ostream &operator<<(std::ostream &os, RerecoverError error) {
  return os << error_msg(error);
}

/// Section content classification categories, used for identifying if an
/// address is a potential function pointer
enum class Content {
  unknown,
  code,
  data,
};

/// Flags for different kinds of inheritance
enum class Inheritance : unsigned {
  virtual_mask = 1,
  public_mask = 2,
};

/// Convenience function for printing inheritance flags
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

/// Convenience function for reinterpreting the bytes of a span as another kind
/// of span
template <typename ElementType, size_t Extent = std::dynamic_extent>
constexpr std::span<ElementType, Extent> as_span(auto backing) {
  auto bytes = std::as_bytes(std::span(backing.data(), backing.size()));
  size_t nelems = backing.size_bytes() / sizeof(ElementType);
  // Does this violate the constexpr-ness of this function?
  const void *data = bytes.data();
  return {static_cast<ElementType *>(data), nelems};
}

template <std::unsigned_integral AddrType = std::uint32_t>
class RttiRecover {
 public:
  using addr_type = AddrType;
  using diff_type = decltype([](addr_type i) {
    if constexpr (sizeof(i) > 4) {
      return int64_t{-1};
    }
    return int32_t{-1};
  }(1));
  static_assert(sizeof(diff_type) == sizeof(addr_type));

  static constexpr auto inheritance_flags_mask =
      static_cast<addr_type>(std::to_underlying(Inheritance::public_mask) |
                             std::to_underlying(Inheritance::virtual_mask));

  struct Typeinfo;
  struct Vtable;
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
    Vtable *primary_vtable{};
    /// Base classes for this class
    std::vector<TypeinfoDep> base_classes{};
    // All vtables for this class, ungrouped and including the primary vtable.
    std::vector<Vtable *> vtables{};
  };
  struct Vtable {
    struct VfuncPtr {
      addr_type value{};
      std::string unqualified_name{};
    };
    Typeinfo *typeinfo{};
    /**
     * Address of the global symbol for this vtable
     *
     * This points to the first of the elements that come before the function
     * pointers.
     *
     * @see https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable
     */
    addr_type global_symbol_addr{};
    /// offset from the address of the vtable pointer to the beginning of the
    /// object instance
    diff_type offset_to_top{};
    addr_type func_table_begin{};
    addr_type func_table_end{};
    std::vector<VfuncPtr> vfuncptrs{};
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
  void create_function_symbols_for_class(LIEF::ELF::Binary &binary,
                                         const Typeinfo &typeinfo);
  auto step_past_typeinfo(addr_type addr) const -> addr_type;

  void import_existing_function_symbols(const LIEF::ELF::Binary &binary);
  void init_cti_addrs(const LIEF::Binary &binary);
  void init_dependency_map(LIEF::Binary &binary);
  void init_content_class(const LIEF::ELF::Binary &binary);
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
  void create_symbol_for_vfptr(LIEF::ELF::Binary &binary,
                               const Typeinfo &typeinfo,
                               addr_type derived_vfptr_value,
                               std::string_view unqualified_func_name);

  /// sequence numbering used for generated symbol names
  int vfunc_seq{};
  std::map<addr_type, Content> content_class;
  std::map<addr_type, std::string> function_addr_name;
  std::set<const Typeinfo *> processed_vtables;
  /// Typeinfo objects found
  // keys are address of the typeinfo
  typeinfo_map typeinfos{};
  /// Identified vtables
  // keys are address of the vtable
  vtable_addr_map vtables{};
  addr_type cti_addr{};
  addr_type si_addr{};
  addr_type vmi_addr{};
  addr_type cxa_pure_virtual_addr{};
  uint16_t rodata_shndx{14};
  uint16_t text_shndx{12};
};

template <std::unsigned_integral AddrType>
auto RttiRecover<AddrType>::step_past_typeinfo(addr_type addr) const
    -> addr_type {
  if (auto after = typeinfos.upper_bound(addr); after != begin(typeinfos)) {
    const auto &[typeinfo_addr, node] = *prev(after);
    const auto addr_after = typeinfo_addr + node->symbol->size();
    if (addr_after > addr) {
      // There is a typeinfo object here, skip past it.
      //      std::cerr << "Skipping past " << node->symbol->name() << " @ "
      //      << std::hex
      //                << typeinfo_addr << ": " << std::hex << addr;
      addr = (addr_after + sizeof(addr_type) - 1) & ~(sizeof(addr_type) - 1);
      //      std::cerr << " - " << std::hex << addr << std::endl;
      return addr;
    }
  }
  return addr;
}

template <std::unsigned_integral AddrType>
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
      if (typeinfo.primary_vtable != nullptr &&
          typeinfo.primary_vtable->func_table_begin !=
              primary_vtable.func_table_begin) {
        std::cerr << "Multiple primary vtables for " << typeinfo.symbol->name()
                  << " @ " << std::hex << typeinfo.symbol->value() << ": "
                  << typeinfo.primary_vtable->func_table_begin << ", " << addr
                  << " from VTT @ " << offset * sizeof(addr_type) + base_addr
                  << std::endl;
      } else {
        typeinfo.primary_vtable = &primary_vtable;
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

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::guess_primary_vtables() {
  for (auto &&[addr, vtable] : vtables) {
    // we guess that the vtable with the lowest address is the primary vtable
    // for any given class that lacks a VTT
    if (vtable.typeinfo->primary_vtable == nullptr) {
      vtable.typeinfo->primary_vtable = &vtable;
    }
  }
}

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::create_vtable_symbols(LIEF::ELF::Binary &binary) {
  for (auto &&[addr, typeinfo] : typeinfos) {
    if (!typeinfo.vtables.empty()) {
      auto vtable_symbol =
          make_symbol(typeinfo.name,
                      typeinfo.primary_vtable->func_table_begin,
                      NamePrefix::vtable);
      vtable_symbol.size(vtables[typeinfo.vtables.back()].func_table_end -
                         vtables[typeinfo.primary_vtable].func_table_begin);
      vtable_symbol.shndx(rodata_shndx);
      binary.add_static_symbol(vtable_symbol);
    }
  }
}

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::create_function_symbols_for_class(
    LIEF::ELF::Binary &binary, const RttiRecover::Typeinfo &typeinfo) {
  if (typeinfo.vtables.empty()) {
    return;
  }
  if (processed_vtables.contains(&typeinfo)) {
    return;
  }
  processed_vtables.insert(&typeinfo);
  // Depth-first to get to the base classes
  constexpr auto is_virtual_class = [](auto &&dep) {
    return 0 != (std::to_underlying(dep.flags) &
                 std::to_underlying(Inheritance::virtual_mask));
  };
  constexpr auto is_non_virtual_class = [](auto &&dep) {
    return !is_virtual_class(dep);
  };
  constexpr auto typeinfo_from_dep =
      std::views::transform([](auto &&dep) -> auto & { return *dep.typeinfo; });
  constexpr auto non_virtual_bases_only =
      std::views::filter(is_non_virtual_class) | typeinfo_from_dep;
  constexpr auto virtual_bases_only =
      std::views::filter(is_virtual_class) | typeinfo_from_dep;
  const auto has_implementation = [this](auto &&vfptr) {
    return vfptr.value != 0 && vfptr.value != cxa_pure_virtual_addr;
  };

  for (auto &&base : typeinfo.base_classes | typeinfo_from_dep) {
    std::cerr << "Checking " << typeinfo.name << " base class " << base.name
              << std::endl;
    create_function_symbols_for_class(binary, base);
  }

  auto base_vtables =
      typeinfo.base_classes |
      std::views::transform(
          [](auto &&dep) -> const auto & { return dep.typeinfo->vtables; }) |
      std::views::join |
      std::views::transform(
          [](auto &&vtable_ptr) -> const auto & { return *vtable_ptr; });
  auto derived_vtables =
      typeinfo.vtables | std::views::transform([](auto &&vtable_ptr) -> auto & {
        return *vtable_ptr;
      });
  if (base_vtables.empty()) {
    // Assume that for classes without bases and with exactly two virtual
    // functions that are not pure virtual, that those two functions are the
    // virtual destructor pair
    for (auto &&vfuncptrs :
         derived_vtables | std::views::transform(&Vtable::vfuncptrs) |
             std::views::filter([&has_implementation](auto &&vfuncptrs) {
               return std::ranges::count_if(vfuncptrs, has_implementation) == 2;
             })) {
      auto implemented_vfuncs =
          vfuncptrs | std::views::filter(has_implementation);
      auto vfunc_it = begin(implemented_vfuncs);
      // Order of dtor pair in Itanium C++ ABI is: D1, D0
      (vfunc_it++)->unqualified_name = SymbolNames::complete_object_destructor;
      (vfunc_it++)->unqualified_name = SymbolNames::deleting_destructor;
    }
  }
  auto base_vtable_it = begin(base_vtables);
  auto base_vtables_end = end(base_vtables);
  for (auto &&derived_vtable : derived_vtables) {
    if (base_vtable_it != base_vtables_end) {
      auto &&base_vtable = *base_vtable_it++;
      auto derived_vfunc_names =
          derived_vtable.vfuncptrs |
          std::views::transform(&Vtable::VfuncPtr::unqualified_name);
      auto base_vfunc_names =
          base_vtable.vfuncptrs |
          std::views::transform(&Vtable::VfuncPtr::unqualified_name);
      auto derived_vfunc_it = begin(derived_vfunc_names);
      auto derived_vfunc_end = end(derived_vfunc_names);
      for (auto &&base_vfunc_name : base_vfunc_names) {
        if (derived_vfunc_it == derived_vfunc_end) {
          std::cerr << "derived vtable @ " << std::hex
                    << derived_vtable.func_table_begin
                    << " too short, expected " << std::dec
                    << base_vtable.vfuncptrs.size() << ", got "
                    << derived_vtable.vfuncptrs.size() << std::endl;
          break;
        }
        auto &&derived_vfunc_name = *derived_vfunc_it++;
        derived_vfunc_name = base_vfunc_name;
      }
    }
    std::ranges::generate(
        derived_vtable.vfuncptrs |
            std::views::transform(&Vtable::VfuncPtr::unqualified_name) |
            std::views::filter(&std::string::empty),
        [this]() {
          std::ostringstream oss;
          oss << "vfunc"sv << std::dec << std::setw(4) << std::setfill('0')
              << ++vfunc_seq;
          return std::to_string(oss.tellp()) + oss.str();
        });
  }
  for (auto &&vfptr :
       derived_vtables | std::views::transform(&Vtable::vfuncptrs) |
           std::views::join | std::views::filter(has_implementation)) {
    create_symbol_for_vfptr(
        binary, typeinfo, vfptr.value, vfptr.unqualified_name);
  }
}

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::create_symbol_for_vfptr(
    LIEF::ELF::Binary &binary,
    const RttiRecover::Typeinfo &typeinfo,
    addr_type vfptr_value,
    std::string_view unqualified_func_name) {
  auto symbol_name = std::string(NamePrefix::member_function);
  if (typeinfo.name.front() == 'N' && typeinfo.name.back() == 'E') {
    // strip enclosing "N..E"
    symbol_name.append(typeinfo.name.substr(1, typeinfo.name.size() - 2));
  } else {
    symbol_name.append(typeinfo.name);
  }
  symbol_name.append(unqualified_func_name).append("Ev");
  binary.add_exported_function(vfptr_value, symbol_name);
  std::cout << "Added " << symbol_name << " @ " << std::hex << vfptr_value
            << std::endl;
}

template <std::unsigned_integral AddrType>
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

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::scan_section_for_vtables(
    LIEF::ELF::Binary &binary, const LIEF::ELF::Section &section) {
  // Crude heuristic to detect vtables:
  // Look for pointers to typeinfo objects.
  // If the next word in memory contains a pointer into a code section (e.g.
  // .text), then assume that this is part of a vtable.

  init_content_class(binary);

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
      // object, which is not part of another typeinfo object. This is
      // possibly a vtable or a VTT (virtual table table).

      auto vtable_data =
          as_span<const addr_type>(binary.get_content_from_virtual_address(
              addr - sizeof(addr_type), 8000));

      Vtable vtable{
          .typeinfo = typeinfo_ptr.get(),
          .offset_to_top = static_cast<diff_type>(vtable_data[0]),
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
      addr = addr + (offset - 2) * sizeof(addr_type);
      if (count_vfuncs == 0) {
        std::cerr << "Suspicious empty vtable @ " << std::hex
                  << vtable.func_table_begin << " for "
                  << typeinfo_ptr->symbol->name() << " @ " << typeinfo_addr
                  << " offset-to-top?: " << std::dec << vtable.offset_to_top
                  << std::endl;
        continue;
      } else {
        vtable.func_table_end = addr;
        vtable.vfuncptrs.reserve(vtable.func_table_end -
                                 vtable.func_table_begin);
        std::ranges::transform(
            as_span<const addr_type>(binary.get_content_from_virtual_address(
                vtable.func_table_begin,
                vtable.func_table_end - vtable.func_table_begin)),
            std::back_inserter(vtable.vfuncptrs),
            [](auto value) -> Vtable::VfuncPtr { return {value}; });
        auto [item, was_added] =
            vtables.try_emplace(vtable.func_table_begin, std::move(vtable));
        auto &&[key, elem] = *item;
        vtable.typeinfo->vtables.push_back(&elem);
      }
    } else {
      // not a typeinfo pointer
      addr += sizeof(addr_type);
    }
  }
}

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::init_content_class(
    const LIEF::ELF::Binary &binary) {
  this->content_class.try_emplace(0, Content::unknown);
  for (const auto &section_name : {SectionNames::text, SectionNames::plt}) {
    if (auto sec = binary.get_section(section_name)) {
      this->content_class[sec->virtual_address()] = Content::code;
      this->content_class.try_emplace(sec->virtual_address() + sec->size(),
                                      Content::unknown);
    }
  }
}

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::scan_section_for_typeinfo(
    LIEF::ELF::Binary &binary, const LIEF::ELF::Section &section) {
  addr_type addr = section.virtual_address();
  const addr_type end_addr = addr + section.size();

  while (addr < end_addr) {
    // Attempt to parse to determine if the current address contains a
    // type_info object.
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

template <std::unsigned_integral AddrType>
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

    // si_... and vmi_... are subclasses of __class_type_info, handle the
    // extra fields below
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

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::init_cti_addrs(const LIEF::Binary &binary) {
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

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::init_dependency_map(LIEF::Binary &binary) {
  for (auto &sym : binary.symbols()) {
    if (sym.name().starts_with(NamePrefix::typeinfo_obj)) {
      typeinfos.try_emplace(sym.value(), std::make_unique<Typeinfo>(&sym));
    }
  }
}

template <std::unsigned_integral AddrType>
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

template <std::unsigned_integral AddrType>
std::string RttiRecover<AddrType>::ntbs(const LIEF::ELF::Binary &binary,
                                        addr_type address) {
  // get_content_from_virtual_address will clamp the size, so we don't read
  // out of bounds
  auto data = binary.get_content_from_virtual_address(address, 8000);
  auto end = std::ranges::find(data, '\0');
  return {data.begin(), end};
}

template <std::unsigned_integral AddrType>
std::string RttiRecover<AddrType>::default_class_name(addr_type address) {
  std::ostringstream oss;
  oss << "Class" << std::hex << std::setw(6) << address;
  auto name = oss.str();
  name = std::to_string(name.size()) + name;
  return name;
}

template <std::unsigned_integral AddrType>
LIEF::ELF::Symbol RttiRecover<AddrType>::typeinfo_obj(
    std::string_view name_without_prefix, addr_type address) {
  auto symbol =
      make_symbol(name_without_prefix, address, NamePrefix::typeinfo_obj);
  return symbol;
}

template <std::unsigned_integral AddrType>
LIEF::ELF::Symbol RttiRecover<AddrType>::typeinfo_name(
    std::string_view name_without_prefix, addr_type address) {
  auto symbol =
      make_symbol(name_without_prefix, address, NamePrefix::typeinfo_name);
  symbol.size(name_without_prefix.size() + 1);
  return symbol;
}

template <std::unsigned_integral AddrType>
void RttiRecover<AddrType>::import_existing_function_symbols(
    const LIEF::ELF::Binary &binary) {
  for (auto &&symbol : binary.symbols()) {
    if (symbol.value() != 0 &&
        symbol.type() == LIEF::ELF::ELF_SYMBOL_TYPES::STT_FUNC &&
        !symbol.name().empty()) {
      function_addr_name.try_emplace(symbol.value(), symbol.name());
    }
  }
  //  std::ranges::for_each(
  //      binary.functions() | std::views::filter([](auto &&symbol) {
  //        return symbol.value() != 0 && !symbol.name().empty();
  //      }),
  //      [this](auto &&symbol) {
  //        function_addr_name.try_emplace(symbol.value(), symbol.name());
  //      });
}

template <std::unsigned_integral AddrType>
auto RttiRecover<AddrType>::scan_for_typeinfo(LIEF::ELF::Binary &binary)
    -> std::expected<typeinfo_map, RerecoverError> {
  RttiRecover<AddrType> recover;
  recover.init_dependency_map(binary);
  recover.init_cti_addrs(binary);
  if (recover.cti_addr == 0) {
    std::cerr << "No typeinfo base class references found" << std::endl;
    return std::unexpected{RerecoverError::no_rtti_usage};
  }

  //  recover.import_existing_function_symbols(binary);
  if (const auto *section_p = binary.get_section(SectionNames::rodata)) {
    const auto &section = *section_p;
    recover.scan_section_for_typeinfo(binary, section);
    recover.scan_section_for_vtables(binary, section);
    recover.scan_section_for_vtt(binary, section);
    recover.guess_primary_vtables();
    recover.processed_vtables.clear();
    if (auto symbol = binary.get_symbol(SymbolNames::cxa_pure_virtual)) {
      recover.cxa_pure_virtual_addr = symbol->value();
      recover.function_addr_name[recover.cxa_pure_virtual_addr] = "";
    }
    for (auto &&it : recover.typeinfos) {
      auto &&[addr, typeinfo_ptr] = it;
      recover.create_function_symbols_for_class(binary, *typeinfo_ptr);
    }

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
