#pragma once

#include <cstdio>
#include <typeinfo>

#define PRINT_TYPEINFO_TRACE(self)  \
  auto &&typeinfo = typeid(self);   \
  std::printf("%20s::%-20s (%p)\n", \
              typeinfo.name(),      \
              __FUNCTION__,         \
              reinterpret_cast<const void *>(&(self)));
