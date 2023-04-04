
add_executable(diamond diamond.cpp typeinfo_trace.hpp)
add_executable(y y.cpp typeinfo_trace.hpp)
if (CMAKE_STRIP)
  add_custom_command(TARGET y POST_BUILD
          COMMAND ${CMAKE_STRIP} -s -o "$<TARGET_FILE:y>-stripped" "$<TARGET_FILE:y>")
endif ()
