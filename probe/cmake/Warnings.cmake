# Strict warnings for GCC and Clang. The probe parses attacker-controlled bytes,
# so implicit conversions and shadowing are treated as defects, not style.
function(prahari_set_warnings target)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic
            -Wconversion -Wsign-conversion
            -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
            -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion
            -Wformat=2 -Wimplicit-fallthrough)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${target} PRIVATE
                -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wuseless-cast)
        endif()
        if(PRAHARI_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()
