function(argos_enable_static_analysis target)
    if(ARGOS_ENABLE_CLANG_TIDY)
        find_program(CLANG_TIDY_EXE NAMES clang-tidy)
        if(CLANG_TIDY_EXE)
            set_target_properties(${target} PROPERTIES CXX_CLANG_TIDY
                "${CLANG_TIDY_EXE};--warnings-as-errors=*"
            )
        else()
            message(WARNING "clang-tidy requested but not found")
        endif()
    endif()
endfunction()
